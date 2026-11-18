"""HTTP client for the ViewDNS.info API.

Ported from the ViewDNS Cortex XSOAR integration. It depends only on ``requests`` so it can be unit tested
without Splunk. The API key is never logged and is scrubbed from every exception message.
"""

import logging
import random
import time

import requests

DEFAULT_BASE_URL = "https://api.viewdns.info"
DEFAULT_TIMEOUT = 100
USER_AGENT = "TA-viewdns/1.0.0 (Splunk add-on)"

# Retries for transient failures: 5xx responses and connection failures (including connect timeouts, where the
# request never reached ViewDNS). A read timeout is NOT retried: ViewDNS counts a query before running it, so
# retrying could charge twice. 429 is never retried: on ViewDNS it means the quota is used up.
RETRIES = 3
BACKOFF_SECONDS = (1, 2, 4)
RETRY_STATUS_CODES = (500, 502, 503, 504)

# Free API keys receive a canned demonstration payload from the Reverse WHOIS API instead of an error.
DEMO_QUERY_MARKER = "demonstration---tool-for-paid-users-only"
# IP History reports "nothing known about this domain" as an error string in a successful response.
NO_RECORDS_MARKER = "do not have any records"

REDACTED = "<redacted>"

logger = logging.getLogger("ta_viewdns.client")
# urllib3 logs full request URLs, including the apikey query parameter, at DEBUG level.
logging.getLogger("urllib3").setLevel(logging.WARNING)


class ViewDNSError(Exception):
    """Base error. ``scope`` tells the caller how far the failure reaches.

    - ``value``: only this lookup failed; carry on with other values.
    - ``action``: every lookup with this action will fail (for example a paid-only tool).
    - ``search``: every lookup will fail (bad key, no quota); stop calling the API.
    """

    scope = "value"
    kind = "error"

    def __init__(self, message, status_code=None):
        super().__init__(message)
        self.message = message
        self.status_code = status_code

    def __str__(self):
        return self.message


class InvalidInputError(ViewDNSError):
    kind = "invalid_input"


class TransientError(ViewDNSError):
    """Network failure, timeout or 5xx that persisted through the retries."""

    kind = "transient"


class PaidPlanError(ViewDNSError):
    scope = "action"
    kind = "paid_plan"


class AuthError(ViewDNSError):
    scope = "search"
    kind = "auth"


class QuotaError(ViewDNSError):
    scope = "search"
    kind = "quota"


class ConfigurationError(ViewDNSError):
    scope = "search"
    kind = "configuration"


def scrub(text, secrets):
    """Replaces every secret in ``text`` with a placeholder."""
    text = str(text)
    for secret in secrets:
        if secret:
            text = text.replace(secret, REDACTED)
    return text


def extract_error_message(response):
    """Extracts the message from a ViewDNS error body: {"success": false, "error": {"code": N, "message": "..."}}."""
    try:
        body = response.json()
    except ValueError:
        return ""
    if not isinstance(body, dict):
        return ""
    error = body.get("error")
    if isinstance(error, dict):
        return str(error.get("message") or "")
    return str(error or "")


def error_for_status(status_code, api_message):
    """Maps a ViewDNS HTTP error status to a typed error with a clear, actionable message."""
    details = " ViewDNS said: {0}".format(api_message) if api_message else ""
    if status_code == 401:
        return AuthError(
            "ViewDNS: the API key is invalid. Check it on the add-on's Configuration page.{0}".format(details), 401
        )
    if status_code == 403:
        return PaidPlanError("ViewDNS: this lookup requires a paid ViewDNS API plan.{0}".format(details), 403)
    if status_code == 429:
        return QuotaError(
            "ViewDNS: the API query quota is used up - the monthly limit is reached and no prepaid queries remain."
            "{0}".format(details),
            429,
        )
    if status_code == 400:
        return InvalidInputError("ViewDNS: invalid input.{0}".format(details), 400)
    if status_code in RETRY_STATUS_CODES:
        return TransientError(
            "ViewDNS: the API is unavailable (HTTP {0}) after {1} retries.{2}".format(status_code, RETRIES, details),
            status_code,
        )
    return ViewDNSError("ViewDNS: the API returned HTTP {0}.{1}".format(status_code, details), status_code)


class ViewDNSClient(object):
    """Client for the ViewDNS.info API. Each public method is one API call, which costs one query."""

    def __init__(
        self,
        api_key,
        base_url=DEFAULT_BASE_URL,
        timeout=DEFAULT_TIMEOUT,
        proxies=None,
        session=None,
        sleep=time.sleep,
        secrets=(),
    ):
        if not api_key:
            raise ConfigurationError(
                "ViewDNS: no API key is configured. Set it on the add-on's Configuration page."
            )
        self._api_key = api_key
        self._base_url = (base_url or DEFAULT_BASE_URL).rstrip("/")
        self._timeout = timeout
        self._proxies = proxies or None
        self._session = session or requests.Session()
        self._session.headers.update({"User-Agent": USER_AGENT, "Accept": "application/json"})
        self._sleep = sleep
        # Values scrubbed from messages: the key and anything else secret, such as a proxy password.
        self._secrets = tuple(s for s in (api_key,) + tuple(secrets) if s)
        self.calls = 0

    # -- transport ---------------------------------------------------------------------------------------------------

    def _get(self, path, params):
        query = {key: value for key, value in params.items() if value not in (None, "")}
        query["apikey"] = self._api_key
        query["output"] = "json"
        url = self._base_url + path
        last_error = None
        for attempt in range(RETRIES + 1):
            if attempt:
                delay = BACKOFF_SECONDS[min(attempt - 1, len(BACKOFF_SECONDS) - 1)]
                self._sleep(delay + random.uniform(0, delay / 2.0))
            try:
                self.calls += 1
                response = self._session.get(url, params=query, timeout=self._timeout, proxies=self._proxies)
            except requests.exceptions.ReadTimeout:
                logger.warning("ViewDNS %s read timeout after %ss (not retried)", path, self._timeout)
                raise TransientError(
                    "ViewDNS: no response within {0} seconds. Not retried, because ViewDNS may already have counted "
                    "the query. Raise the request timeout on the Configuration page if this keeps happening."
                    .format(self._timeout)
                )
            except requests.exceptions.ConnectTimeout:
                last_error = TransientError(
                    "ViewDNS: could not connect to the API within {0} seconds ({1} retries).".format(
                        self._timeout, RETRIES
                    )
                )
                logger.warning("ViewDNS %s connect timeout (attempt %d)", path, attempt + 1)
                continue
            except requests.exceptions.RequestException as error:
                detail = scrub(error, self._secrets)
                last_error = TransientError(
                    "ViewDNS: could not connect to the API ({0} retries): {1}".format(RETRIES, detail)
                )
                logger.warning("ViewDNS %s connection error (attempt %d): %s", path, attempt + 1, detail)
                continue
            logger.debug("ViewDNS %s -> HTTP %s", path, response.status_code)
            if response.status_code in RETRY_STATUS_CODES:
                last_error = error_for_status(response.status_code, scrub(extract_error_message(response), self._secrets))
                continue
            return response
        raise last_error

    def _request(self, path, params, empty_markers=()):
        """Sends a request and returns the parsed body, whose ``response`` key is always a dict."""
        response = self._get(path, params)
        if response.status_code != 200:
            raise error_for_status(response.status_code, scrub(extract_error_message(response), self._secrets))
        try:
            body = response.json()
        except ValueError:
            raise ViewDNSError("ViewDNS: the API returned a response which is not valid JSON.")
        if not isinstance(body, dict):
            raise ViewDNSError("ViewDNS: the API returned an unexpected response.")
        result = body.get("response")
        if not isinstance(result, dict):
            result = {}
        body["response"] = result
        error = result.get("error")
        if error:
            text = scrub(error, self._secrets)
            lowered = text.lower()
            if any(marker in text for marker in empty_markers):
                body["response"] = {}
            elif "invalid api key" in lowered:
                # The Account API reports a bad key in a 200 response rather than a 401.
                raise error_for_status(401, text)
            elif "query limit" in lowered:
                raise error_for_status(429, text)
            else:
                raise InvalidInputError("ViewDNS: {0}".format(text))
        return body

    # -- endpoints ---------------------------------------------------------------------------------------------------

    def account_balance(self):
        """Free: does not consume a query."""
        return self._request("/account/", {"action": "balance"})

    def reverse_ip(self, host, page=None):
        return self._request("/reverseip/", {"host": host, "page": page})

    def reverse_whois(self, query, page=None):
        body = self._request("/reversewhois/", {"q": query, "page": page})
        if (body.get("query") or {}).get("query") == DEMO_QUERY_MARKER:
            raise PaidPlanError(
                "ViewDNS: Reverse WHOIS requires a paid ViewDNS API plan. The API returned demonstration data, "
                "which was discarded."
            )
        return body

    def reverse_ns(self, nameserver, page=None):
        return self._request("/reversens/", {"ns": nameserver, "page": page})

    def reverse_mx(self, mail_server, page=None):
        return self._request("/reversemx/", {"mx": mail_server, "page": page})

    def ip_history(self, domain):
        return self._request("/iphistory/", {"domain": domain}, empty_markers=(NO_RECORDS_MARKER,))

    def dns_record(self, domain, record_type="ANY"):
        return self._request("/dnsrecord/", {"domain": domain, "recordtype": record_type})

    def subdomains(self, domain, page=None):
        return self._request("/subdomains/", {"domain": domain, "page": page})

    def whois(self, domain):
        return self._request("/whois/v2/", {"domain": domain})

    def abuse_lookup(self, host):
        return self._request("/abuselookup/", {"domain": host})

    def free_email(self, domain):
        return self._request("/freeemail/", {"domain": domain})

    def ip_location(self, ip):
        return self._request("/iplocation/", {"ip": ip})

    def reverse_dns(self, ip):
        return self._request("/reversedns/", {"ip": ip})

    def mac_lookup(self, mac):
        return self._request("/maclookup/", {"mac": mac})

    def dnssec(self, domain):
        return self._request("/dnssec/", {"domain": domain})

    def spam_db_lookup(self, ip):
        return self._request("/spamdblookup/", {"ip": ip})

    def http_headers(self, host):
        return self._request("/httpheaders/", {"domain": host})

    def port_scan(self, host):
        return self._request("/portscan/", {"host": host})

    def ping(self, host):
        return self._request("/ping/v2/", {"host": host})

    def traceroute(self, host):
        return self._request("/traceroute/", {"domain": host})

    def propagation(self, domain):
        return self._request("/propagation/", {"domain": domain})

    def chinese_firewall(self, domain):
        return self._request("/chinesefirewall/", {"domain": domain})

    def iran_firewall(self, site_url):
        return self._request("/iranfirewall/", {"siteurl": site_url})
