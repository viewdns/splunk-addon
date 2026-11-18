"""Lookup actions: input validation/normalization, the API call, and parsing into flat result rows.

Parsers are ported from the ViewDNS Cortex XSOAR integration. Every parser returns a ``LookupResult`` whose rows are
flat dicts with unprefixed field names. The search command adds a prefix (``viewdns_`` by default). The alert action
writes them as-is.
"""

import html
import ipaddress
import re

try:  # Python 3
    from urllib.parse import urlsplit
except ImportError:  # pragma: no cover
    from urlparse import urlsplit  # type: ignore

STATUS_OK = "ok"
STATUS_NO_RESULTS = "no_results"

DNS_RECORD_TYPES = (
    "ANY", "A", "AAAA", "CAA", "CNAME", "DNSKEY", "DS", "MX", "NS", "NSEC", "PTR", "RRSIG", "SOA", "SRV", "TXT",
)

# The server rejects reverse WHOIS terms shorter than this.
REVERSE_WHOIS_MIN_LENGTH = 5

_DOMAIN_RE = re.compile(r"^(?=.{1,253}$)(?:[a-z0-9_](?:[a-z0-9\-_]{0,61}[a-z0-9_])?\.)+[a-z][a-z0-9\-]{0,61}[a-z0-9]$")


class LookupResult(object):
    """The normalized outcome of one successful lookup."""

    __slots__ = ("status", "rows", "total_count")

    def __init__(self, rows, total_count=None):
        self.rows = rows
        self.total_count = len(rows) if total_count is None else max(total_count, len(rows))
        self.status = STATUS_OK if rows else STATUS_NO_RESULTS

    def to_dict(self):
        return {"status": self.status, "rows": self.rows, "total_count": self.total_count}

    @classmethod
    def from_dict(cls, data):
        return cls(list(data.get("rows") or []), data.get("total_count"))


# -- generic helpers (from XSOAR) ------------------------------------------------------------------------------------


def to_int(value):
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return None


def remove_blank_values(data):
    """Drops keys whose value is None, False, an empty string or an empty collection.

    The API returns nulls, empty strings and ``false`` for missing WHOIS fields.
    """
    return {key: value for key, value in data.items() if value not in (None, "", [], {}, False)}


def as_list(value):
    return value if isinstance(value, list) else []


def clean_text(value):
    if value is None or value is False:
        return None
    text = html.unescape(str(value)).strip()
    return text or None


# -- input validation ------------------------------------------------------------------------------------------------


def is_ip(value):
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def is_domain(value):
    return bool(_DOMAIN_RE.match(value))


def normalize_host(value):
    """Lowercases and trims a host, accepting URLs (``https://host:443/path``) and trailing dots."""
    value = value.strip()
    if "://" in value:
        try:
            value = urlsplit(value).hostname or ""
        except ValueError:
            return ""
    value = value.strip().lower().rstrip(".")
    if value.startswith("[") and value.endswith("]"):
        value = value[1:-1]
    return value


def validate_domain(raw):
    value = normalize_host(raw)
    if not is_domain(value):
        if is_ip(value):
            return None, "expected a domain name, not an IP address"
        return None, "not a valid domain name"
    return value, None


def validate_host(raw):
    value = normalize_host(raw)
    if is_ip(value):
        return str(ipaddress.ip_address(value)), None
    if is_domain(value):
        return value, None
    return None, "not a valid domain name or IP address"


def validate_ip(raw):
    value = normalize_host(raw)
    if is_ip(value):
        return str(ipaddress.ip_address(value)), None
    if is_domain(value):
        return None, "expected an IP address, not a domain name"
    return None, "not a valid IP address"


def validate_email_or_domain(raw):
    """Free email check: an email address is reduced to its domain."""
    value = raw.strip()
    if "@" in value and "://" not in value:
        value = value.rsplit("@", 1)[1]
    return validate_domain(value)


_MAC_SEPARATORS = re.compile(r"[\s:.\-]")


def validate_mac(raw):
    value = _MAC_SEPARATORS.sub("", raw).upper()
    if not re.match(r"^[0-9A-F]{6,12}$", value):
        return None, "not a valid MAC address (6 to 12 hexadecimal digits)"
    return value, None


def validate_site(raw):
    """A domain or URL for the firewall tests. URLs keep their scheme and path; bare hosts get http://."""
    value = raw.strip()
    host = normalize_host(value)
    if not (is_domain(host) or is_ip(host)):
        return None, "not a valid domain name, IP address or URL"
    if "://" in value:
        parts = urlsplit(value)
        if parts.scheme.lower() not in ("http", "https"):
            return None, "only http:// and https:// URLs can be tested"
        path = parts.path or ""
        query = "?" + parts.query if parts.query else ""
        return "{0}://{1}{2}{3}".format(parts.scheme.lower(), parts.netloc.lower(), path, query), None
    return "http://" + host, None


def validate_term(raw):
    value = " ".join(raw.split()).lower()
    if len(value) < REVERSE_WHOIS_MIN_LENGTH:
        return None, "search term must be at least {0} characters".format(REVERSE_WHOIS_MIN_LENGTH)
    if len(value) > 256:
        return None, "search term is longer than 256 characters"
    return value, None


# -- parsers ---------------------------------------------------------------------------------------------------------


def parse_reverse_ip(body):
    response = body.get("response") or {}
    rows = [
        remove_blank_values({"domain": clean_text(item.get("name")), "last_resolved": clean_text(item.get("last_resolved"))})
        for item in as_list(response.get("domains"))
        if isinstance(item, dict) and item.get("name")
    ]
    return LookupResult(rows, to_int(response.get("domain_count")))


def parse_reverse_whois(body):
    response = body.get("response") or {}
    rows = [
        remove_blank_values(
            {
                "domain": clean_text(item.get("domain")),
                "created": clean_text(item.get("created_date")),
                "registrar": clean_text(item.get("registrar")),
            }
        )
        for item in as_list(response.get("matches"))
        if isinstance(item, dict) and item.get("domain")
    ]
    return LookupResult(rows, to_int(response.get("result_count")))


def parse_domain_list(body):
    """Reverse NS returns objects ({"domain": ...}), Reverse MX returns strings; both become {"domain": ...} rows."""
    response = body.get("response") or {}
    rows = []
    for item in as_list(response.get("domains")):
        name = item.get("domain") if isinstance(item, dict) else item
        name = clean_text(name)
        if name:
            rows.append({"domain": name})
    return LookupResult(rows, to_int(response.get("domain_count")))


def parse_ip_history(body):
    response = body.get("response") or {}
    rows = [
        remove_blank_values(
            {
                "ip": clean_text(item.get("ip")),
                "location": clean_text(item.get("location")),
                "owner": clean_text(item.get("owner")),
                "last_seen": clean_text(item.get("lastseen")),
            }
        )
        for item in as_list(response.get("records"))
        if isinstance(item, dict) and item.get("ip")
    ]
    return LookupResult(rows)


def parse_subdomains(body):
    """Each subdomain carries a list of current IPs, kept as a list in the row."""
    response = body.get("response") or {}
    rows = []
    for item in as_list(response.get("subdomains")):
        if not isinstance(item, dict) or not clean_text(item.get("name")):
            continue
        ips = [clean_text(ip) for ip in as_list(item.get("ips")) if clean_text(ip)]
        rows.append(
            remove_blank_values(
                {
                    "subdomain": clean_text(item.get("name")).lower(),
                    "subdomain_ips": ips,
                    "last_resolved": clean_text(item.get("last_resolved")),
                }
            )
        )
    return LookupResult(rows, to_int(response.get("subdomain_count")))


def _as_bool_text(value):
    text = str(value).strip().lower()
    if text in ("true", "1", "yes"):
        return "true"
    if text in ("false", "0", "no"):
        return "false"
    return None


def _number_text(value):
    """Numbers as strings without blanks; the API mixes ints and strings."""
    if value is None or value == "":
        return None
    return str(value).strip()


def parse_abuse_lookup(body):
    response = body.get("response") or {}
    contact = clean_text(response.get("abusecontact"))
    return LookupResult([{"abuse_contact": contact}] if contact else [])


def parse_free_email(body):
    response = body.get("response") or {}
    text = clean_text(response.get("result"))
    if not text:
        return LookupResult([])
    lowered = text.lower()
    if "does not" in lowered:
        verdict = "false"
    elif "does" in lowered:
        verdict = "true"
    else:
        verdict = None
    return LookupResult([remove_blank_values({"free_email": verdict, "free_email_result": text})])


def parse_ip_location(body):
    response = body.get("response") or {}
    row = {
        "city": clean_text(response.get("city")),
        "zipcode": clean_text(response.get("zipcode")),
        "region_code": clean_text(response.get("region_code")),
        "region_name": clean_text(response.get("region_name")),
        "country_code": clean_text(response.get("country_code")),
        "country_name": clean_text(response.get("country_name")),
        "latitude": clean_text(response.get("latitude")),
        "longitude": clean_text(response.get("longitude")),
    }
    if row["zipcode"] == "0":
        row["zipcode"] = None
    row = remove_blank_values(row)
    return LookupResult([row] if row else [])


def parse_reverse_dns(body):
    response = body.get("response") or {}
    rdns = clean_text(response.get("rdns"))
    if rdns:
        rdns = rdns.rstrip(".").lower()
    return LookupResult([{"rdns": rdns}] if rdns else [])


def parse_mac_lookup(body):
    response = body.get("response") or {}
    manufacturer = clean_text(response.get("manufacturer"))
    if not manufacturer or "not found" in manufacturer.lower():
        return LookupResult([])
    return LookupResult([{"manufacturer": manufacturer}])


def parse_dnssec(body):
    result = (body.get("response") or {}).get("result") or {}
    if not isinstance(result, dict):
        return LookupResult([])
    enabled = _as_bool_text(result.get("status"))
    signatures = [
        item for item in as_list((result.get("detail") or {}).get("signatures") if isinstance(result.get("detail"), dict) else [])
        if isinstance(item, dict)
    ]
    row = remove_blank_values(
        {
            "dnssec_enabled": enabled,
            "dnssec_signature_type": [clean_text(item.get("type")) for item in signatures if clean_text(item.get("type"))],
            "dnssec_algorithm": [clean_text(item.get("algorithm")) for item in signatures if clean_text(item.get("algorithm"))],
            "dnssec_signed_by": [clean_text(item.get("signedby")) for item in signatures if clean_text(item.get("signedby"))],
        }
    )
    return LookupResult([row] if row else [])


def parse_spam_db(body):
    response = body.get("response") or {}
    rows = [
        remove_blank_values({"blacklist": clean_text(item.get("name")), "blacklist_result": clean_text(item.get("result"))})
        for item in as_list(response.get("dbs"))
        if isinstance(item, dict) and item.get("name")
    ]
    listed = sum(1 for row in rows if row.get("blacklist_result") not in (None, "ok"))
    for row in rows:
        row["blacklisted_count"] = listed
    return LookupResult(rows)


def parse_http_headers(body):
    response = body.get("response") or {}
    rows = [
        remove_blank_values({"header_name": clean_text(item.get("name")), "header_value": clean_text(item.get("value"))})
        for item in as_list(response.get("headers"))
        if isinstance(item, dict) and item.get("name")
    ]
    return LookupResult(rows)


def parse_port_scan(body):
    response = body.get("response") or {}
    rows = [
        remove_blank_values(
            {
                "port": _number_text(item.get("number")),
                "service": clean_text(item.get("service")),
                "port_status": clean_text(item.get("status")),
            }
        )
        for item in as_list(response.get("port"))
        if isinstance(item, dict) and _number_text(item.get("number"))
    ]
    open_ports = " ".join(row["port"] for row in rows if row.get("port_status") == "open")
    for row in rows:
        row["open_ports"] = open_ports
    return LookupResult(rows)


def parse_ping(body):
    response = body.get("response") or {}
    rows = []
    for region in as_list(response.get("detail")):
        if not isinstance(region, dict):
            continue
        for location in as_list(region.get("locations")):
            if not isinstance(location, dict):
                continue
            rows.append(
                remove_blank_values(
                    {
                        "ping_region": clean_text(region.get("region")),
                        "ping_location": clean_text(location.get("location")),
                        "ping_ip": clean_text(location.get("ip_address")),
                        "ping_min_rtt": _number_text(location.get("min_rtt")),
                        "ping_avg_rtt": _number_text(location.get("avg_rtt")),
                        "ping_max_rtt": _number_text(location.get("max_rtt")),
                        "ping_packet_loss": clean_text(location.get("packet_loss")),
                    }
                )
            )
    return LookupResult(rows)


def parse_traceroute(body):
    response = body.get("response") or {}
    rows = [
        remove_blank_values(
            {
                "hop": _number_text(item.get("number")),
                "hop_hostname": clean_text(item.get("hostname")),
                "hop_ip": clean_text(item.get("ip")),
                "hop_rtt": _number_text(item.get("rtt")),
            }
        )
        for item in as_list(response.get("hops"))
        if isinstance(item, dict)
    ]
    return LookupResult([row for row in rows if row])


def _server_rows(servers, extra):
    rows = []
    for item in as_list(servers):
        if not isinstance(item, dict):
            continue
        row = remove_blank_values(
            {
                "server_location": clean_text(item.get("location")),
                "server_result": clean_text(item.get("resultvalue")),
                "server_status": clean_text(item.get("resultstatus")),
            }
        )
        if row:
            row.update(extra)
            rows.append(row)
    return rows


def parse_propagation(body):
    expected = clean_text(body.get("expectedresponse"))
    extra = {"expected_result": expected} if expected else {}
    return LookupResult(_server_rows((body.get("response") or {}).get("server"), extra))


def parse_chinese_firewall(body):
    response = body.get("response") or {}
    detail = response.get("detail") if isinstance(response.get("detail"), dict) else {}
    summary = response.get("summary") if isinstance(response.get("summary"), dict) else {}
    extra = remove_blank_values(
        {
            "firewall_result": clean_text(summary.get("result")),
            "firewall_description": clean_text(summary.get("description")),
            "expected_result": clean_text(body.get("expectedresponse")),
        }
    )
    return LookupResult(_server_rows(detail.get("server"), extra))


def parse_iran_firewall(body):
    result = clean_text((body.get("response") or {}).get("result"))
    return LookupResult([{"firewall_result": result}] if result else [])


def parse_dns_record(body):
    response = body.get("response") or {}
    rows = []
    for item in as_list(response.get("records")):
        if not isinstance(item, dict):
            continue
        row = remove_blank_values(
            {
                "record_name": clean_text(item.get("name")),
                "record_type": clean_text(item.get("type")),
                "record_ttl": to_int(item.get("ttl")),
                "record_priority": to_int(item.get("priority")),
                "record_data": clean_text(item.get("data")),
            }
        )
        if row.get("record_type") or row.get("record_data"):
            rows.append(row)
    return LookupResult(rows)


def _contact(contact, prefix, fields=("name", "organization", "email", "country")):
    if not isinstance(contact, dict):
        return {}
    out = {}
    for field in fields:
        value = clean_text(contact.get(field))
        if value and "REDACTED" not in value.upper():
            key = "org" if field == "organization" else field
            out["{0}_{1}".format(prefix, key)] = value
    return out


def parse_domain_whois(body):
    response = body.get("response") or {}
    registry = response.get("registryData") or {}
    name_servers = [
        clean_text(host.get("Address")).lower().rstrip(".")
        for host in as_list((registry.get("nameServers") or {}).get("hostNames"))
        if isinstance(host, dict) and clean_text(host.get("Address"))
    ]
    # Status formats vary by registry, for example "clientHold https://icann.org/epp#clientHold".
    statuses = [
        re.sub(r"\s+\(?https?://\S+\)?$", "", line.strip())
        for line in str(registry.get("status") or "").splitlines()
        if line.strip()
    ]
    row = {
        "registrar": clean_text(response.get("registrarName")),
        "registrar_iana_id": clean_text(response.get("registrarIANAID")),
        "created": clean_text(registry.get("standardCreatedDate") or registry.get("createdDate")),
        "updated": clean_text(registry.get("standardUpdatedDate") or registry.get("updatedDate")),
        "expires": clean_text(registry.get("standardExpiresDate") or registry.get("expiresDate")),
        "abuse_email": clean_text(registry.get("abuseEmail")),
        "nameserver": name_servers,
        "domain_status": statuses,
    }
    row.update(_contact(registry.get("registrant"), "registrant"))
    row.update(_contact(registry.get("administrativeContact"), "admin", ("email",)))
    row.update(_contact(registry.get("technicalContact"), "tech", ("email",)))
    row = remove_blank_values(row)
    if not row:
        # Unregistered domains return a record in which every field is empty.
        return LookupResult([])
    row["whois_type"] = "domain"
    return LookupResult([row])


def parse_ip_whois(body):
    response = body.get("response") or {}
    registry = response.get("registryData") or {}
    abuse = registry.get("abuseContact") or {}
    row = remove_blank_values(
        {
            "registry": clean_text(response.get("registrarName")),
            "owner": clean_text(response.get("owner")),
            "netname": clean_text(response.get("netname")),
            "netrange": clean_text(response.get("netrange")),
            "cidr": clean_text(response.get("cidr")),
            "asn": clean_text(response.get("as")),
            "country": clean_text(response.get("country")),
            "created": clean_text(registry.get("standardCreatedDate") or registry.get("createdDate")),
            "updated": clean_text(registry.get("standardUpdatedDate") or registry.get("updatedDate")),
            "abuse_email": clean_text(abuse.get("email") if isinstance(abuse, dict) else None),
        }
    )
    if not row:
        return LookupResult([])
    row["whois_type"] = "ip"
    return LookupResult([row])


# -- registry --------------------------------------------------------------------------------------------------------


LIVE_CACHE_TTL = 3600  # live checks and blacklist status change quickly: cache them for at most an hour


class Action(object):
    def __init__(
        self, name, label, validate, call, parse, fields, input_label, one_to_many=True, summary_fields=(),
        max_cache_ttl=None, live=False,
    ):
        self.name = name
        self.label = label
        self.validate = validate
        self._call = call
        self._parse = parse
        self.fields = fields
        self.input_label = input_label
        self.one_to_many = one_to_many
        # Per-lookup values repeated on every row (rows mode) but shown once in mv mode.
        self.summary_fields = tuple(summary_fields)
        self.max_cache_ttl = max_cache_ttl
        # Live checks make ViewDNS contact the target (ping, port scan, ...).
        self.live = live

    def run(self, client, query, recordtype="ANY"):
        """Performs the API call (one query) and returns a LookupResult."""
        if self.name == "dnsrecord":
            body = client.dns_record(query, recordtype)
        else:
            body = self._call(client, query)
        if self.name == "whois":
            if is_ip(query) or "ip" in (body.get("query") or {}):
                return parse_ip_whois(body)
            return parse_domain_whois(body)
        return self._parse(body)


DOMAIN_WHOIS_FIELDS = [
    "whois_type", "registrar", "registrar_iana_id", "created", "updated", "expires", "abuse_email",
    "registrant_name", "registrant_org", "registrant_email", "registrant_country", "admin_email", "tech_email",
    "nameserver", "domain_status",
]
IP_WHOIS_FIELDS = ["registry", "owner", "netname", "netrange", "cidr", "asn", "country"]

ACTIONS = {
    "reverseip": Action(
        "reverseip", "Reverse IP", validate_host, lambda c, q: c.reverse_ip(q), parse_reverse_ip,
        ["domain", "last_resolved"], "domain or IP address",
    ),
    "reversewhois": Action(
        "reversewhois", "Reverse WHOIS", validate_term, lambda c, q: c.reverse_whois(q), parse_reverse_whois,
        ["domain", "created", "registrar"], "email address, name or organization",
    ),
    "reversens": Action(
        "reversens", "Reverse NS", validate_domain, lambda c, q: c.reverse_ns(q), parse_domain_list,
        ["domain"], "name server host name",
    ),
    "reversemx": Action(
        "reversemx", "Reverse MX", validate_domain, lambda c, q: c.reverse_mx(q), parse_domain_list,
        ["domain"], "mail server host name",
    ),
    "iphistory": Action(
        "iphistory", "IP History", validate_domain, lambda c, q: c.ip_history(q), parse_ip_history,
        ["ip", "location", "owner", "last_seen"], "domain name",
    ),
    "dnsrecord": Action(
        "dnsrecord", "DNS Record", validate_domain, None, parse_dns_record,
        ["record_name", "record_type", "record_ttl", "record_priority", "record_data"], "domain name",
    ),
    "subdomains": Action(
        "subdomains", "Subdomains", validate_domain, lambda c, q: c.subdomains(q), parse_subdomains,
        ["subdomain", "subdomain_ips", "last_resolved"], "domain name",
    ),
    "abuselookup": Action(
        "abuselookup", "Abuse Contact", validate_host, lambda c, q: c.abuse_lookup(q), parse_abuse_lookup,
        ["abuse_contact"], "domain name or IP address", one_to_many=False,
    ),
    "freeemail": Action(
        "freeemail", "Free Email", validate_email_or_domain, lambda c, q: c.free_email(q), parse_free_email,
        ["free_email", "free_email_result"], "domain name or email address", one_to_many=False,
    ),
    "iplocation": Action(
        "iplocation", "IP Location", validate_ip, lambda c, q: c.ip_location(q), parse_ip_location,
        ["city", "zipcode", "region_code", "region_name", "country_code", "country_name", "latitude", "longitude"],
        "IP address", one_to_many=False,
    ),
    "reversedns": Action(
        "reversedns", "Reverse DNS", validate_ip, lambda c, q: c.reverse_dns(q), parse_reverse_dns,
        ["rdns"], "IP address", one_to_many=False,
    ),
    "maclookup": Action(
        "maclookup", "MAC Lookup", validate_mac, lambda c, q: c.mac_lookup(q), parse_mac_lookup,
        ["manufacturer"], "MAC address", one_to_many=False,
    ),
    "dnssec": Action(
        "dnssec", "DNSSEC", validate_domain, lambda c, q: c.dnssec(q), parse_dnssec,
        ["dnssec_enabled", "dnssec_signature_type", "dnssec_algorithm", "dnssec_signed_by"], "domain name",
        one_to_many=False,
    ),
    "spamdblookup": Action(
        "spamdblookup", "Spam Database", validate_ip, lambda c, q: c.spam_db_lookup(q), parse_spam_db,
        ["blacklisted_count", "blacklist", "blacklist_result"], "IP address",
        summary_fields=("blacklisted_count",), max_cache_ttl=LIVE_CACHE_TTL,
    ),
    "httpheaders": Action(
        "httpheaders", "HTTP Headers", validate_host, lambda c, q: c.http_headers(q), parse_http_headers,
        ["header_name", "header_value"], "domain name or IP address", max_cache_ttl=LIVE_CACHE_TTL, live=True,
    ),
    "portscan": Action(
        "portscan", "Port Scan", validate_host, lambda c, q: c.port_scan(q), parse_port_scan,
        ["open_ports", "port", "service", "port_status"], "domain name or IP address",
        summary_fields=("open_ports",), max_cache_ttl=LIVE_CACHE_TTL, live=True,
    ),
    "ping": Action(
        "ping", "Ping", validate_host, lambda c, q: c.ping(q), parse_ping,
        ["ping_region", "ping_location", "ping_ip", "ping_min_rtt", "ping_avg_rtt", "ping_max_rtt", "ping_packet_loss"],
        "domain name or IP address", max_cache_ttl=LIVE_CACHE_TTL, live=True,
    ),
    "traceroute": Action(
        "traceroute", "Traceroute", validate_host, lambda c, q: c.traceroute(q), parse_traceroute,
        ["hop", "hop_hostname", "hop_ip", "hop_rtt"], "domain name or IP address",
        max_cache_ttl=LIVE_CACHE_TTL, live=True,
    ),
    "propagation": Action(
        "propagation", "DNS Propagation", validate_domain, lambda c, q: c.propagation(q), parse_propagation,
        ["expected_result", "server_location", "server_result", "server_status"], "domain name",
        summary_fields=("expected_result",), max_cache_ttl=LIVE_CACHE_TTL, live=True,
    ),
    "chinesefirewall": Action(
        "chinesefirewall", "China Firewall Test", validate_host, lambda c, q: c.chinese_firewall(q),
        parse_chinese_firewall,
        ["firewall_result", "firewall_description", "expected_result", "server_location", "server_result",
         "server_status"],
        "domain name or URL", summary_fields=("firewall_result", "firewall_description", "expected_result"),
        max_cache_ttl=LIVE_CACHE_TTL, live=True,
    ),
    "iranfirewall": Action(
        "iranfirewall", "Iran Firewall Test", validate_site, lambda c, q: c.iran_firewall(q), parse_iran_firewall,
        ["firewall_result"], "domain name or http(s) URL", one_to_many=False, max_cache_ttl=LIVE_CACHE_TTL,
        live=True,
    ),
    "whois": Action(
        "whois", "WHOIS", validate_host, lambda c, q: c.whois(q), None,
        DOMAIN_WHOIS_FIELDS + [f for f in IP_WHOIS_FIELDS if f not in DOMAIN_WHOIS_FIELDS], "domain name or IP address",
        one_to_many=False,
    ),
}

ACTION_NAMES = tuple(sorted(ACTIONS))
