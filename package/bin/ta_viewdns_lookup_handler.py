"""Persistent REST endpoint POST /services/ta_viewdns/lookup (capability: viewdns_lookup).

The ``viewdns`` and ``viewdnsaccount`` commands and the alert action call this endpoint instead of reading the API key
themselves. It runs with the system token (passSystemAuth), so users need only the narrow ``viewdns_lookup``
capability, not ``list_storage_passwords``. The API key never leaves this process, and only this endpoint writes the
KV store cache.

Request (JSON):
    {"op": "lookup", "action": "reverseip", "queries": ["1.2.3.4", ...], "recordtype": "ANY",
     "use_cache": true, "budget": 1000}
    {"op": "balance"}

Lookup response (JSON):
    {"outcomes": {query: {"status", "rows", "total_count", "error", "cached"}}, "messages": [[level, text]],
     "api_calls": n, "cache_hits": n, "max_results": n, "max_lookups": n,
     "fatal": {"scope": "search"|"action", "message": "..."} | null}
"""

import json
import os
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "lib"))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from splunk.persistconn.application import PersistentServerConnectionApplication  # noqa: E402

from ta_viewdns import splunk_env  # noqa: E402
from ta_viewdns.account import summarize_balance  # noqa: E402
from ta_viewdns.actions import ACTION_NAMES, DNS_RECORD_TYPES  # noqa: E402
from ta_viewdns.client import ViewDNSError  # noqa: E402
from ta_viewdns.enrich import Enricher, Settings  # noqa: E402

MAX_QUERIES_PER_REQUEST = 100
SETTINGS_CACHE_SECONDS = 30

logger = splunk_env.setup_logging()


def _response(status, body):
    return {"payload": json.dumps(body), "status": status, "headers": {"Content-Type": "application/json"}}


def _error(status, message):
    return _response(status, {"error": message})


class LookupHandler(PersistentServerConnectionApplication):
    def __init__(self, command_line=None, command_arg=None):
        PersistentServerConnectionApplication.__init__(self)
        self._settings = None
        self._settings_loaded_at = 0

    # -- helpers -----------------------------------------------------------------------------------------------------

    def _load_settings(self, token, rest_uri):
        """Settings are re-read at most every 30 seconds (the handler process is long-lived)."""
        now = time.time()
        if self._settings is None or now - self._settings_loaded_at > SETTINGS_CACHE_SECONDS:
            settings, level = splunk_env.load_settings(token, rest_uri)
            splunk_env.setup_logging(level)
            self._settings, self._settings_loaded_at = settings, now
        return self._settings

    # -- entry point -------------------------------------------------------------------------------------------------

    def handle(self, in_string):
        try:
            request = json.loads(in_string)
        except ValueError:
            return _error(400, "Malformed request.")
        if str(request.get("method", "")).upper() != "POST":
            return _error(405, "Use POST.")
        token = request.get("system_authtoken")
        rest_uri = (request.get("server") or {}).get("rest_uri") or "https://127.0.0.1:8089"
        user = (request.get("session") or {}).get("user")
        try:
            payload = json.loads(request.get("payload") or "{}")
        except ValueError:
            return _error(400, "The request body must be JSON.")
        if not isinstance(payload, dict):
            return _error(400, "The request body must be a JSON object.")

        try:
            settings = self._load_settings(token, rest_uri)
        except ViewDNSError as error:
            return _response(200, {"fatal": {"scope": "search", "message": error.message}, "outcomes": {}})
        except Exception as error:
            logger.exception("ViewDNS settings could not be loaded")
            return _response(
                200, {"fatal": {"scope": "search", "message": "ViewDNS: settings could not be loaded ({0}).".format(
                    type(error).__name__)}, "outcomes": {}}
            )

        op = payload.get("op") or "lookup"
        try:
            if op == "balance":
                return self._balance(settings)
            if op == "lookup":
                return self._lookup(settings, payload, token, rest_uri, user)
        except Exception as error:  # never return a stack trace
            logger.exception("ViewDNS %s request failed", op)
            return _error(500, "ViewDNS: the request failed ({0}).".format(type(error).__name__))
        return _error(400, "Unknown op.")

    def _balance(self, settings):
        try:
            client = splunk_env.make_client_factory(settings)()
            return _response(200, {"balance": summarize_balance(client.account_balance())})
        except ViewDNSError as error:
            return _response(200, {"fatal": {"scope": "search", "message": error.message}})

    def _lookup(self, settings, payload, token, rest_uri, user):
        action = str(payload.get("action") or "").lower()
        if action not in ACTION_NAMES:
            return _error(400, "action must be one of: {0}".format(", ".join(ACTION_NAMES)))
        recordtype = str(payload.get("recordtype") or "ANY").upper()
        if recordtype not in DNS_RECORD_TYPES:
            return _error(400, "recordtype must be one of: {0}".format(", ".join(DNS_RECORD_TYPES)))
        queries = payload.get("queries")
        if not isinstance(queries, list) or not all(isinstance(q, str) for q in queries):
            return _error(400, "queries must be a list of strings.")
        if len(queries) > MAX_QUERIES_PER_REQUEST:
            return _error(400, "At most {0} queries per request.".format(MAX_QUERIES_PER_REQUEST))

        # The caller's remaining credit-guard budget for its search, never more than the configured maximum.
        budget = settings.max_lookups
        try:
            if payload.get("budget") is not None:
                budget = max(0, min(int(payload["budget"]), settings.max_lookups))
        except (TypeError, ValueError):
            pass
        request_settings = Settings(
            api_key=settings.api_key, base_url=settings.base_url, timeout=settings.timeout,
            max_results=settings.max_results, max_lookups=budget, cache_ttl=settings.cache_ttl,
            proxies=settings.proxies, secrets=settings.secrets,
        )
        cache = None
        if settings.cache_ttl > 0:
            try:
                cache = splunk_env.KVCache(splunk_env.connect_service(token, rest_uri))
            except Exception as error:
                logger.warning("ViewDNS cache unavailable: %s", error)
        enricher = Enricher(request_settings, splunk_env.make_client_factory(request_settings), cache)
        outcomes = enricher.resolve(action, queries, recordtype, use_cache=bool(payload.get("use_cache", True)))

        fatal = None
        if enricher.fatal is not None:
            fatal = {"scope": "search", "message": enricher.fatal.message}
        elif action in enricher.disabled_actions:
            fatal = {"scope": "action", "message": enricher.disabled_actions[action].message}
        if enricher.api_calls:
            logger.info(
                "lookup user=%s action=%s queries=%d api_calls=%d cache_hits=%d",
                user, action, len(queries), enricher.api_calls, enricher.cache_hits,
            )
        return _response(200, {
            "outcomes": {
                raw: {
                    "query": outcome.query, "status": outcome.status, "rows": outcome.rows,
                    "total_count": outcome.total_count, "error": outcome.error, "cached": outcome.cached,
                }
                for raw, outcome in outcomes.items()
            },
            "messages": enricher.drain_messages(),
            "api_calls": enricher.api_calls,
            "cache_hits": enricher.cache_hits,
            "max_results": settings.max_results,
            "max_lookups": settings.max_lookups,
            "fatal": fatal,
        })
