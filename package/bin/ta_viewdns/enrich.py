"""The enrichment engine shared by the ``viewdns`` search command and the alert action.

A lookup is resolved from, in order: the in-process memo (dedupes values within one search), the KV store cache, then
the API. The engine enforces the per-search credit guard, escalates fatal errors (bad key, no quota, paid-only tool),
and trips a circuit breaker after repeated network failures. Nothing here depends on Splunk; the cache is injected.
"""

import hashlib
import json
import logging
import time

from .actions import ACTIONS, DNS_RECORD_TYPES, STATUS_NO_RESULTS, STATUS_OK, LookupResult
from .client import InvalidInputError, TransientError, ViewDNSError

STATUS_ERROR = "error"
STATUS_SKIPPED = "skipped"
STATUS_GUARD = "skipped_quota_guard"

CIRCUIT_BREAKER_THRESHOLD = 5

logger = logging.getLogger("ta_viewdns.enrich")


class Settings(object):
    def __init__(
        self,
        api_key=None,
        base_url="https://api.viewdns.info",
        timeout=100,
        max_results=100,
        max_lookups=1000,
        cache_ttl=86400,
        proxies=None,
        secrets=(),
    ):
        self.api_key = api_key
        self.base_url = base_url
        self.timeout = timeout
        self.max_results = max_results
        self.max_lookups = max_lookups
        self.cache_ttl = cache_ttl
        self.proxies = proxies
        self.secrets = secrets


class Outcome(object):
    """The result of looking up one value, before the per-call ``limit`` is applied."""

    __slots__ = ("query", "status", "rows", "total_count", "error", "cached")

    def __init__(self, query, status, rows=(), total_count=0, error=None, cached=False):
        self.query = query
        self.status = status
        self.rows = list(rows)
        self.total_count = total_count
        self.error = error
        self.cached = cached

    def limited(self, limit):
        rows = self.rows[:limit] if limit else self.rows
        return rows, self.total_count > len(rows)


def cache_key(action, query, recordtype):
    raw = "{0}|{1}|{2}".format(action, query, recordtype if action == "dnsrecord" else "")
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


class Enricher(object):
    def __init__(self, settings, client_factory, cache=None, clock=time.time):
        """
        Args:
            settings: a Settings instance.
            client_factory: a callable returning a ViewDNSClient. It is called lazily, on the first API lookup,
                so fully cached searches never need the API key.
            cache: an object with ``get_many(keys) -> {key: doc}`` and ``put_many(docs)``, or None.
            clock: returns the current epoch time (injectable for tests).
        """
        self.settings = settings
        self._client_factory = client_factory
        self._client = None
        self.cache = cache if settings.cache_ttl > 0 else None
        self.clock = clock
        self.memo = {}
        self.api_calls = 0
        self.cache_hits = 0
        self.fatal = None  # ViewDNSError that stops every further API call
        self.disabled_actions = {}  # action -> ViewDNSError (for example paid-only tools)
        self._consecutive_transient = 0
        self._messages = []  # (level, text), deduplicated, drained by the caller
        self._seen_messages = set()

    # -- messages ----------------------------------------------------------------------------------------------------

    def _message(self, level, text):
        if (level, text) not in self._seen_messages:
            self._seen_messages.add((level, text))
            self._messages.append((level, text))

    def drain_messages(self):
        messages, self._messages = self._messages, []
        return messages

    # -- client ------------------------------------------------------------------------------------------------------

    def _get_client(self):
        if self._client is None:
            self._client = self._client_factory()
        return self._client

    # -- resolution --------------------------------------------------------------------------------------------------

    @staticmethod
    def normalize(action_name, raw):
        """Returns (query, error) for a raw field value."""
        if raw is None:
            return None, None
        raw = str(raw).strip()
        if not raw:
            return None, None
        return ACTIONS[action_name].validate(raw)

    def resolve(self, action_name, raw_values, recordtype="ANY", use_cache=True, limit=None):
        """Resolves every value (looking up the ones not yet known) and returns {raw_value: Outcome}.

        Values are processed in order, so the credit guard skips the last ones, not random ones.
        """
        action = ACTIONS[action_name]
        recordtype = (recordtype or "ANY").upper()
        if recordtype not in DNS_RECORD_TYPES:
            raise ValueError("recordtype must be one of: {0}".format(", ".join(DNS_RECORD_TYPES)))
        needed = min(limit or self.settings.max_results, self.settings.max_results)

        outcomes = {}
        pending = []  # (raw, query, key) still needing cache or API
        for raw in raw_values:
            if raw in outcomes:
                continue
            query, error = self.normalize(action_name, raw)
            if query is None:
                if error:
                    outcomes[raw] = Outcome(
                        str(raw).strip(), STATUS_ERROR,
                        error="ViewDNS: {0} can't look up '{1}': {2}.".format(
                            action.label, str(raw).strip()[:100], error
                        ),
                    )
                    self._message(
                        "warning",
                        "ViewDNS: some values were not looked up because they are not valid input for {0}; "
                        "see the {{prefix}}error field.".format(action.label),
                    )
                else:
                    outcomes[raw] = Outcome("", STATUS_SKIPPED)
                continue
            key = cache_key(action_name, query, recordtype)
            memo = self.memo.get(key)
            if memo is not None and self._complete(memo, needed):
                outcomes[raw] = memo
            else:
                pending.append((raw, query, key))

        if not pending:
            return outcomes

        # KV store cache, in one bulk read.
        if self.cache is not None and use_cache:
            keys = list({key for _, _, key in pending})
            try:
                docs = self.cache.get_many(keys)
            except Exception as error:  # the cache must never break enrichment
                logger.warning("ViewDNS cache read failed: %s", error)
                docs = {}
            now = self.clock()
            still_pending = []
            for raw, query, key in pending:
                doc = docs.get(key)
                outcome = self._from_cache(doc, query, now) if doc else None
                if outcome is not None and self._complete(outcome, needed):
                    self.memo[key] = outcome
                    outcomes[raw] = outcome
                    self.cache_hits += 1
                else:
                    still_pending.append((raw, query, key))
            pending = still_pending

        # API calls.
        to_cache = []
        for raw, query, key in pending:
            if key in self.memo and self._complete(self.memo[key], needed):
                outcomes[raw] = self.memo[key]
                continue
            outcome = self._lookup(action, query, recordtype)
            if outcome.status in (STATUS_OK, STATUS_NO_RESULTS, STATUS_ERROR):
                # Errors are memoized (not cached) so repeated bad values don't call the API again in this search.
                if outcome.status != STATUS_ERROR or self.fatal is None:
                    self.memo[key] = outcome
            if outcome.status in (STATUS_OK, STATUS_NO_RESULTS) and not outcome.cached:
                to_cache.append(self._to_cache(key, action_name, query, recordtype, outcome))
            outcomes[raw] = outcome

        if to_cache and self.cache is not None:
            try:
                self.cache.put_many(to_cache)
            except Exception as error:
                logger.warning("ViewDNS cache write failed: %s", error)
        return outcomes

    @staticmethod
    def _complete(outcome, needed):
        """True when the outcome holds enough rows to satisfy ``needed`` (or every row there is)."""
        if outcome.status != STATUS_OK:
            return True
        return len(outcome.rows) >= min(needed, outcome.total_count)

    def _lookup(self, action, query, recordtype):
        if self.fatal is not None:
            return Outcome(query, STATUS_ERROR, error=self.fatal.message)
        if action.name in self.disabled_actions:
            return Outcome(query, STATUS_ERROR, error=self.disabled_actions[action.name].message)
        if self.api_calls >= self.settings.max_lookups:
            self._message(
                "warning",
                "ViewDNS: the credit guard stopped lookups after {0} API calls in this search (Max API lookups per "
                "search on the Configuration page). The remaining values have {{prefix}}status=skipped_quota_guard."
                .format(self.settings.max_lookups),
            )
            return Outcome(query, STATUS_GUARD)
        try:
            client = self._get_client()
            self.api_calls += 1
            result = action.run(client, query, recordtype)
        except ViewDNSError as error:
            return self._handle_error(action, query, error)
        except Exception as error:  # unexpected parsing failure: report, don't crash the search
            logger.exception("ViewDNS %s lookup failed unexpectedly", action.name)
            return Outcome(query, STATUS_ERROR, error="ViewDNS: unexpected error: {0}".format(type(error).__name__))
        self._consecutive_transient = 0
        return Outcome(query, result.status, result.rows[: self.settings.max_results], result.total_count)

    def _handle_error(self, action, query, error):
        if error.scope == "search":
            self.fatal = error
            self._message("error", error.message)
        elif error.scope == "action":
            self.disabled_actions[action.name] = error
            self._message("error", error.message)
        elif isinstance(error, TransientError):
            self._consecutive_transient += 1
            self._message("warning", "ViewDNS: some lookups failed because the API could not be reached: {0}".format(error.message))
            if self._consecutive_transient >= CIRCUIT_BREAKER_THRESHOLD:
                self.fatal = ViewDNSError(
                    "ViewDNS: stopped after {0} consecutive network failures. Last error: {1}".format(
                        CIRCUIT_BREAKER_THRESHOLD, error.message
                    )
                )
                self._message("error", self.fatal.message)
        elif isinstance(error, InvalidInputError):
            self._consecutive_transient = 0
            self._message(
                "warning",
                "ViewDNS: the API rejected some values for {0}; see the {{prefix}}error field.".format(action.label),
            )
        else:
            self._message("warning", error.message)
        return Outcome(query, STATUS_ERROR, error=error.message)

    # -- cache documents ---------------------------------------------------------------------------------------------

    def _to_cache(self, key, action_name, query, recordtype, outcome):
        now = int(self.clock())
        ttl = int(self.settings.cache_ttl)
        cap = ACTIONS[action_name].max_cache_ttl
        if cap:
            ttl = min(ttl, cap)
        return {
            "_key": key,
            "action": action_name,
            "query": query,
            "recordtype": recordtype if action_name == "dnsrecord" else "",
            "status": outcome.status,
            "total_count": outcome.total_count,
            "fetched_at": now,
            "expires_at": now + ttl,
            "result": json.dumps(outcome.rows, separators=(",", ":"), sort_keys=True),
        }

    @staticmethod
    def _from_cache(doc, query, now):
        try:
            if float(doc.get("expires_at") or 0) <= now:
                return None
            rows = json.loads(doc.get("result") or "[]")
            if not isinstance(rows, list):
                return None
            result = LookupResult(rows, int(doc.get("total_count") or 0))
        except (TypeError, ValueError):
            return None
        return Outcome(query, result.status, result.rows, result.total_count, cached=True)
