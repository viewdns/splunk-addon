"""Caller side of the ``ta_viewdns/lookup`` REST endpoint, used by the search commands and the alert action.

``RemoteResolver`` mirrors ``Enricher.resolve``: it validates and deduplicates values locally (bad values never leave
the search process), sends the unknown ones to the endpoint in batches, and keeps the per-search state: the memo,
the credit-guard budget, and fatal errors.
"""

import json

from .actions import ACTIONS, DNS_RECORD_TYPES
from .enrich import STATUS_ERROR, STATUS_SKIPPED, Enricher, Outcome, cache_key

BATCH_SIZE = 25
ENDPOINT = "ta_viewdns/lookup"

MISSING_CAPABILITY = (
    "ViewDNS: your Splunk role is not allowed to run ViewDNS lookups. Ask an admin to give you the viewdns_user "
    "role (or the viewdns_lookup capability)."
)


class TransportError(Exception):
    def __init__(self, message, status=None):
        super(TransportError, self).__init__(message)
        self.message = message
        self.status = status


def splunk_transport(service):
    """Returns a callable that POSTs a JSON payload to the lookup endpoint with the caller's session."""

    def send(payload):
        from splunklib.binding import HTTPError

        try:
            # post() sends a str body as-is (request() would form-encode it).
            response = service.post(ENDPOINT, headers=[("Content-Type", "application/json")], body=json.dumps(payload))
        except HTTPError as error:
            if error.status == 403:
                raise TransportError(MISSING_CAPABILITY, 403)
            body = ""
            try:
                body = json.loads(error.body or b"{}").get("error") or ""
            except (ValueError, AttributeError, TypeError):
                pass
            raise TransportError(
                "ViewDNS: the add-on's lookup service returned HTTP {0}. {1}".format(error.status, body).strip(),
                error.status,
            )
        return json.loads(response.body.read())

    return send


def connect_user_service(session_key, splunkd_uri):
    from splunklib import client

    from .splunk_env import _split_uri

    scheme, host, port = _split_uri(splunkd_uri)
    return client.Service(scheme=scheme, host=host, port=port, token=session_key)


class RemoteResolver(object):
    def __init__(self, transport):
        self._send = transport
        self.memo = {}
        self.fatal = None  # message: stops every further request
        self.disabled_actions = {}
        self.api_calls = 0
        self.cache_hits = 0
        self.max_results = None
        self.max_lookups = None
        self._messages = []
        self._seen = set()

    def _message(self, level, text):
        if (level, text) not in self._seen:
            self._seen.add((level, text))
            self._messages.append((level, text))

    def drain_messages(self):
        messages, self._messages = self._messages, []
        return messages

    def balance(self):
        try:
            response = self._send({"op": "balance"})
        except TransportError as error:
            self._message("error", error.message)
            return None
        if response.get("fatal"):
            self._message("error", response["fatal"]["message"])
            return None
        return response.get("balance")

    def resolve(self, action_name, raw_values, recordtype="ANY", use_cache=True, limit=None):
        action = ACTIONS[action_name]
        recordtype = (recordtype or "ANY").upper()
        if recordtype not in DNS_RECORD_TYPES:
            raise ValueError("recordtype must be one of: {0}".format(", ".join(DNS_RECORD_TYPES)))

        outcomes = {}
        pending = {}  # query -> [raw values]
        for raw in raw_values:
            if raw in outcomes or any(raw in raws for raws in pending.values()):
                continue
            query, error = Enricher.normalize(action_name, raw)
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
            if key in self.memo:
                outcomes[raw] = self.memo[key]
            else:
                pending.setdefault(query, []).append(raw)

        queries = list(pending)
        for start in range(0, len(queries), BATCH_SIZE):
            batch = queries[start:start + BATCH_SIZE]
            results = self._lookup_batch(action_name, batch, recordtype, use_cache)
            for query in batch:
                outcome = results.get(query) or Outcome(query, STATUS_ERROR, error=self.fatal or "ViewDNS: no result.")
                if outcome.status != STATUS_ERROR or self.fatal is None:
                    self.memo[cache_key(action_name, query, recordtype)] = outcome
                for raw in pending[query]:
                    outcomes[raw] = outcome
        return outcomes

    def _lookup_batch(self, action_name, batch, recordtype, use_cache):
        if self.fatal is not None:
            return {query: Outcome(query, STATUS_ERROR, error=self.fatal) for query in batch}
        if action_name in self.disabled_actions:
            return {query: Outcome(query, STATUS_ERROR, error=self.disabled_actions[action_name]) for query in batch}
        payload = {
            "op": "lookup", "action": action_name, "queries": batch, "recordtype": recordtype,
            "use_cache": bool(use_cache),
        }
        if self.max_lookups is not None:
            payload["budget"] = max(0, self.max_lookups - self.api_calls)
        try:
            response = self._send(payload)
        except TransportError as error:
            self.fatal = error.message
            self._message("error", error.message)
            return {query: Outcome(query, STATUS_ERROR, error=error.message) for query in batch}

        self.api_calls += int(response.get("api_calls") or 0)
        self.cache_hits += int(response.get("cache_hits") or 0)
        if response.get("max_results") is not None:
            self.max_results = int(response["max_results"])
        if response.get("max_lookups") is not None:
            self.max_lookups = int(response["max_lookups"])
        for level, text in response.get("messages") or []:
            self._message(level, text)
        fatal = response.get("fatal")
        if fatal:
            self._message("error", fatal["message"])
            if fatal.get("scope") == "action":
                self.disabled_actions[action_name] = fatal["message"]
            else:
                self.fatal = fatal["message"]

        results = {}
        for query, data in (response.get("outcomes") or {}).items():
            results[query] = Outcome(
                data.get("query") or query, data.get("status") or STATUS_ERROR, data.get("rows") or [],
                data.get("total_count") or 0, data.get("error"), bool(data.get("cached")),
            )
        return results
