"""End-to-end tests: RemoteResolver -> ta_viewdns/lookup handler -> Enricher -> fake ViewDNS API."""

import json
import sys
import types

import pytest

from conftest import FakeResponse, FakeSession, load_fixture

# Stub Splunk's persistent REST handler base class before the handler is imported.
_persistconn = types.ModuleType("splunk.persistconn.application")
_persistconn.PersistentServerConnectionApplication = type(
    "PersistentServerConnectionApplication", (object,), {"__init__": lambda self: None}
)
sys.modules.setdefault("splunk", types.ModuleType("splunk"))
sys.modules.setdefault("splunk.persistconn", types.ModuleType("splunk.persistconn"))
sys.modules["splunk.persistconn.application"] = _persistconn

import ta_viewdns_lookup_handler as handler_module  # noqa: E402
from ta_viewdns import remote, splunk_env  # noqa: E402
from ta_viewdns.client import ConfigurationError, ViewDNSClient  # noqa: E402
from ta_viewdns.enrich import Settings  # noqa: E402

API_KEY = "server-side-key-0123456789"


class Harness(object):
    def __init__(self, monkeypatch, route, **settings):
        self.session = FakeSession(route=route)
        self.settings = Settings(api_key=API_KEY, cache_ttl=0, **settings)
        self.requests = []
        self.settings_error = None
        monkeypatch.setattr(splunk_env, "load_settings", self._load_settings)
        monkeypatch.setattr(
            splunk_env,
            "make_client_factory",
            lambda s: (lambda: ViewDNSClient(s.api_key, session=self.session, sleep=lambda x: None)),
        )
        self.handler = handler_module.LookupHandler()

    def _load_settings(self, token, uri):
        assert token == "system-token"
        if self.settings_error:
            raise self.settings_error
        return self.settings, "INFO"

    def transport(self, payload):
        """What splunkd does: wrap the body in a request envelope, call handle(), unwrap the payload."""
        self.requests.append(payload)
        envelope = {
            "method": "POST",
            "payload": json.dumps(payload),
            "system_authtoken": "system-token",
            "session": {"user": "analyst", "authtoken": "user-token"},
            "server": {"rest_uri": "https://127.0.0.1:8089"},
        }
        response = self.handler.handle(json.dumps(envelope))
        body = json.loads(response["payload"])
        if response["status"] != 200:
            raise remote.TransportError(body.get("error"), response["status"])
        return body


def route(mapping):
    def handle(url, params):
        for path, value in mapping.items():
            if url.endswith(path):
                return FakeResponse(200, load_fixture(value)) if isinstance(value, str) else value
        raise AssertionError(url)

    return handle


def test_lookup_round_trip(monkeypatch):
    harness = Harness(monkeypatch, route({"/reverseip/": "reverse_ip.json"}))
    resolver = remote.RemoteResolver(harness.transport)
    outcomes = resolver.resolve("reverseip", ["1.2.3.4", "1.2.3.4", "bad value!", ""])
    assert outcomes["1.2.3.4"].status == "ok" and len(outcomes["1.2.3.4"].rows) == 5
    assert outcomes["bad value!"].status == "error"
    assert outcomes[""].status == "skipped"
    assert harness.requests[0]["queries"] == ["1.2.3.4"]  # invalid/empty values never leave the search
    assert resolver.api_calls == 1 and resolver.max_results == 100


def test_api_key_never_reaches_the_caller(monkeypatch):
    harness = Harness(monkeypatch, route({"/reverseip/": "reverse_ip.json", "/whois/v2/": FakeResponse(401, load_fixture("error_401.json"))}))
    resolver = remote.RemoteResolver(harness.transport)
    raw = []
    original = harness.transport

    def recording(payload):
        body = original(payload)
        raw.append(json.dumps(body))
        return body

    resolver._send = recording
    resolver.resolve("reverseip", ["1.2.3.4"])
    resolver.resolve("whois", ["x.com"])
    assert raw and all(API_KEY not in text for text in raw)


def test_memo_spans_chunks(monkeypatch):
    harness = Harness(monkeypatch, route({"/reverseip/": "reverse_ip.json"}))
    resolver = remote.RemoteResolver(harness.transport)
    resolver.resolve("reverseip", ["1.2.3.4"])
    resolver.resolve("reverseip", ["1.2.3.4", "1.2.3.4"])
    assert len(harness.requests) == 1


def test_batches(monkeypatch):
    harness = Harness(monkeypatch, route({"/reverseip/": "reverse_ip.json"}))
    resolver = remote.RemoteResolver(harness.transport)
    values = ["10.0.0.{0}".format(i) for i in range(60)]
    outcomes = resolver.resolve("reverseip", values)
    assert [len(r["queries"]) for r in harness.requests] == [25, 25, 10]
    assert all(outcomes[v].status == "ok" for v in values)


def test_credit_guard_spans_requests(monkeypatch):
    harness = Harness(monkeypatch, route({"/reverseip/": "reverse_ip.json"}), max_lookups=30)
    resolver = remote.RemoteResolver(harness.transport)
    values = ["10.0.0.{0}".format(i) for i in range(60)]
    outcomes = resolver.resolve("reverseip", values)
    assert resolver.api_calls == 30
    assert harness.requests[1]["budget"] == 5 and harness.requests[2]["budget"] == 0
    assert sum(1 for v in values if outcomes[v].status == "skipped_quota_guard") == 30
    assert any("credit guard" in text for _, text in resolver.drain_messages())


def test_fatal_error_stops_requests(monkeypatch):
    harness = Harness(monkeypatch, route({"/reverseip/": FakeResponse(429, load_fixture("error_429.json"))}))
    resolver = remote.RemoteResolver(harness.transport)
    values = ["10.0.0.{0}".format(i) for i in range(60)]
    outcomes = resolver.resolve("reverseip", values)
    assert len(harness.requests) == 1 and len(harness.session.requests) == 1
    assert all("quota" in outcomes[v].error for v in values)
    assert [level for level, _ in resolver.drain_messages()] == ["error"]


def test_paid_plan_error_disables_only_that_action(monkeypatch):
    harness = Harness(
        monkeypatch,
        route({"/whois/v2/": FakeResponse(403, load_fixture("error_403.json")), "/iphistory/": "ip_history.json"}),
    )
    resolver = remote.RemoteResolver(harness.transport)
    resolver.resolve("whois", ["a.com"])
    resolver.resolve("whois", ["b.com"])
    assert len(harness.requests) == 1
    assert resolver.resolve("iphistory", ["a.com"])["a.com"].status == "ok"


def test_not_configured(monkeypatch):
    harness = Harness(monkeypatch, route({}))
    harness.settings_error = ConfigurationError("ViewDNS: no API key is configured.")
    resolver = remote.RemoteResolver(harness.transport)
    outcome = resolver.resolve("reverseip", ["1.2.3.4"])["1.2.3.4"]
    assert outcome.status == "error" and "no API key" in outcome.error


def test_missing_capability_message():
    def forbidden(payload):
        raise remote.TransportError(remote.MISSING_CAPABILITY, 403)

    resolver = remote.RemoteResolver(forbidden)
    outcome = resolver.resolve("reverseip", ["1.2.3.4", "5.6.7.8"])["5.6.7.8"]
    assert "viewdns_user" in outcome.error
    assert resolver.drain_messages() == [("error", remote.MISSING_CAPABILITY)]


def test_balance(monkeypatch):
    harness = Harness(monkeypatch, route({"/account/": "account_balance.json"}))
    assert remote.RemoteResolver(harness.transport).balance()["monthly_remaining"] == 6803


@pytest.mark.parametrize(
    "payload, status",
    [
        ({"op": "lookup", "action": "nope", "queries": []}, 400),
        ({"op": "lookup", "action": "whois", "queries": "x.com"}, 400),
        ({"op": "lookup", "action": "dnsrecord", "queries": ["x.com"], "recordtype": "BOGUS"}, 400),
        ({"op": "lookup", "action": "whois", "queries": ["a.com"] * 101}, 400),
        ({"op": "explode"}, 400),
    ],
)
def test_handler_rejects_bad_requests(monkeypatch, payload, status):
    harness = Harness(monkeypatch, route({}))
    with pytest.raises(remote.TransportError) as info:
        harness.transport(payload)
    assert info.value.status == status


def test_handler_rejects_get(monkeypatch):
    harness = Harness(monkeypatch, route({}))
    response = harness.handler.handle(json.dumps({"method": "GET"}))
    assert response["status"] == 405


def test_budget_cannot_exceed_configured_maximum(monkeypatch):
    harness = Harness(monkeypatch, route({"/reverseip/": "reverse_ip.json"}), max_lookups=2)
    body = harness.transport({"op": "lookup", "action": "reverseip", "queries": ["1.1.1.1", "2.2.2.2", "3.3.3.3"], "budget": 999})
    assert body["api_calls"] == 2
