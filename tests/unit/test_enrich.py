import json

import pytest

from conftest import FakeResponse, load_fixture
from ta_viewdns.enrich import Enricher, Settings, cache_key

NOW = 1_800_000_000


class MemoryCache(object):
    def __init__(self, docs=None, fail=False):
        self.docs = dict(docs or {})
        self.reads = []
        self.writes = []
        self.fail = fail

    def get_many(self, keys):
        if self.fail:
            raise RuntimeError("kvstore down")
        self.reads.append(list(keys))
        return {key: self.docs[key] for key in keys if key in self.docs}

    def put_many(self, docs):
        if self.fail:
            raise RuntimeError("kvstore down")
        self.writes.extend(docs)
        for doc in docs:
            self.docs[doc["_key"]] = doc


def route_by_path(mapping):
    """Route fake API responses by URL path; values are fixture names, FakeResponses or exceptions."""

    def route(url, params):
        for path, value in mapping.items():
            if url.endswith(path):
                if isinstance(value, str):
                    return FakeResponse(200, load_fixture(value))
                return value
        raise AssertionError("unexpected URL " + url)

    return route


@pytest.fixture
def engine(make_client):
    def factory(route=None, responses=None, cache=None, **settings):
        client, session = make_client(responses, route)
        enricher = Enricher(Settings(api_key="k", **settings), lambda: client, cache=cache, clock=lambda: NOW)
        return enricher, session

    return factory


def test_dedupes_values_within_a_search(engine):
    enricher, session = engine(route_by_path({"/reverseip/": "reverse_ip.json"}))
    outcomes = enricher.resolve("reverseip", ["1.2.3.4", "1.2.3.4", " 1.2.3.4 "])
    assert len(session.requests) == 1
    assert outcomes["1.2.3.4"].status == "ok"
    # later chunk of the same search
    enricher.resolve("reverseip", ["1.2.3.4"])
    assert len(session.requests) == 1
    assert enricher.api_calls == 1


def test_normalized_values_share_one_lookup(engine):
    enricher, session = engine(route_by_path({"/iphistory/": "ip_history.json"}))
    enricher.resolve("iphistory", ["Domain.com", "domain.com.", "https://domain.com/x"])
    assert len(session.requests) == 1


def test_empty_and_invalid_values_make_no_calls(engine):
    enricher, session = engine(route_by_path({}))
    outcomes = enricher.resolve("iphistory", ["", None, "8.8.8.8", "not a domain"])
    assert session.requests == []
    assert outcomes[""].status == "skipped"
    assert outcomes["8.8.8.8"].status == "error"
    assert "not an IP address" in outcomes["8.8.8.8"].error
    assert enricher.drain_messages()[0][0] == "warning"


def test_cache_hit_avoids_the_api(engine):
    key = cache_key("reverseip", "1.2.3.4", "ANY")
    doc = {
        "_key": key, "status": "ok", "total_count": 1, "expires_at": NOW + 60,
        "result": json.dumps([{"domain": "cached.com"}]),
    }
    cache = MemoryCache({key: doc})
    enricher, session = engine(route_by_path({}), cache=cache)
    outcome = enricher.resolve("reverseip", ["1.2.3.4"])["1.2.3.4"]
    assert session.requests == []
    assert outcome.cached and outcome.rows == [{"domain": "cached.com"}]
    assert enricher.cache_hits == 1


def test_expired_cache_entry_is_refetched_and_rewritten(engine):
    key = cache_key("reverseip", "1.2.3.4", "ANY")
    cache = MemoryCache({key: {"_key": key, "status": "ok", "total_count": 1, "expires_at": NOW - 1, "result": "[]"}})
    enricher, session = engine(route_by_path({"/reverseip/": "reverse_ip.json"}), cache=cache, cache_ttl=3600)
    outcome = enricher.resolve("reverseip", ["1.2.3.4"])["1.2.3.4"]
    assert len(session.requests) == 1 and not outcome.cached
    written = cache.docs[key]
    assert written["expires_at"] == NOW + 3600
    assert written["action"] == "reverseip" and written["query"] == "1.2.3.4"
    assert len(json.loads(written["result"])) == 5
    assert "k" not in json.dumps(written).split('"')  # API key never stored


def test_cache_disabled_by_zero_ttl(engine):
    cache = MemoryCache()
    enricher, _ = engine(route_by_path({"/reverseip/": "reverse_ip.json"}), cache=cache, cache_ttl=0)
    enricher.resolve("reverseip", ["1.2.3.4"])
    assert cache.reads == [] and cache.writes == []


def test_cache_false_skips_reads_but_writes(engine):
    key = cache_key("reverseip", "1.2.3.4", "ANY")
    cache = MemoryCache({key: {"_key": key, "status": "ok", "total_count": 1, "expires_at": NOW + 60, "result": "[]"}})
    enricher, session = engine(route_by_path({"/reverseip/": "reverse_ip.json"}), cache=cache)
    enricher.resolve("reverseip", ["1.2.3.4"], use_cache=False)
    assert cache.reads == [] and len(session.requests) == 1 and len(cache.writes) == 1


def test_no_results_are_cached_but_errors_are_not(engine):
    cache = MemoryCache()
    enricher, _ = engine(
        route_by_path({"/reverseip/": "reverse_ip_empty.json", "/iphistory/": "ip_history_error.json"}), cache=cache
    )
    enricher.resolve("reverseip", ["9.9.9.9"])
    enricher.resolve("iphistory", ["example.com"])
    assert [doc["status"] for doc in cache.writes] == ["no_results"]


def test_cache_failure_does_not_break_enrichment(engine):
    enricher, session = engine(route_by_path({"/reverseip/": "reverse_ip.json"}), cache=MemoryCache(fail=True))
    assert enricher.resolve("reverseip", ["1.2.3.4"])["1.2.3.4"].status == "ok"


def test_dns_record_type_is_part_of_the_cache_key():
    assert cache_key("dnsrecord", "x.com", "A") != cache_key("dnsrecord", "x.com", "MX")
    assert cache_key("reverseip", "x.com", "A") == cache_key("reverseip", "x.com", "MX")


def test_invalid_record_type(engine):
    enricher, _ = engine(route_by_path({}))
    with pytest.raises(ValueError):
        enricher.resolve("dnsrecord", ["x.com"], recordtype="BOGUS")


def test_rows_are_capped_at_max_results(engine):
    enricher, _ = engine(route_by_path({"/reverseip/": "reverse_ip.json"}), max_results=2)
    outcome = enricher.resolve("reverseip", ["1.2.3.4"])["1.2.3.4"]
    assert len(outcome.rows) == 2 and outcome.total_count == 5
    rows, truncated = outcome.limited(1)
    assert len(rows) == 1 and truncated


def test_credit_guard(engine):
    enricher, session = engine(route_by_path({"/reverseip/": "reverse_ip.json"}), max_lookups=2)
    outcomes = enricher.resolve("reverseip", ["1.1.1.1", "2.2.2.2", "3.3.3.3", "4.4.4.4"])
    assert len(session.requests) == 2
    assert [outcomes[v].status for v in ["1.1.1.1", "2.2.2.2", "3.3.3.3", "4.4.4.4"]] == [
        "ok", "ok", "skipped_quota_guard", "skipped_quota_guard",
    ]
    assert any("credit guard" in text for _, text in enricher.drain_messages())
    # cached and already-known values are still served after the guard trips
    assert enricher.resolve("reverseip", ["1.1.1.1"])["1.1.1.1"].status == "ok"


def test_bad_key_is_fatal_for_the_search(engine):
    enricher, session = engine(route_by_path({"/reverseip/": FakeResponse(401, load_fixture("error_401.json"))}))
    outcomes = enricher.resolve("reverseip", ["1.1.1.1", "2.2.2.2", "3.3.3.3"])
    assert len(session.requests) == 1
    assert all(outcome.status == "error" for outcome in outcomes.values())
    assert all("API key is invalid" in outcome.error for outcome in outcomes.values())
    messages = enricher.drain_messages()
    assert messages == [("error", outcomes["1.1.1.1"].error)]
    enricher.resolve("reverseip", ["4.4.4.4"])
    assert len(session.requests) == 1


def test_quota_exhausted_is_fatal_and_not_retried(engine):
    enricher, session = engine(route_by_path({"/whois/v2/": FakeResponse(429, load_fixture("error_429.json"))}))
    outcomes = enricher.resolve("whois", ["a.com", "b.com"])
    assert len(session.requests) == 1
    assert "quota" in outcomes["b.com"].error


def test_paid_plan_error_disables_only_that_action(engine):
    enricher, session = engine(
        route_by_path({"/whois/v2/": FakeResponse(403, load_fixture("error_403.json")), "/iphistory/": "ip_history.json"})
    )
    outcomes = enricher.resolve("whois", ["a.com", "b.com"])
    assert len(session.requests) == 1 and outcomes["b.com"].status == "error"
    assert enricher.resolve("iphistory", ["a.com"])["a.com"].status == "ok"


def test_invalid_input_from_api_is_per_value(engine):
    def route(url, params):
        if params["host"] == "nonexistent.example":
            return FakeResponse(200, load_fixture("reverse_ip_error.json"))
        return FakeResponse(200, load_fixture("reverse_ip.json"))

    enricher, _ = engine(route)
    outcomes = enricher.resolve("reverseip", ["nonexistent.example", "1.2.3.4"])
    assert outcomes["nonexistent.example"].status == "error"
    assert outcomes["1.2.3.4"].status == "ok"
    assert enricher.fatal is None


def test_circuit_breaker_after_consecutive_network_failures(engine):
    enricher, session = engine(route=lambda url, params: FakeResponse(503, text="down"))
    values = ["{0}.{0}.{0}.{0}".format(i) for i in range(1, 9)]
    outcomes = enricher.resolve("reverseip", values)
    assert enricher.fatal is not None
    # 5 values x 4 attempts each, then no more calls
    assert len(session.requests) == 5 * 4
    assert "consecutive network failures" in outcomes[values[-1]].error


def test_client_is_created_lazily(make_client):
    created = []
    key = cache_key("reverseip", "1.2.3.4", "ANY")
    cache = MemoryCache({key: {"_key": key, "status": "ok", "total_count": 0, "expires_at": NOW + 60, "result": "[]"}})
    enricher = Enricher(Settings(api_key="k"), lambda: created.append(1), cache=cache, clock=lambda: NOW)
    enricher.resolve("reverseip", ["1.2.3.4"])
    assert created == []


def test_cached_entry_with_too_few_rows_is_refetched(engine):
    key = cache_key("reverseip", "1.2.3.4", "ANY")
    doc = {"_key": key, "status": "ok", "total_count": 5, "expires_at": NOW + 60, "result": json.dumps([{"domain": "a"}])}
    enricher, session = engine(route_by_path({"/reverseip/": "reverse_ip.json"}), cache=MemoryCache({key: doc}))
    outcome = enricher.resolve("reverseip", ["1.2.3.4"], limit=3)["1.2.3.4"]
    assert len(session.requests) == 1 and len(outcome.rows) == 5
