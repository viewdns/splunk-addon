"""Parsers and validators for the network, reputation and live-check lookups (fixtures: live captures and API docs samples)."""

import pytest

from conftest import load_fixture
from ta_viewdns import actions as a
from ta_viewdns.enrich import Outcome
from ta_viewdns.output import enrich_mv, enrich_rows

P = "viewdns_"

NEW = [
    "abuselookup", "freeemail", "iplocation", "reversedns", "maclookup", "dnssec", "spamdblookup", "httpheaders",
    "portscan", "ping", "traceroute", "propagation", "chinesefirewall", "iranfirewall",
]


@pytest.mark.parametrize("name", NEW)
def test_registered_with_declared_fields(name):
    action = a.ACTIONS[name]
    fixtures = ["live_{0}.json".format(name)]
    if name != "dnssec":
        fixtures.append("docs_{0}.json".format(name))
    for fixture in fixtures:
        result = action._parse(load_fixture(fixture))
        for row in result.rows:
            assert set(row) <= set(action.fields), (fixture, set(row) - set(action.fields))
        assert set(action.summary_fields) <= set(action.fields)


def test_abuse_lookup():
    assert a.parse_abuse_lookup(load_fixture("live_abuselookup.json")).rows == [{"abuse_contact": "abuse@gmail.com"}]
    assert a.parse_abuse_lookup({"response": {"abusecontact": ""}}).status == "no_results"


def test_free_email():
    assert a.parse_free_email(load_fixture("live_freeemail.json")).rows[0]["free_email"] == "true"
    assert a.parse_free_email(load_fixture("docs_freeemail.json")).rows[0]["free_email"] == "false"


def test_ip_location_drops_blank_and_zero_zip():
    row = a.parse_ip_location(load_fixture("live_iplocation.json")).rows[0]
    assert row == {"country_code": "US", "country_name": "United States", "latitude": "37.751", "longitude": "-97.822"}
    assert a.parse_ip_location(load_fixture("docs_iplocation.json")).rows[0]["city"] == "Berkeley"


def test_reverse_dns_strips_trailing_dot():
    assert a.parse_reverse_dns(load_fixture("docs_reversedns.json")).rows == [{"rdns": "dns9.quad9.net"}]
    assert a.parse_reverse_dns(load_fixture("live_reversedns.json")).rows == [{"rdns": "dns.google"}]


def test_mac_lookup_not_found_is_no_results():
    assert a.parse_mac_lookup(load_fixture("live_maclookup.json")).status == "no_results"
    assert "APPLE" in a.parse_mac_lookup(load_fixture("docs_maclookup.json")).rows[0]["manufacturer"]


def test_dnssec():
    row = a.parse_dnssec(load_fixture("live_dnssec.json")).rows[0]
    assert row["dnssec_enabled"] == "true"
    assert row["dnssec_signature_type"] == ["HINFO"] and row["dnssec_algorithm"] == ["13"]
    assert a.parse_dnssec({"response": {"result": {"status": "false", "detail": ""}}}).rows == [{"dnssec_enabled": "false"}]


def test_spam_db_counts_listings():
    result = a.parse_spam_db(load_fixture("live_spamdblookup.json"))
    blocked = [row for row in result.rows if row["blacklist_result"] != "ok"]
    assert blocked and all(row["blacklisted_count"] == len(blocked) for row in result.rows)
    assert all(row["blacklisted_count"] == 0 for row in a.parse_spam_db(load_fixture("docs_spamdblookup.json")).rows)


def test_http_headers():
    rows = a.parse_http_headers(load_fixture("docs_httpheaders.json")).rows
    assert rows[0] == {"header_name": "http_status", "header_value": "403"}
    assert a.parse_http_headers(load_fixture("live_httpheaders.json")).status == "no_results"


def test_port_scan_handles_int_and_string_ports():
    live = a.parse_port_scan(load_fixture("live_portscan.json")).rows
    docs = a.parse_port_scan(load_fixture("docs_portscan.json")).rows
    assert live[0]["port"] == "21" and docs[0]["port"] == "21"
    expected = " ".join(str(p["number"]) for p in load_fixture("live_portscan.json")["response"]["port"] if p["status"] == "open")
    assert expected and all(row["open_ports"] == expected for row in live)


def test_ping_flattens_regions():
    rows = a.parse_ping(load_fixture("live_ping.json")).rows
    assert len(rows) == 17
    assert rows[0]["ping_region"] == "Asia" and rows[0]["ping_location"] == "Hong Kong, China"
    assert rows[0]["ping_avg_rtt"] == "0.675" and rows[0]["ping_packet_loss"] == "0%"


def test_traceroute():
    rows = a.parse_traceroute(load_fixture("live_traceroute.json")).rows
    assert rows[0] == {"hop": "1", "hop_hostname": "obfuscated.internal.network.com", "hop_ip": "0.0.0.0", "hop_rtt": "0.000"}


def test_propagation_and_china_firewall_summaries():
    rows = a.parse_propagation(load_fixture("live_propagation.json")).rows
    assert len(rows) == 17 and rows[0]["expected_result"] == "104.26.12.118 104.26.13.118 172.67.75.9"
    china = a.parse_chinese_firewall(load_fixture("live_chinesefirewall.json")).rows
    assert china[0]["firewall_result"] == "visible" and china[0]["server_location"] == "Beijing"


def test_iran_firewall():
    assert a.parse_iran_firewall(load_fixture("live_iranfirewall.json")).rows == [{"firewall_result": "ok"}]


@pytest.mark.parametrize(
    "raw, expected",
    [("00-05-02-34-56-78", "000502345678"), ("0005.0234.5678", "000502345678"), ("f0:18:98", "F01898")],
)
def test_validate_mac(raw, expected):
    assert a.validate_mac(raw) == (expected, None)


@pytest.mark.parametrize("raw", ["xyz", "00:11", "00:11:22:33:44:55:66"])
def test_validate_mac_rejects(raw):
    assert a.validate_mac(raw)[0] is None


def test_validate_site():
    assert a.validate_site("Example.com") == ("http://example.com", None)
    assert a.validate_site("https://Example.com/a?b=1") == ("https://example.com/a?b=1", None)
    assert a.validate_site("ftp://example.com")[0] is None


def test_validate_email_or_domain():
    assert a.validate_email_or_domain("Bob@Gmail.com") == ("gmail.com", None)
    assert a.validate_email_or_domain("gmail.com") == ("gmail.com", None)


def test_ip_only_actions_reject_domains():
    for name in ("iplocation", "reversedns", "spamdblookup"):
        assert a.ACTIONS[name].validate("example.com")[0] is None


def test_live_checks_are_cached_for_at_most_an_hour():
    for name in ("ping", "portscan", "traceroute", "httpheaders", "propagation", "chinesefirewall", "iranfirewall"):
        assert a.ACTIONS[name].live and a.ACTIONS[name].max_cache_ttl == a.LIVE_CACHE_TTL
    assert a.ACTIONS["spamdblookup"].max_cache_ttl == a.LIVE_CACHE_TTL
    assert a.ACTIONS["whois"].max_cache_ttl is None


def test_summary_fields_shown_once_in_mv_mode():
    result = a.parse_port_scan(load_fixture("docs_portscan.json"))
    outcome = Outcome("example.com", "ok", result.rows, len(result.rows))
    [out] = enrich_mv({}, "portscan", [outcome], P, 100)
    assert isinstance(out[P + "open_ports"], str)
    assert len(out[P + "port"]) == len(out[P + "service"]) == len(out[P + "port_status"]) == len(result.rows)
    rows = enrich_rows({}, "portscan", [outcome], P, 100)
    assert all(row[P + "open_ports"] == out[P + "open_ports"] for row in rows)


def test_summary_fields_with_multivalue_input_align_with_query():
    china = a.parse_chinese_firewall(load_fixture("live_chinesefirewall.json"))
    outcomes = [Outcome("a.com", "ok", china.rows, len(china.rows)), Outcome("b.com", "no_results")]
    [out] = enrich_mv({}, "chinesefirewall", outcomes, P, 100)
    assert out[P + "firewall_result"] == ["visible", ""]
    assert out[P + "query"] == ["a.com", "b.com"]


def test_live_check_cache_ttl_is_capped(make_client):
    from ta_viewdns.enrich import Enricher, Settings

    class Cache(object):
        docs = []

        def get_many(self, keys):
            return {}

        def put_many(self, docs):
            self.docs.extend(docs)

    from conftest import FakeResponse

    client, _ = make_client(route=lambda url, params: FakeResponse(200, load_fixture("live_portscan.json")))
    cache = Cache()
    enricher = Enricher(Settings(api_key="k", cache_ttl=86400), lambda: client, cache=cache, clock=lambda: 1000)
    enricher.resolve("portscan", ["example.com"])
    assert cache.docs[0]["expires_at"] == 1000 + 3600
