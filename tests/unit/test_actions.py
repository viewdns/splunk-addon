import pytest

from conftest import load_fixture
from ta_viewdns import actions
from ta_viewdns.account import summarize_balance


@pytest.mark.parametrize(
    "raw, expected",
    [
        ("Example.COM", "example.com"),
        ("example.com.", "example.com"),
        ("  example.com ", "example.com"),
        ("https://www.Example.com:8443/path?q=1", "www.example.com"),
        ("_dmarc.example.com", "_dmarc.example.com"),
        ("xn--bcher-kva.example", "xn--bcher-kva.example"),
    ],
)
def test_validate_domain_accepts(raw, expected):
    assert actions.validate_domain(raw) == (expected, None)


@pytest.mark.parametrize("raw", ["8.8.8.8", "not a domain", "localhost", "-bad.com", "a..b.com", "http://", "x" * 300])
def test_validate_domain_rejects(raw):
    value, error = actions.validate_domain(raw)
    assert value is None and error


def test_validate_domain_explains_ip():
    assert actions.validate_domain("1.2.3.4")[1] == "expected a domain name, not an IP address"


@pytest.mark.parametrize(
    "raw, expected",
    [("8.8.8.8", "8.8.8.8"), ("2001:DB8::1", "2001:db8::1"), ("[2001:db8::1]", "2001:db8::1"), ("Example.com", "example.com")],
)
def test_validate_host(raw, expected):
    assert actions.validate_host(raw) == (expected, None)


def test_validate_host_rejects():
    assert actions.validate_host("999.1.1.1")[0] is None


def test_validate_term():
    assert actions.validate_term("  Domain@Example.com ") == ("domain@example.com", None)
    assert actions.validate_term("Acme   Corp") == ("acme corp", None)
    assert actions.validate_term("abcd")[0] is None


def test_parse_reverse_ip():
    result = actions.parse_reverse_ip(load_fixture("reverse_ip.json"))
    assert result.status == "ok"
    assert result.total_count == 5
    assert result.rows[0] == {"domain": "atlabs.dev", "last_resolved": "2024-09-28"}


def test_parse_reverse_ip_total_is_never_below_rows():
    result = actions.parse_reverse_ip({"response": {"domain_count": "1", "domains": [{"name": "a.com"}, {"name": "b.com"}]}})
    assert result.total_count == 2


def test_parse_reverse_ip_empty():
    result = actions.parse_reverse_ip(load_fixture("reverse_ip_empty.json"))
    assert result.status == "no_results" and result.rows == []


def test_parse_reverse_whois():
    result = actions.parse_reverse_whois(load_fixture("reverse_whois.json"))
    assert result.total_count == 4
    assert result.rows[0] == {"domain": "atheismfacts.org", "created": "2012-08-03", "registrar": "NAME.COM, LLC"}


def test_parse_reverse_ns_objects_and_reverse_mx_strings():
    ns = actions.parse_domain_list(load_fixture("reverse_ns.json"))
    mx = actions.parse_domain_list(load_fixture("reverse_mx.json"))
    assert ns.total_count == 2217 and ns.rows[0] == {"domain": "123riff.com"}
    assert mx.total_count == 981 and mx.rows[-1] == {"domain": "academyhill.org"}


def test_parse_ip_history():
    result = actions.parse_ip_history(load_fixture("ip_history.json"))
    assert len(result.rows) == 4
    assert result.rows[2] == {
        "ip": "65.254.244.180", "location": "United States", "owner": "BIZLAND-SD", "last_seen": "2015-12-15",
    }


def test_parse_dns_record():
    result = actions.parse_dns_record(load_fixture("dns_record.json"))
    types = [row["record_type"] for row in result.rows]
    assert "SOA" in types and "A" in types
    a_record = [row for row in result.rows if row["record_type"] == "A"][0]
    assert a_record["record_ttl"] == 300 and a_record["record_data"] == "172.64.145.59"


def test_parse_dns_record_empty():
    assert actions.parse_dns_record(load_fixture("dns_record_empty.json")).status == "no_results"


def test_parse_domain_whois():
    row = actions.parse_domain_whois(load_fixture("whois_domain.json")).rows[0]
    assert row["whois_type"] == "domain"
    assert row["registrar"] == "Domain.com, LLC"
    assert row["registrar_iana_id"] == "886"
    assert row["created"] == "1994-07-01T04:00:00Z"
    assert row["registrant_org"] == "Newfold Digital, Inc."
    assert row["registrant_email"] == "corpdomains@newfold.com"
    assert "admin_email" not in row  # "REDACTED FOR PRIVACY" is dropped
    assert all(ns == ns.lower() and not ns.endswith(".") for ns in row["nameserver"])
    assert all("http" not in status for status in row.get("domain_status", []))


def test_parse_domain_whois_unregistered():
    assert actions.parse_domain_whois(load_fixture("whois_domain_empty.json")).status == "no_results"


def test_parse_ip_whois():
    row = actions.parse_ip_whois(load_fixture("whois_ip.json")).rows[0]
    assert row == {
        "whois_type": "ip", "registry": "ARIN", "owner": "Google LLC (GOGL)", "netname": "GOGL",
        "netrange": "8.8.8.0 - 8.8.8.255", "cidr": "8.8.8.0/24", "country": "US",
        "created": "2023-12-28T00:00:00Z", "updated": "2023-12-28T00:00:00Z", "abuse_email": "network-abuse@google.com",
    }


def test_whois_action_picks_ip_or_domain_parser():
    class Client(object):
        def whois(self, query):
            return load_fixture("whois_ip.json" if query[0].isdigit() else "whois_domain.json")

    assert actions.ACTIONS["whois"].run(Client(), "8.8.8.8").rows[0]["whois_type"] == "ip"
    assert actions.ACTIONS["whois"].run(Client(), "domain.com").rows[0]["whois_type"] == "domain"


def test_dnsrecord_action_passes_record_type():
    calls = []

    class Client(object):
        def dns_record(self, domain, record_type):
            calls.append((domain, record_type))
            return load_fixture("dns_record.json")

    actions.ACTIONS["dnsrecord"].run(Client(), "x.com", "MX")
    assert calls == [("x.com", "MX")]


def test_every_action_declares_its_parsed_fields():
    samples = {
        "reverseip": ("reverse_ip.json", actions.parse_reverse_ip),
        "reversewhois": ("reverse_whois.json", actions.parse_reverse_whois),
        "reversens": ("reverse_ns.json", actions.parse_domain_list),
        "reversemx": ("reverse_mx.json", actions.parse_domain_list),
        "iphistory": ("ip_history.json", actions.parse_ip_history),
        "dnsrecord": ("dns_record.json", actions.parse_dns_record),
        "whois": ("whois_domain.json", actions.parse_domain_whois),
        "subdomains": ("subdomains.json", actions.parse_subdomains),
    }
    for name, (fixture_name, parse) in samples.items():
        for row in parse(load_fixture(fixture_name)).rows:
            assert set(row) <= set(actions.ACTIONS[name].fields), name
    for row in actions.parse_ip_whois(load_fixture("whois_ip.json")).rows:
        assert set(row) <= set(actions.ACTIONS["whois"].fields)


def test_account_balance_summary():
    assert summarize_balance(load_fixture("account_balance.json")) == {
        "plan": "monthly", "monthly_limit": 10000, "monthly_usage": 3197, "monthly_remaining": 6803,
        "prepaid_balance": 2000,
    }


def test_account_balance_unlimited():
    body = {"response": {"monthly": {"limit": "0", "usage": "5"}, "prepaid": {"balance": "2000"}}}
    summary = summarize_balance(body)
    assert summary["monthly_limit"] == "unlimited" and summary["monthly_remaining"] == "unlimited"


def test_account_balance_trial():
    assert summarize_balance(load_fixture("account_balance_trial.json"))["plan"] == "trial"


def test_parse_subdomains():
    result = actions.parse_subdomains(load_fixture("subdomains.json"))
    assert result.total_count == 6 and len(result.rows) == 6
    assert result.rows[0] == {
        "subdomain": "api.viewdns.info",
        "subdomain_ips": ["104.26.12.118", "104.26.13.118", "172.67.75.9"],
        "last_resolved": "2026-11-18",
    }
    mail = [row for row in result.rows if row["subdomain"] == "mail.viewdns.info"][0]
    assert mail == {"subdomain": "mail.viewdns.info"}  # no IPs, null last_resolved


def test_parse_subdomains_empty():
    result = actions.parse_subdomains(load_fixture("subdomains_empty.json"))
    assert result.status == "no_results" and result.total_count == 0


def test_subdomains_rejects_ip():
    assert actions.ACTIONS["subdomains"].validate("8.8.8.8")[0] is None
