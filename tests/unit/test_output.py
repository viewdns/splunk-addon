from ta_viewdns.enrich import Outcome
from ta_viewdns.output import enrich_mv, enrich_rows, field_names, values_of

P = "viewdns_"


def reverse_ip_outcome(query, names, total=None):
    rows = [{"domain": name, "last_resolved": "2024-01-0{0}".format(i + 1)} for i, name in enumerate(names)]
    return Outcome(query, "ok" if rows else "no_results", rows, total if total is not None else len(rows))


def test_values_of():
    assert values_of({"f": "a"}, "f") == ["a"]
    assert values_of({"f": ["a", "", "b"]}, "f") == ["a", "b"]
    assert values_of({"f": ""}, "f") == []
    assert values_of({}, "f") == []


def test_mv_single_value():
    record = {"dest_ip": "1.2.3.4", "count": "3"}
    [out] = enrich_mv(record, "reverseip", [reverse_ip_outcome("1.2.3.4", ["a.com", "b.com"], total=10)], P, 100)
    assert out["count"] == "3"
    assert out[P + "query"] == "1.2.3.4"
    assert out[P + "status"] == "ok"
    assert out[P + "domain"] == ["a.com", "b.com"]
    assert out[P + "last_resolved"] == ["2024-01-01", "2024-01-02"]
    assert out[P + "result_count"] == 2 and out[P + "total_count"] == 10 and out[P + "truncated"] == 1
    assert out[P + "cached"] == 0 and out[P + "error"] is None


def test_mv_applies_limit():
    [out] = enrich_mv({}, "reverseip", [reverse_ip_outcome("1.2.3.4", ["a.com", "b.com", "c.com"])], P, 1)
    assert out[P + "domain"] == "a.com" and out[P + "truncated"] == 1


def test_every_record_carries_every_field():
    names = set(field_names("reverseip", P))
    [empty] = enrich_mv({}, "reverseip", [], P, 10)
    [hit] = enrich_mv({}, "reverseip", [reverse_ip_outcome("1.2.3.4", ["a.com"])], P, 10)
    rows = enrich_rows({}, "reverseip", [reverse_ip_outcome("1.2.3.4", [])], P, 10)
    for record in [empty, hit] + rows:
        assert names <= set(record)


def test_mv_missing_field_is_skipped():
    [out] = enrich_mv({"x": "1"}, "reverseip", [], P, 10)
    assert out[P + "status"] == "skipped" and out[P + "domain"] is None


def test_mv_multivalue_input_combines_results():
    outcomes = [
        reverse_ip_outcome("1.1.1.1", ["a.com"]),
        Outcome("bad", "error", error="nope"),
        reverse_ip_outcome("2.2.2.2", ["b.com", "c.com"]),
    ]
    [out] = enrich_mv({}, "reverseip", outcomes, P, 10)
    assert out[P + "query"] == ["1.1.1.1", "bad", "2.2.2.2"]
    assert out[P + "status"] == ["ok", "error", "ok"]
    assert out[P + "error"] == ["", "nope", ""]
    assert out[P + "domain"] == ["a.com", "b.com", "c.com"]
    assert out[P + "action"] == "reverseip"


def test_mv_keeps_parallel_fields_aligned():
    outcome = Outcome("x", "ok", [{"domain": "a.com"}, {"domain": "b.com", "last_resolved": "2024"}], 2)
    [out] = enrich_mv({}, "reverseip", [outcome], P, 10)
    assert out[P + "domain"] == ["a.com", "b.com"]
    assert out[P + "last_resolved"] == ["", "2024"]


def test_mv_whois_list_fields():
    outcome = Outcome("x.com", "ok", [{"registrar": "R", "nameserver": ["ns1.x.com", "ns2.x.com"]}], 1)
    [out] = enrich_mv({}, "whois", [outcome], P, 10)
    assert out[P + "registrar"] == "R"
    assert out[P + "nameserver"] == ["ns1.x.com", "ns2.x.com"]
    assert out[P + "owner"] is None


def test_rows_one_record_per_result():
    record = {"dest_ip": "1.2.3.4"}
    rows = enrich_rows(record, "reverseip", [reverse_ip_outcome("1.2.3.4", ["a.com", "b.com", "c.com"])], P, 2)
    assert [row[P + "domain"] for row in rows] == ["a.com", "b.com"]
    assert all(row["dest_ip"] == "1.2.3.4" and row[P + "truncated"] == 1 for row in rows)
    assert record == {"dest_ip": "1.2.3.4"}  # input not mutated


def test_rows_no_results_passes_event_through_once():
    rows = enrich_rows({"a": 1}, "reverseip", [reverse_ip_outcome("1.2.3.4", [])], P, 10)
    assert len(rows) == 1 and rows[0][P + "status"] == "no_results" and rows[0][P + "domain"] is None


def test_rows_multivalue_input_attributes_each_row():
    outcomes = [reverse_ip_outcome("1.1.1.1", ["a.com"]), reverse_ip_outcome("2.2.2.2", ["b.com"])]
    rows = enrich_rows({}, "reverseip", outcomes, P, 10)
    assert [(row[P + "query"], row[P + "domain"]) for row in rows] == [("1.1.1.1", "a.com"), ("2.2.2.2", "b.com")]


def test_custom_prefix():
    [out] = enrich_mv({}, "reverseip", [reverse_ip_outcome("1.2.3.4", ["a.com"])], "rip_", 10)
    assert out["rip_domain"] == "a.com" and "viewdns_domain" not in out


def subdomain_outcome():
    rows = [
        {"subdomain": "api.x.com", "subdomain_ips": ["1.1.1.1", "2.2.2.2"], "last_resolved": "2026-11-18"},
        {"subdomain": "mail.x.com"},
        {"subdomain": "www.x.com", "subdomain_ips": ["3.3.3.3"], "last_resolved": "2026-11-17"},
    ]
    return Outcome("x.com", "ok", rows, 3)


def test_mv_subdomain_ips_stay_aligned():
    [out] = enrich_mv({}, "subdomains", [subdomain_outcome()], P, 10)
    assert out[P + "subdomain"] == ["api.x.com", "mail.x.com", "www.x.com"]
    assert out[P + "subdomain_ips"] == ["1.1.1.1 2.2.2.2", "", "3.3.3.3"]
    assert out[P + "last_resolved"] == ["2026-11-18", "", "2026-11-17"]


def test_rows_subdomain_ips_are_multivalue():
    rows = enrich_rows({}, "subdomains", [subdomain_outcome()], P, 10)
    assert rows[0][P + "subdomain_ips"] == ["1.1.1.1", "2.2.2.2"]
    assert rows[1][P + "subdomain_ips"] is None
    assert rows[2][P + "subdomain_ips"] == "3.3.3.3"
