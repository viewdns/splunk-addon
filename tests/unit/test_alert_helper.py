import json

from ta_viewdns import modalert_viewdns_enrichment_helper as alert
from ta_viewdns.enrich import Outcome


def test_result_values_plain_and_multivalue():
    assert alert.result_values({"f": "a.com"}, "f") == ["a.com"]
    assert alert.result_values({"f": "a.com\nb.com", "__mv_f": "$a.com$;$b.com$"}, "f") == ["a.com", "b.com"]
    assert alert.result_values({"f": "x", "__mv_f": "$co$$t$;$y$"}, "f") == ["co$t", "y"]
    assert alert.result_values({"f": ""}, "f") == []
    assert alert.result_values({}, "f") == []


def test_build_event_one_to_many_always_uses_lists():
    outcome = Outcome("1.2.3.4", "ok", [{"domain": "a.com", "last_resolved": "2024"}], 10)
    event = alert.build_event("reverseip", "dest_ip", outcome, 100, {"orig_sid": "s1", "search_name": None})
    assert event["domain"] == ["a.com"] and event["last_resolved"] == ["2024"]
    assert event["lookup"] == "reverseip" and event["field"] == "dest_ip"
    assert event["total_count"] == 10 and event["truncated"] == 1
    assert event["orig_sid"] == "s1" and "search_name" not in event
    assert list(event)[0] == "time"  # props.conf TIME_PREFIX = ^\{"time":
    json.dumps(event)


def test_build_event_applies_limit():
    rows = [{"domain": "d{0}.com".format(i)} for i in range(5)]
    event = alert.build_event("reversens", "ns", Outcome("ns1.x.com", "ok", rows, 5), 2, {})
    assert event["domain"] == ["d0.com", "d1.com"] and event["result_count"] == 2


def test_build_event_whois():
    outcome = Outcome("x.com", "ok", [{"whois_type": "domain", "registrar": "R", "nameserver": ["ns1.x.com"]}], 1)
    event = alert.build_event("whois", "d", outcome, None, {})
    assert event["registrar"] == "R" and event["nameserver"] == ["ns1.x.com"]


def test_build_event_error():
    event = alert.build_event("whois", "d", Outcome("x.com", "error", error="ViewDNS: boom"), None, {})
    assert event["status"] == "error" and event["error"] == "ViewDNS: boom" and "total_count" not in event


class FakeHelper(object):
    def __init__(self, params, results):
        self.params = params
        self.results = results
        self.logs = []

    def get_param(self, name):
        return self.params.get(name)

    def get_events(self):
        return iter(self.results)

    def log_error(self, msg):
        self.logs.append(("error", msg))

    log_info = log_warn = lambda self, msg: self.logs.append(("info", msg))


def test_invalid_parameters_fail_fast():
    helper = FakeHelper({"lookup_action": "nope", "field": "f", "index": "summary"}, [])
    assert alert.process_event(helper) == 3
    helper = FakeHelper({"lookup_action": "whois", "field": "f", "index": "summary", "limit": "abc"}, [])
    assert alert.process_event(helper) == 3


def test_no_values_is_a_no_op():
    helper = FakeHelper({"lookup_action": "whois", "field": "f", "index": "summary"}, [{"other": "x"}])
    assert alert.process_event(helper) == 0


def test_build_event_subdomains_flattens_ip_lists():
    rows = [{"subdomain": "api.x.com", "subdomain_ips": ["1.1.1.1", "2.2.2.2"]}, {"subdomain": "mail.x.com"}]
    event = alert.build_event("subdomains", "d", Outcome("x.com", "ok", rows, 2), None, {})
    assert event["subdomain"] == ["api.x.com", "mail.x.com"]
    assert event["subdomain_ips"] == ["1.1.1.1 2.2.2.2", ""]


class RunHelper(FakeHelper):
    """Enough of ModularAlertBase/ModularAction for a full process_event run."""

    session_key = "token"
    settings = {"server_uri": "https://127.0.0.1:8089"}
    search_name = "My alert"
    action_name = "viewdns_enrichment"
    sid = "sid1"
    orig_sid = ""
    orig_rid = ""

    def __init__(self, params, results):
        super(RunHelper, self).__init__(params, results)
        self.rid = ""
        self.events = []
        self.messages = []
        self.written = None

    def update(self, result):
        self.rid = result["rid"]

    def addevent(self, raw, sourcetype, cam_header=True):
        self.events.append((json.loads(raw), sourcetype, cam_header))

    def writeevents(self, index, source, fext):
        self.written = (index, source, fext)
        return True

    def message(self, text, status=None, level=None):
        self.messages.append((status, text))


def fake_resolver(monkeypatch, responses):
    from ta_viewdns import remote

    sent = []

    def transport(payload):
        sent.append(payload)
        return responses(payload)

    monkeypatch.setattr(remote, "connect_user_service", lambda token, uri: None)
    monkeypatch.setattr(remote, "splunk_transport", lambda service: transport)
    return sent


def test_full_run_dedupes_and_writes_events(monkeypatch):
    def responses(payload):
        return {
            "outcomes": {q: {"query": q, "status": "ok", "rows": [{"domain": "x.com"}], "total_count": 1, "cached": False}
                         for q in payload["queries"]},
            "messages": [], "api_calls": len(payload["queries"]), "cache_hits": 0, "max_results": 100,
            "max_lookups": 1000, "fatal": None,
        }

    sent = fake_resolver(monkeypatch, responses)
    results = [
        {"rid": "0", "ip": "1.1.1.1"},
        {"rid": "1", "ip": "1.1.1.1\n2.2.2.2", "__mv_ip": "$1.1.1.1$;$2.2.2.2$"},
        {"rid": "2", "ip": "bad value!"},
    ]
    helper = RunHelper({"lookup_action": "reverseip", "field": "ip", "index": "summary", "limit": "5"}, results)
    assert alert.process_event(helper) == 0
    assert sent[0]["queries"] == ["1.1.1.1", "2.2.2.2"]  # deduped, invalid value never sent
    events = {event["query"]: event for event, _, _ in helper.events}
    assert events["1.1.1.1"]["orig_rid"] == "0" and events["2.2.2.2"]["orig_rid"] == "1"
    assert events["bad value!"]["status"] == "error"
    assert all(e["search_name"] == "My alert" and e["orig_sid"] == "sid1" for e in events.values())
    assert all(st == "viewdns:enrichment" and not cam for _, st, cam in helper.events)
    assert helper.written == ("summary", "viewdns_enrichment", "viewdns_enrichment")
    assert helper.messages[-1][0] == "success"


def test_full_run_max_values(monkeypatch):
    def responses(payload):
        return {"outcomes": {q: {"query": q, "status": "no_results", "rows": [], "total_count": 0} for q in payload["queries"]},
                "messages": [], "api_calls": 0, "cache_hits": 0, "max_results": 100, "max_lookups": 1000, "fatal": None}

    sent = fake_resolver(monkeypatch, responses)
    results = [{"rid": str(i), "d": "d{0}.com".format(i)} for i in range(5)]
    helper = RunHelper({"lookup_action": "whois", "field": "d", "index": "summary", "max_values": "2"}, results)
    assert alert.process_event(helper) == 0
    assert sent[0]["queries"] == ["d0.com", "d1.com"]
    assert any("3 more were skipped" in msg for _, msg in helper.logs)


def test_full_run_fatal_error_fails_the_action(monkeypatch):
    fake_resolver(monkeypatch, lambda payload: {
        "outcomes": {}, "fatal": {"scope": "search", "message": "ViewDNS: the API key is invalid."}})
    helper = RunHelper({"lookup_action": "whois", "field": "d", "index": "summary"}, [{"rid": "0", "d": "x.com"}])
    assert alert.process_event(helper) == 2
    assert helper.messages[-1][0] == "failure" and "invalid" in helper.messages[-1][1]
    assert helper.events[0][0]["status"] == "error"
