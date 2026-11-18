import pytest
import requests

from conftest import API_KEY, FakeResponse, load_fixture
from ta_viewdns import client as client_module
from ta_viewdns.client import (
    AuthError,
    ConfigurationError,
    InvalidInputError,
    PaidPlanError,
    QuotaError,
    TransientError,
    ViewDNSClient,
    ViewDNSError,
)


def test_request_sends_key_output_and_params(make_client):
    client, session = make_client([FakeResponse(200, load_fixture("reverse_ip.json"))])
    body = client.reverse_ip("example.com")
    request = session.requests[0]
    assert request["url"] == "https://api.viewdns.info/reverseip/"
    assert request["params"] == {"host": "example.com", "apikey": API_KEY, "output": "json"}
    assert body["response"]["domain_count"] == "5"


def test_base_url_trailing_slash_and_timeout(make_client):
    client, session = make_client([FakeResponse(200, load_fixture("whois_ip.json"))], base_url="https://x.test/", timeout=7)
    client.whois("8.8.8.8")
    assert session.requests[0]["url"] == "https://x.test/whois/v2/"
    assert session.requests[0]["timeout"] == 7


def test_missing_api_key_is_configuration_error():
    with pytest.raises(ConfigurationError):
        ViewDNSClient("")


@pytest.mark.parametrize(
    "status, fixture_name, error_type, text",
    [
        (401, "error_401.json", AuthError, "API key is invalid"),
        (403, "error_403.json", PaidPlanError, "paid ViewDNS API plan"),
        (429, "error_429.json", QuotaError, "quota is used up"),
        (400, "error_400.json", InvalidInputError, "Invalid domain or IP specified"),
    ],
)
def test_error_statuses_map_to_typed_errors(make_client, status, fixture_name, error_type, text):
    client, session = make_client([FakeResponse(status, load_fixture(fixture_name))])
    with pytest.raises(error_type) as info:
        client.whois("example.com")
    assert text in str(info.value)
    assert len(session.requests) == 1  # never retried


def test_error_scopes():
    assert AuthError("x").scope == "search"
    assert QuotaError("x").scope == "search"
    assert PaidPlanError("x").scope == "action"
    assert InvalidInputError("x").scope == "value"
    assert TransientError("x").scope == "value"


def test_429_is_not_retried(make_client):
    client, session = make_client([FakeResponse(429, load_fixture("error_429.json"))] * 4)
    with pytest.raises(QuotaError):
        client.reverse_ip("1.2.3.4")
    assert len(session.requests) == 1


def test_5xx_is_retried_then_succeeds(make_client):
    sleeps = []
    client, session = make_client(
        [FakeResponse(503, text="busy"), FakeResponse(502, text="bad"), FakeResponse(200, load_fixture("reverse_ip.json"))]
    )
    client._sleep = sleeps.append
    client.reverse_ip("1.2.3.4")
    assert len(session.requests) == 3
    assert len(sleeps) == 2
    assert 1 <= sleeps[0] <= 1.5 and 2 <= sleeps[1] <= 3  # exponential backoff with jitter


def test_5xx_exhausts_retries(make_client):
    client, session = make_client([FakeResponse(500, text="oops")] * 4)
    with pytest.raises(TransientError) as info:
        client.reverse_ip("1.2.3.4")
    assert "HTTP 500" in str(info.value)
    assert len(session.requests) == client_module.RETRIES + 1


def test_connect_timeout_is_retried(make_client):
    client, session = make_client(
        [requests.exceptions.ConnectTimeout("slow"), FakeResponse(200, load_fixture("reverse_ip.json"))]
    )
    client.reverse_ip("1.2.3.4")
    assert len(session.requests) == 2


def test_read_timeout_is_not_retried(make_client):
    client, session = make_client([requests.exceptions.ReadTimeout("slow")] * 4, timeout=100)
    with pytest.raises(TransientError) as info:
        client.reverse_ip("1.2.3.4")
    assert len(session.requests) == 1
    assert "100 seconds" in str(info.value) and "Not retried" in str(info.value)


def test_default_timeout_is_100_seconds(make_client):
    client, session = make_client([FakeResponse(200, load_fixture("reverse_ip.json"))])
    client.reverse_ip("1.2.3.4")
    assert session.requests[0]["timeout"] == 100


def test_connection_error_never_leaks_the_api_key(make_client):
    leaked = requests.exceptions.ConnectionError(
        "HTTPSConnectionPool: Max retries exceeded with url: /reverseip/?host=x&apikey={0}&output=json".format(API_KEY)
    )
    client, _ = make_client([leaked] * 4)
    with pytest.raises(TransientError) as info:
        client.reverse_ip("1.2.3.4")
    assert API_KEY not in str(info.value)
    assert "<redacted>" in str(info.value)


def test_proxy_password_is_scrubbed(make_client):
    leaked = requests.exceptions.ProxyError("Cannot connect to proxy http://u:s3cretpw@proxy:8080")
    client, _ = make_client([leaked] * 4, secrets=("s3cretpw",))
    with pytest.raises(TransientError) as info:
        client.reverse_ip("1.2.3.4")
    assert "s3cretpw" not in str(info.value)


def test_api_key_not_logged(make_client, caplog):
    caplog.set_level("DEBUG")
    leaked = requests.exceptions.ConnectionError("url: /x?apikey={0}".format(API_KEY))
    client, _ = make_client([leaked] * 4)
    with pytest.raises(TransientError):
        client.reverse_ip("1.2.3.4")
    assert API_KEY not in caplog.text


def test_invalid_json(make_client):
    client, _ = make_client([FakeResponse(200, text="<html>nope</html>")])
    with pytest.raises(ViewDNSError) as info:
        client.reverse_ip("1.2.3.4")
    assert "not valid JSON" in str(info.value)


def test_non_dict_json(make_client):
    client, _ = make_client([FakeResponse(200, body=[1, 2])])
    with pytest.raises(ViewDNSError):
        client.reverse_ip("1.2.3.4")


def test_in_body_error_is_invalid_input(make_client):
    client, _ = make_client([FakeResponse(200, load_fixture("reverse_ip_error.json"))])
    with pytest.raises(InvalidInputError) as info:
        client.reverse_ip("nonexistent.example")
    assert "could not find the IP address" in str(info.value)


def test_ip_history_no_records_marker_is_empty(make_client):
    client, _ = make_client([FakeResponse(200, load_fixture("ip_history_empty.json"))])
    assert client.ip_history("unknown-domain.example")["response"] == {}


def test_ip_history_other_in_body_error_raises(make_client):
    client, _ = make_client([FakeResponse(200, load_fixture("ip_history_error.json"))])
    with pytest.raises(InvalidInputError):
        client.ip_history("8.8.8.8")


def test_reverse_whois_demo_data_is_paid_plan_error(make_client):
    client, _ = make_client([FakeResponse(200, load_fixture("reverse_whois_demo.json"))])
    with pytest.raises(PaidPlanError) as info:
        client.reverse_whois("someone@example.com")
    assert "demonstration data" in str(info.value)


@pytest.mark.parametrize(
    "method, args, path, params",
    [
        ("reverse_whois", ("a@b.com",), "/reversewhois/", {"q": "a@b.com"}),
        ("reverse_ns", ("ns1.x.com",), "/reversens/", {"ns": "ns1.x.com"}),
        ("reverse_mx", ("mx.x.com",), "/reversemx/", {"mx": "mx.x.com"}),
        ("ip_history", ("x.com",), "/iphistory/", {"domain": "x.com"}),
        ("dns_record", ("x.com", "MX"), "/dnsrecord/", {"domain": "x.com", "recordtype": "MX"}),
        ("whois", ("x.com",), "/whois/v2/", {"domain": "x.com"}),
        ("subdomains", ("x.com",), "/subdomains/", {"domain": "x.com"}),
        ("account_balance", (), "/account/", {"action": "balance"}),
    ],
)
def test_endpoints(make_client, method, args, path, params):
    client, session = make_client([FakeResponse(200, {"query": {}, "response": {}})])
    getattr(client, method)(*args)
    request = session.requests[0]
    assert request["url"].endswith(path)
    for key, value in params.items():
        assert request["params"][key] == value


def test_account_api_in_body_invalid_key_is_auth_error(make_client):
    body = {"query": {"tool": "account_PRO"}, "response": {"error": "Invalid API Key Provided."}}
    client, _ = make_client([FakeResponse(200, body)])
    with pytest.raises(AuthError):
        client.account_balance()


def test_in_body_query_limit_is_quota_error(make_client):
    client, _ = make_client([FakeResponse(200, {"response": {"error": "Query limit reached for the supplied API key."}})])
    with pytest.raises(QuotaError):
        client.reverse_ip("1.2.3.4")
