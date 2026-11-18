#!/usr/bin/env python3
"""Live smoke test of the ViewDNS client and parsers against the real API. NOT shipped in the add-on package.

    VIEWDNS_API_KEY=... python tests/smoke/smoke_test.py [--include-paid] [--include-live]

(VIEWDNS_API_KEY can also be set in the repo's .env file.)

Hard budget: 30 HTTP calls (enforced; the test aborts rather than exceed it). The default run makes 20 calls, of
which 16 consume queries (the Account API and requests rejected for invalid input or a bad key are free).
--include-paid adds Reverse WHOIS (paid keys only, 1 call); --include-live adds the 7 live checks (port scan, ping,
traceroute, HTTP headers, DNS propagation, China and Iran firewall tests), which make ViewDNS contact the target.

The API key is read only from the environment and is never printed; the test also asserts it never appears in any
error message.
"""

import argparse
import os
import sys
import time
import traceback

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(ROOT, "package", "bin"))

import requests  # noqa: E402

from ta_viewdns.account import summarize_balance  # noqa: E402
from ta_viewdns.actions import ACTIONS  # noqa: E402
from ta_viewdns.client import AuthError, InvalidInputError, ViewDNSClient, ViewDNSError  # noqa: E402

MAX_CALLS = 30


class BudgetSession(requests.Session):
    """A requests session that refuses to make more than MAX_CALLS calls."""

    def __init__(self, counter):
        super(BudgetSession, self).__init__()
        self.counter = counter

    def request(self, *args, **kwargs):
        if self.counter["calls"] >= MAX_CALLS:
            raise RuntimeError("smoke test call budget ({0}) exhausted".format(MAX_CALLS))
        self.counter["calls"] += 1
        return super(BudgetSession, self).request(*args, **kwargs)


class Smoke(object):
    def __init__(self, api_key, base_url):
        self.api_key = api_key
        self.counter = {"calls": 0}
        self.client = ViewDNSClient(api_key, base_url=base_url, timeout=100, session=BudgetSession(self.counter))
        self.bad_client = ViewDNSClient(
            "invalid-key-for-smoke-test", base_url=base_url, timeout=60, session=BudgetSession(self.counter)
        )
        self.passed = []
        self.failed = []

    def check(self, name, function):
        started = time.time()
        try:
            detail = function()
        except Exception as error:  # report and continue
            message = str(error)
            assert self.api_key not in message, "API key leaked into an error message"
            self.failed.append(name)
            print("FAIL  {0:<38} {1}".format(name, message[:200]))
            if os.environ.get("SMOKE_DEBUG"):
                traceback.print_exc()
            return
        self.passed.append(name)
        print("ok    {0:<38} {1} ({2:.1f}s)".format(name, detail or "", time.time() - started))

    def lookup(self, action, query, recordtype="ANY", expect_rows=True):
        query, error = ACTIONS[action].validate(query)
        assert query is not None, error
        result = ACTIONS[action].run(self.client, query, recordtype)
        assert result.total_count >= len(result.rows), "total_count below row count"
        if expect_rows:
            assert result.rows, "expected results, got none"
            for row in result.rows:
                assert set(row) <= set(ACTIONS[action].fields), "unexpected fields {0}".format(set(row) - set(ACTIONS[action].fields))
        return "{0} rows of {1}".format(len(result.rows), result.total_count)


def read_env_file():
    """Values from the repo's git-ignored .env, used when VIEWDNS_API_KEY isn't in the environment."""
    values = {}
    path = os.path.join(ROOT, ".env")
    if os.path.isfile(path):
        with open(path) as handle:
            for line in handle:
                if "=" in line and not line.lstrip().startswith("#"):
                    key, _, value = line.strip().partition("=")
                    values[key.strip()] = value.strip().strip('"').strip("'")
    return values


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--include-paid", action="store_true", help="also run Reverse WHOIS (paid keys only)")
    parser.add_argument("--include-live", action="store_true", help="also run the 7 live checks")
    parser.add_argument("--base-url", default=os.environ.get("VIEWDNS_BASE_URL", "https://api.viewdns.info"))
    args = parser.parse_args()
    api_key = os.environ.get("VIEWDNS_API_KEY", "").strip() or read_env_file().get("VIEWDNS_API_KEY", "").strip()
    if not api_key:
        print("Set VIEWDNS_API_KEY (for example in .env) to run the live smoke test.", file=sys.stderr)
        return 2

    smoke = Smoke(api_key, args.base_url)
    c = smoke.client

    def balance():
        summary = summarize_balance(c.account_balance())
        assert summary["plan"] in ("monthly", "trial")
        return "plan={plan} remaining={monthly_remaining} prepaid={prepaid_balance}".format(**summary)

    smoke.check("account balance (free)", balance)
    smoke.check("reverseip ip", lambda: smoke.lookup("reverseip", "8.8.8.8"))
    smoke.check("iphistory", lambda: smoke.lookup("iphistory", "viewdns.info"))
    smoke.check("dnsrecord ANY", lambda: smoke.lookup("dnsrecord", "viewdns.info", "ANY"))
    smoke.check("whois domain", lambda: smoke.lookup("whois", "viewdns.info"))
    smoke.check("whois ip", lambda: smoke.lookup("whois", "1.1.1.1"))
    smoke.check("reversens", lambda: smoke.lookup("reversens", "ns1.google.com"))
    smoke.check("reversemx", lambda: smoke.lookup("reversemx", "aspmx.l.google.com"))
    smoke.check("subdomains", lambda: smoke.lookup("subdomains", "viewdns.info"))
    smoke.check("abuselookup", lambda: smoke.lookup("abuselookup", "viewdns.info"))
    smoke.check("freeemail", lambda: smoke.lookup("freeemail", "someone@gmail.com"))
    smoke.check("iplocation", lambda: smoke.lookup("iplocation", "8.8.8.8"))
    smoke.check("reversedns", lambda: smoke.lookup("reversedns", "8.8.8.8"))
    smoke.check("maclookup", lambda: smoke.lookup("maclookup", "00-05-02-34-56-78"))
    smoke.check("dnssec", lambda: smoke.lookup("dnssec", "viewdns.info"))
    smoke.check("spamdblookup", lambda: smoke.lookup("spamdblookup", "8.8.8.8"))
    if args.include_live:
        smoke.check("portscan (live)", lambda: smoke.lookup("portscan", "viewdns.info"))
        smoke.check("ping (live)", lambda: smoke.lookup("ping", "viewdns.info"))
        smoke.check("traceroute (live)", lambda: smoke.lookup("traceroute", "viewdns.info"))
        smoke.check("httpheaders (live)", lambda: smoke.lookup("httpheaders", "viewdns.info"))
        smoke.check("propagation (live)", lambda: smoke.lookup("propagation", "viewdns.info"))
        smoke.check("chinesefirewall (live)", lambda: smoke.lookup("chinesefirewall", "viewdns.info"))
        smoke.check("iranfirewall (live)", lambda: smoke.lookup("iranfirewall", "https://viewdns.info"))
    if args.include_paid:
        smoke.check("reversewhois", lambda: smoke.lookup("reversewhois", "domains@viewdns.info", expect_rows=False))

    def no_history():
        result = ACTIONS["iphistory"].run(c, "this-domain-should-not-exist-viewdns-smoke.com")
        assert result.status == "no_results", result.status
        return "no_results as expected"

    smoke.check("iphistory unknown domain", no_history)

    def invalid_input():
        try:
            c.dns_record("not a domain!", "A")
        except InvalidInputError as error:
            return "InvalidInputError: {0}".format(error)
        raise AssertionError("expected InvalidInputError")

    smoke.check("invalid input -> 400", invalid_input)

    def bad_key():
        try:
            smoke.bad_client.reverse_ip("8.8.8.8")
        except AuthError:
            pass
        else:
            raise AssertionError("expected AuthError from a lookup")
        try:
            smoke.bad_client.account_balance()
        except AuthError:
            return "AuthError from lookup (401) and account (200 + body)"
        raise AssertionError("expected AuthError from the account API")

    smoke.check("bad key -> AuthError", bad_key)

    print("\n{0} passed, {1} failed, {2} HTTP calls (budget {3})".format(
        len(smoke.passed), len(smoke.failed), smoke.counter["calls"], MAX_CALLS))
    return 1 if smoke.failed else 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except ViewDNSError as error:
        print("ERROR: {0}".format(error), file=sys.stderr)
        sys.exit(1)
