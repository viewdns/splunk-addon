import json
import os
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "package", "bin"))
FIXTURES = os.path.join(ROOT, "tests", "fixtures")

API_KEY = "test-api-key-0123456789"


def load_fixture(name):
    with open(os.path.join(FIXTURES, name)) as handle:
        return json.load(handle)


class FakeResponse(object):
    def __init__(self, status_code=200, body=None, text=None):
        self.status_code = status_code
        self._body = body
        self.text = text if text is not None else json.dumps(body)

    def json(self):
        if self._body is None:
            return json.loads(self.text)
        return self._body


class FakeSession(object):
    """Replays queued responses (or exceptions) and records every request."""

    def __init__(self, responses=None, route=None):
        self.responses = list(responses or [])
        self.route = route  # optional callable(path, params) -> FakeResponse
        self.requests = []
        self.headers = {}

    def get(self, url, params=None, timeout=None, proxies=None):
        self.requests.append({"url": url, "params": dict(params or {}), "timeout": timeout, "proxies": proxies})
        if self.route is not None:
            result = self.route(url, params)
        else:
            result = self.responses.pop(0)
        if isinstance(result, Exception):
            raise result
        return result


@pytest.fixture
def fixture():
    return load_fixture


@pytest.fixture
def make_client():
    from ta_viewdns.client import ViewDNSClient

    def factory(responses=None, route=None, **kwargs):
        session = FakeSession(responses, route)
        client = ViewDNSClient(API_KEY, session=session, sleep=lambda seconds: None, **kwargs)
        return client, session

    return factory
