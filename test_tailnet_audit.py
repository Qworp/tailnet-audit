from datetime import datetime, timezone

import pytest
import requests

from tailnet_audit import TailscaleAPIError, TailscaleClient, audit_devices, parse_ts

NOW = datetime(2026, 10, 12, 12, 0, tzinfo=timezone.utc)


class FakeResponse:
    def __init__(self, status_code, payload=None, headers=None):
        self.status_code = status_code
        self._payload = payload or {}
        self.headers = headers or {}
        self.text = str(payload)

    @property
    def ok(self):
        return 200 <= self.status_code < 300

    def json(self):
        return self._payload


class FakeSession:
    def __init__(self, responses):
        self.responses = list(responses)
        self.calls = []

    def get(self, url, headers=None, params=None, timeout=None):
        self.calls.append({"url": url, "headers": headers, "params": params})
        return self.responses.pop(0)


def make_client(responses, sleeps=None):
    session = FakeSession(responses)
    recorder = sleeps if sleeps is not None else []
    client = TailscaleClient("tskey-test", session=session, sleep=recorder.append)
    return client, session


def test_list_devices_sends_auth_and_parses():
    client, session = make_client([FakeResponse(200, {"devices": [{"name": "a"}]})])
    assert client.list_devices() == [{"name": "a"}]
    call = session.calls[0]
    assert call["url"].endswith("/tailnet/-/devices")
    assert call["headers"]["Authorization"] == "Bearer tskey-test"


def test_retries_on_rate_limit_using_retry_after():
    sleeps = []
    client, _ = make_client(
        [FakeResponse(429, headers={"Retry-After": "3"}), FakeResponse(200, {"devices": []})], sleeps
    )
    assert client.list_devices() == []
    assert sleeps == [3.0]


def test_retries_on_server_error_then_gives_up():
    sleeps = []
    client, _ = make_client([FakeResponse(503)] * 4, sleeps)
    with pytest.raises(TailscaleAPIError):
        client.list_devices()
    assert sleeps == [1.0, 2.0, 4.0]


def test_auth_failure_is_not_retried():
    client, session = make_client([FakeResponse(401)])
    with pytest.raises(TailscaleAPIError, match="Authentication failed"):
        client.list_devices()
    assert len(session.calls) == 1


def test_connection_error_retries():
    class FlakySession(FakeSession):
        def get(self, *a, **kw):
            if not self.calls:
                self.calls.append("fail")
                raise requests.ConnectionError("boom")
            return FakeResponse(200, {"devices": [{"name": "b"}]})

    client = TailscaleClient("k", session=FlakySession([]), sleep=lambda s: None)
    assert client.list_devices() == [{"name": "b"}]


def test_missing_key_raises():
    with pytest.raises(ValueError):
        TailscaleClient("")


def test_parse_ts_handles_zero_and_bad_values():
    assert parse_ts("0001-01-01T00:00:00Z") is None
    assert parse_ts("") is None
    assert parse_ts("not-a-date") is None
    assert parse_ts("2026-10-01T00:00:00Z") == datetime(2026, 10, 1, tzinfo=timezone.utc)


def test_audit_flags_each_issue_type():
    devices = [
        {"name": "expired", "expires": "2026-10-01T00:00:00Z", "lastSeen": "2026-10-12T00:00:00Z"},
        {"name": "expiring", "expires": "2026-10-20T12:00:00Z", "lastSeen": "2026-10-12T00:00:00Z"},
        {"name": "no-expiry", "keyExpiryDisabled": True, "expires": "2026-01-01T00:00:00Z"},
        {"name": "stale", "lastSeen": "2026-08-01T00:00:00Z"},
        {"name": "old-client", "updateAvailable": True, "clientVersion": "1.60.0"},
        {"name": "pending", "authorized": False},
        {"name": "healthy", "expires": "2027-04-01T00:00:00Z", "lastSeen": "2026-10-12T11:00:00Z",
         "authorized": True},
    ]
    findings = audit_devices(devices, NOW)
    issues = {(f.device, f.issue) for f in findings}
    assert issues == {
        ("expired", "key_expired"),
        ("expiring", "key_expiring"),
        ("stale", "stale"),
        ("old-client", "update_available"),
        ("pending", "unauthorized"),
    }
    assert findings[0].severity == "high"
