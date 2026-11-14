"""HTTP status → error class, matched to the Surface backend's real bodies.

Quota exhaustion is 402 (not 429); ``?defer=true`` on a plan without async
scanning is also 402 but is a plan wall; 429 is always a rate limit; 403 is
never an authentication error.
"""

from __future__ import annotations

import warnings

import httpx
import pytest

from surface import (
    AsyncSurfaceClient,
    AuthenticationError,
    PermissionDeniedError,
    PlanRequiredError,
    QuotaExceededError,
    RateLimitError,
    SurfaceClient,
    SurfaceError,
)

from test_client import SCAN_RESPONSE


def _client(status: int, body: dict, seen: list | None = None) -> SurfaceClient:
    def handler(request: httpx.Request) -> httpx.Response:
        if seen is not None:
            seen.append(request)
        return httpx.Response(status, json=body)

    c = SurfaceClient(api_key="sfk_test")
    c._client = httpx.Client(base_url=c.base_url, transport=httpx.MockTransport(handler))
    return c


QUOTA_402 = {"error": "monthly scan quota exceeded (100/100 scans used)", "requestId": "r1"}
DEFER_402 = {
    "error": "async scanning is not included on the free plan",
    "feature": "async scanning",
    "current_plan": "free",
    "upgrade": True,
    "requestId": "r2",
}
PLAN_403 = {
    "error": "the free plan includes 1 scan profile(s); this account has 1",
    "feature": "scan profiles",
    "current_plan": "free",
    "code": "plan_required",
    "limit": 1,
    "upgrade": True,
}


def test_402_quota_is_quota_exceeded():
    with pytest.raises(QuotaExceededError) as ei:
        _client(402, QUOTA_402).scan_payload("hi")
    e = ei.value
    assert e.status_code == 402
    assert e.message == QUOTA_402["error"]
    assert e.request_id == "r1"
    assert not isinstance(e, PermissionDeniedError)


def test_402_local_scanner_quota_is_quota_exceeded():
    body = {"error": "this plan's 500 local scans for the month are used up"}
    with pytest.raises(QuotaExceededError):
        _client(402, body).scan_payload("hi")


def test_402_defer_without_async_is_plan_required_not_quota():
    with pytest.raises(PlanRequiredError) as ei:
        _client(402, DEFER_402).scan_file(b"x", defer_scan=True)
    e = ei.value
    assert not isinstance(e, QuotaExceededError)
    assert e.status_code == 402
    assert e.feature == "async scanning"
    assert e.current_plan == "free"
    assert e.code is None  # the server sends no code on this one


def test_402_other_is_generic():
    with pytest.raises(SurfaceError) as ei:
        _client(402, {"error": "could not verify this API key with the server"}).scan_payload("hi")
    assert type(ei.value) is SurfaceError
    assert ei.value.status_code == 402


def test_403_plan_required():
    with pytest.raises(PlanRequiredError) as ei:
        _client(403, PLAN_403).get_usage()
    e = ei.value
    assert isinstance(e, PermissionDeniedError)
    assert e.status_code == 403
    assert e.code == "plan_required"
    assert e.feature == "scan profiles"
    assert e.message == PLAN_403["error"]


@pytest.mark.parametrize(
    "msg",
    [
        "IP address is blocked",
        "permission denied: scans:write required",
        "Payload scanning is not enabled for this scan profile. Update the profile or use an API key linked to a profile with payload scanning enabled.",
    ],
)
def test_403_is_permission_denied_not_auth(msg):
    with pytest.raises(PermissionDeniedError) as ei:
        _client(403, {"error": msg}).scan_payload("hi")
    e = ei.value
    assert type(e) is PermissionDeniedError
    assert not isinstance(e, AuthenticationError)
    assert e.message == msg
    assert e.status_code == 403
    assert e.code is None


def test_401_stays_authentication():
    with pytest.raises(AuthenticationError) as ei:
        _client(401, {"error": "invalid API key"}).scan_payload("hi")
    assert ei.value.status_code == 401


@pytest.mark.parametrize(
    "body",
    [
        {"error": "rate limit exceeded", "plan": "free", "limit_per_minute": 10},
        {"error": "rate limit exceeded", "retry_after": "60"},
        # Even a 429 that mentions quota is a rate limit: quota is 402.
        {"error": "quota-ish wording"},
    ],
)
def test_429_is_rate_limit(body):
    with pytest.raises(RateLimitError) as ei:
        _client(429, body).scan_payload("hi")
    assert not isinstance(ei.value, QuotaExceededError)
    assert ei.value.status_code == 429


def test_quota_default_status_is_402():
    assert QuotaExceededError().status_code == 402


def test_scan_payload_defer_is_deprecated_and_not_sent():
    seen: list[httpx.Request] = []
    c = _client(200, SCAN_RESPONSE, seen)
    with pytest.warns(DeprecationWarning, match="no effect"):
        c.scan_payload("hi", defer_scan=True)
    assert "defer" not in seen[0].url.query.decode()


def test_scan_payload_without_defer_does_not_warn():
    c = _client(200, SCAN_RESPONSE)
    with warnings.catch_warnings():
        warnings.simplefilter("error")
        c.scan_payload("hi")


async def test_async_mapping_and_defer_warning():
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        if request.url.path.endswith("/scan/payload") and len(seen) == 1:
            return httpx.Response(200, json=SCAN_RESPONSE)
        return httpx.Response(403, json=PLAN_403)

    c = AsyncSurfaceClient(api_key="sfk_test")
    c._client = httpx.AsyncClient(base_url=c.base_url, transport=httpx.MockTransport(handler))
    with pytest.warns(DeprecationWarning):
        await c.scan_payload("hi", defer_scan=True)
    assert "defer" not in seen[0].url.query.decode()
    with pytest.raises(PlanRequiredError):
        await c.scan_payload("hi")
