"""Scanner unavailable: one error type, a per-call timeout budget, short retries.

Every test runs against a local fake HTTP server (no network). Backoff waits
are shrunk via ``surface.client._BACKOFF`` so the suite stays fast.
"""

from __future__ import annotations

import json
import socket
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import httpx
import pytest

import surface.client as client_mod
from surface import (
    AsyncSurfaceClient,
    AsyncToolGuard,
    RateLimitError,
    SurfaceClient,
    SurfaceError,
    SurfaceUnavailableError,
    ToolGuard,
)
from surface.middleware import ScanMiddleware

SCAN_RESPONSE = {
    "name": "t.json",
    "size": 1,
    "hash": "sha256:x",
    "contentType": "application/json",
    "safetyScore": {
        "score": 100,
        "threatLevel": "Clean",
        "confidence": "High",
        "confidenceScore": 0.9,
        "confidenceReason": "",
        "primaryThreat": "No threats detected",
        "threatSummary": "",
        "enginesUsed": [],
        "recommendedAction": "Allow",
    },
    "scanTimeMs": 1,
    "timestamp": 0,
}

OK = (200, {"Content-Type": "application/json"}, json.dumps(SCAN_RESPONSE))
HTML = (502, {"Content-Type": "text/html"}, "<html><body>502 Bad Gateway</body></html>")


def _err(status: int, msg: str, headers: dict | None = None):
    return (status, {"Content-Type": "application/json", **(headers or {})}, json.dumps({"error": msg}))


HANG = "hang"


class FakeSurface:
    """Serves a script of responses in order; the last one repeats."""

    def __init__(self, *script):
        self.script = list(script)
        self.requests: list[tuple[str, str, bytes]] = []
        self.release = threading.Event()
        fake = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def _serve(self):
                length = int(self.headers.get("Content-Length") or 0)
                body = self.rfile.read(length) if length else b""
                fake.requests.append((self.command, self.path, body))
                step = fake.script[min(len(fake.requests) - 1, len(fake.script) - 1)]
                if step == HANG:
                    fake.release.wait(10)
                    return
                status, headers, text = step
                data = text.encode()
                self.send_response(status)
                for k, v in headers.items():
                    self.send_header(k, v)
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            do_GET = do_POST = _serve

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.server.daemon_threads = True
        self.url = f"http://127.0.0.1:{self.server.server_address[1]}"
        threading.Thread(target=self.server.serve_forever, args=(0.02,), daemon=True).start()

    def close(self):
        self.release.set()
        self.server.shutdown()
        self.server.server_close()


@pytest.fixture
def fake():
    servers: list[FakeSurface] = []

    def make(*script):
        s = FakeSurface(*script)
        servers.append(s)
        return s

    yield make
    for s in servers:
        s.close()


@pytest.fixture(autouse=True)
def fast_backoff(monkeypatch):
    monkeypatch.setattr(client_mod, "_BACKOFF", (0.02, 0.04))


def _client(server: FakeSurface, **kw) -> SurfaceClient:
    return SurfaceClient(api_key="sfk_test", base_url=server.url, **kw)


def _refused_url() -> str:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return f"http://127.0.0.1:{port}"


def test_worktree_code_under_test():
    assert "site-packages" not in client_mod.__file__


def test_default_timeout_is_60s():
    assert SurfaceClient(api_key="sfk_test").timeout == 60.0
    assert AsyncSurfaceClient(api_key="sfk_test").timeout == 60.0
    assert SurfaceClient(mode="local").timeout == 60.0
    assert SurfaceClient(api_key="sfk_test", timeout=5).timeout == 5


def test_unavailable_is_a_surface_error():
    assert issubclass(SurfaceUnavailableError, SurfaceError)


def test_connection_refused_raises_unavailable_within_budget():
    c = SurfaceClient(api_key="sfk_test", base_url=_refused_url(), timeout=0.5)
    start = time.monotonic()
    with pytest.raises(SurfaceUnavailableError) as ei:
        c.scan_payload("hello")
    assert time.monotonic() - start < 1.5
    assert ei.value.status_code == 0
    assert isinstance(ei.value.__cause__, httpx.TransportError)


def test_500_is_unavailable_and_not_retried(fake):
    s = fake(_err(500, "engine crashed"))
    with pytest.raises(SurfaceUnavailableError) as ei:
        _client(s).scan_payload("hello")
    assert ei.value.status_code == 500
    assert "engine crashed" in ei.value.message
    assert len(s.requests) == 1


@pytest.mark.parametrize("status", [502, 503, 504])
def test_transient_status_then_success_retries(fake, status):
    s = fake(_err(status, "warming up"), OK)
    result = _client(s).scan_payload("hello")
    assert result.safety_score.recommended_action == "Allow"
    assert len(s.requests) == 2
    assert s.requests[0][2] == s.requests[1][2]  # same body re-sent


def test_503_forever_gives_up_within_budget(fake):
    s = fake(_err(503, "warming up"))
    start = time.monotonic()
    with pytest.raises(SurfaceUnavailableError) as ei:
        _client(s, timeout=0.5).scan_payload("hello")
    assert time.monotonic() - start < 0.5 + 0.3
    assert ei.value.status_code == 503
    assert "warming up" in ei.value.message
    assert len(s.requests) > 2


def test_at_most_ten_retries(fake, monkeypatch):
    monkeypatch.setattr(client_mod, "_BACKOFF", (0.001,))
    s = fake(_err(503, "warming up"))
    with pytest.raises(SurfaceUnavailableError):
        _client(s, timeout=10).scan_payload("hello")
    assert len(s.requests) == 11


def test_retry_after_is_honored(fake):
    s = fake(_err(503, "warming up", {"Retry-After": "1"}), OK)
    start = time.monotonic()
    _client(s, timeout=5).scan_payload("hello")
    assert time.monotonic() - start >= 1.0
    assert len(s.requests) == 2


def test_retry_after_past_budget_gives_up_now(fake):
    s = fake(_err(503, "warming up", {"Retry-After": "5"}), OK)
    start = time.monotonic()
    with pytest.raises(SurfaceUnavailableError):
        _client(s, timeout=2).scan_payload("hello")
    assert time.monotonic() - start < 1.0
    assert len(s.requests) == 1


def test_retry_after_is_capped_at_10s():
    resp = httpx.Response(503, headers={"Retry-After": "120"})
    assert client_mod._retry_wait(resp, 0) == 10.0
    assert client_mod._retry_wait(httpx.Response(503), 0) == client_mod._BACKOFF[0]


def test_hang_raises_unavailable_at_timeout(fake):
    s = fake(HANG)
    start = time.monotonic()
    with pytest.raises(SurfaceUnavailableError) as ei:
        _client(s, timeout=0.3).scan_payload("hello")
    assert time.monotonic() - start < 1.0
    assert ei.value.status_code == 0
    assert len(s.requests) == 1  # a hung request spends the budget; no retry


def test_html_body_on_success_status_is_unavailable(fake):
    s = fake((200, {"Content-Type": "text/html"}, "<html>Login</html>"))
    with pytest.raises(SurfaceUnavailableError) as ei:
        _client(s).scan_payload("hello")
    assert ei.value.status_code == 200


def test_html_proxy_error_page_is_unavailable(fake):
    s = fake(HTML)
    with pytest.raises(SurfaceUnavailableError) as ei:
        _client(s, timeout=0.3).scan_payload("hello")
    assert ei.value.status_code == 502


def test_json_with_wrong_shape_is_unavailable(fake):
    s = fake((200, {"Content-Type": "application/json"}, json.dumps({"hello": "world"})))
    with pytest.raises(SurfaceUnavailableError):
        _client(s).scan_payload("hello")


def test_429_unchanged_and_not_retried(fake):
    s = fake(_err(429, "slow down", {"Retry-After": "1"}))
    with pytest.raises(RateLimitError) as ei:
        _client(s).scan_payload("hello")
    assert not isinstance(ei.value, SurfaceUnavailableError)
    assert len(s.requests) == 1


def test_multipart_upload_rebuilt_on_retry(fake):
    s = fake(_err(503, "warming up"), OK)
    _client(s).scan_file(b"FILE-CONTENT-123")
    assert len(s.requests) == 2
    assert all(b"FILE-CONTENT-123" in body for _, _, body in s.requests)


def test_local_mode_retries_too(fake):
    s = fake(_err(503, "warming up"), OK)
    c = SurfaceClient(mode="local", scanner_url=s.url)
    c.scan_payload("hello")
    assert len(s.requests) == 2


def test_non_scan_calls_share_the_budget(fake):
    s = fake(_err(503, "warming up"), (200, {"Content-Type": "application/json"}, '{"status": "pending"}'))
    assert _client(s).get_scan("abc") == {"status": "pending"}
    assert len(s.requests) == 2


def test_dns_failure_is_not_retryable():
    try:
        raise socket.gaierror(8, "nodename nor servname provided")
    except socket.gaierror as cause:
        err = httpx.ConnectError("dns")
        err.__cause__ = cause
    assert not client_mod._retryable_transport_error(err)
    assert client_mod._retryable_transport_error(httpx.ConnectError("refused"))
    assert not client_mod._retryable_transport_error(httpx.ReadTimeout("slow"))


# --- async -------------------------------------------------------------------


async def test_async_503_then_success(fake):
    s = fake(_err(503, "warming up"), OK)
    async with AsyncSurfaceClient(api_key="sfk_test", base_url=s.url) as c:
        result = await c.scan_file(b"FILE")
    assert result.safety_score.recommended_action == "Allow"
    assert len(s.requests) == 2


async def test_async_hang_raises_unavailable(fake):
    s = fake(HANG)
    start = time.monotonic()
    async with AsyncSurfaceClient(api_key="sfk_test", base_url=s.url, timeout=0.3) as c:
        with pytest.raises(SurfaceUnavailableError):
            await c.scan_payload("hello")
    assert time.monotonic() - start < 1.0


async def test_async_refused_and_html(fake):
    async with AsyncSurfaceClient(api_key="sfk_test", base_url=_refused_url(), timeout=0.3) as c:
        with pytest.raises(SurfaceUnavailableError):
            await c.scan_payload("hello")
    s = fake((200, {"Content-Type": "text/html"}, "<html></html>"))
    async with AsyncSurfaceClient(api_key="sfk_test", base_url=s.url) as c:
        with pytest.raises(SurfaceUnavailableError):
            await c.scan_payload("hello")


async def test_async_429_unchanged(fake):
    s = fake(_err(429, "slow down"))
    async with AsyncSurfaceClient(api_key="sfk_test", base_url=s.url) as c:
        with pytest.raises(RateLimitError):
            await c.scan_payload("hello")
    assert len(s.requests) == 1


# --- guard and middleware ----------------------------------------------------


def test_tool_guard_fails_closed_on_unavailable(fake):
    s = fake(_err(503, "warming up"))
    ran = []
    guard = ToolGuard(_client(s, timeout=0.3))
    tool = guard.wrap(lambda to: ran.append(to), name="send_email")
    with pytest.raises(SurfaceUnavailableError):
        tool(to="a@b.com")
    assert ran == []


async def test_async_tool_guard_fails_closed_on_unavailable():
    ran = []

    async def send_email(to):
        ran.append(to)

    c = AsyncSurfaceClient(api_key="sfk_test", base_url=_refused_url(), timeout=0.3)
    tool = AsyncToolGuard(c).wrap(send_email)
    with pytest.raises(SurfaceUnavailableError):
        await tool(to="a@b.com")
    assert ran == []
    await c.close()


async def _call_asgi(mw) -> int:
    sent: list[dict] = []
    messages = [{"type": "http.request", "body": b'{"x": 1}', "more_body": False}]

    async def receive():
        return messages.pop(0) if messages else {"type": "http.disconnect"}

    async def send(msg):
        sent.append(msg)

    await mw({"type": "http", "path": "/api/x", "method": "POST", "headers": []}, receive, send)
    return next(m["status"] for m in sent if m["type"] == "http.response.start")


@pytest.mark.parametrize("fail_open,expected", [(True, 200), (False, 503)])
async def test_middleware_follows_fail_open(fail_open, expected):
    async def app(scope, receive, send):
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b"ok"})

    errors = []
    c = AsyncSurfaceClient(api_key="sfk_test", base_url=_refused_url(), timeout=0.3)
    mw = ScanMiddleware(app, client=c, fail_open=fail_open, on_error=lambda p, e: errors.append(e))
    assert await _call_asgi(mw) == expected
    assert isinstance(errors[0], SurfaceUnavailableError)
    await c.close()
