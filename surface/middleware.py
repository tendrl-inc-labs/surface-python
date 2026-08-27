"""Surface middleware for scanning HTTP request/response bodies.

Provides both a FastAPI/Starlette ASGI middleware and a per-route decorator
for scanning payloads flowing between services or agents.

Usage (ASGI middleware — scans all matching routes)::

    from surface import SurfaceClient
    from surface.middleware import ScanMiddleware

    client = SurfaceClient("sfk_your_token_here")
    app.add_middleware(ScanMiddleware, client=client, reject=["Malicious"])

Usage (decorator — per-route control)::

    from surface import SurfaceClient
    from surface.middleware import scan_request

    client = SurfaceClient("sfk_your_token_here")

    @app.post("/agent/receive")
    @scan_request(client, reject=["Malicious", "Suspicious"])
    async def receive_message(request: Request):
        ...
"""

from __future__ import annotations

import functools
import logging
from typing import Any, Callable, Sequence

logger = logging.getLogger("surface.middleware")


def scan_request(
    client: Any,
    *,
    reject: str | Sequence[str] = ("Malicious",),
    label: str = "middleware-scan",
    fail_open: bool = True,
    min_size: int = 0,
    on_threat: Callable[..., None] | None = None,
    on_error: Callable[..., None] | None = None,
) -> Callable:
    """Decorator that scans incoming request bodies before the handler runs.

    Works with both sync and async handlers (FastAPI, Starlette, Flask).

    Args:
        client: SurfaceClient or AsyncSurfaceClient instance.
        reject: Threat levels to block (default: ["Malicious"]).
        label: Label for the scan in history.
        fail_open: If True (default), pass requests through when scanner is unavailable.
        min_size: Minimum body size to scan (skip smaller payloads).
        on_threat: Callback when a threat is detected. Receives (request, scan_result).
        on_error: Callback when scanning fails. Receives (request, error).
    """
    reject_levels = {reject} if isinstance(reject, str) else set(reject)

    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        async def async_wrapper(*args: Any, **kwargs: Any) -> Any:
            # Find the request object (FastAPI/Starlette pass it as first arg or kwarg)
            request = kwargs.get("request") or (args[0] if args else None)
            if request is None or not hasattr(request, "body"):
                return await func(*args, **kwargs)

            try:
                body = await request.body()
            except Exception:
                if fail_open:
                    return await func(*args, **kwargs)
                from starlette.responses import JSONResponse

                return JSONResponse(
                    {"error": "failed to read request body"}, status_code=500
                )

            if len(body) < min_size or len(body) == 0:
                return await func(*args, **kwargs)

            try:
                # Use async client if available, otherwise sync
                if hasattr(client, "scan_payload") and not hasattr(
                    client, "__aenter__"
                ):
                    result = client.scan_payload(body, label)
                else:
                    result = await client.scan_payload(body, label)
            except Exception as e:
                if on_error:
                    on_error(request, e)
                if fail_open:
                    return await func(*args, **kwargs)
                from starlette.responses import JSONResponse

                return JSONResponse(
                    {"error": "security scan unavailable"}, status_code=503
                )

            if hasattr(result, "safety_score") and result.safety_score.threat_level in reject_levels:
                if on_threat:
                    on_threat(request, result)
                from starlette.responses import JSONResponse

                return JSONResponse(
                    {
                        "error": "request blocked by security scan",
                        "threatLevel": result.safety_score.threat_level,
                        "threat": result.safety_score.primary_threat,
                    },
                    status_code=403,
                    headers={
                        "X-Surface-Scan-Id": getattr(result, "request_id", "") or ""
                    },
                )

            return await func(*args, **kwargs)

        @functools.wraps(func)
        def sync_wrapper(*args: Any, **kwargs: Any) -> Any:
            request = kwargs.get("request") or (args[0] if args else None)
            if request is None:
                return func(*args, **kwargs)

            try:
                if hasattr(request, "get_data"):
                    body = request.get_data()  # Flask
                elif hasattr(request, "data"):
                    body = request.data  # Django
                else:
                    return func(*args, **kwargs)
            except Exception:
                if fail_open:
                    return func(*args, **kwargs)
                return {"error": "failed to read request body"}, 500

            if len(body) < min_size or len(body) == 0:
                return func(*args, **kwargs)

            try:
                result = client.scan_payload(body, label)
            except Exception as e:
                if on_error:
                    on_error(request, e)
                if fail_open:
                    return func(*args, **kwargs)
                return {"error": "security scan unavailable"}, 503

            if hasattr(result, "safety_score") and result.safety_score.threat_level in reject_levels:
                if on_threat:
                    on_threat(request, result)
                return {
                    "error": "request blocked by security scan",
                    "threatLevel": result.safety_score.threat_level,
                    "threat": result.safety_score.primary_threat,
                }, 403

            return func(*args, **kwargs)

        import asyncio

        if asyncio.iscoroutinefunction(func):
            return async_wrapper
        return sync_wrapper

    return decorator


class ScanMiddleware:
    """ASGI middleware that scans request bodies for threats.

    Scans all requests matching the configured paths. Threats are blocked
    with a 403 response. Scanner failures pass through by default (fail-open).

    Usage::

        from surface import SurfaceClient
        from surface.middleware import ScanMiddleware

        client = SurfaceClient("sfk_your_token_here")
        app.add_middleware(
            ScanMiddleware,
            client=client,
            reject=["Malicious", "Suspicious"],
            paths=["/api/*", "/agent/*"],
        )
    """

    def __init__(
        self,
        app: Any,
        *,
        client: Any,
        reject: str | Sequence[str] = ("Malicious",),
        paths: Sequence[str] | None = None,
        label: str = "middleware-scan",
        fail_open: bool = True,
        min_size: int = 0,
        on_threat: Callable[..., None] | None = None,
        on_error: Callable[..., None] | None = None,
    ):
        self.app = app
        self.client = client
        self.reject_levels = {reject} if isinstance(reject, str) else set(reject)
        self.paths = paths
        self.label = label
        self.fail_open = fail_open
        self.min_size = min_size
        self.on_threat = on_threat
        self.on_error = on_error

    def _path_matches(self, path: str) -> bool:
        if not self.paths:
            return True
        for pattern in self.paths:
            if pattern.endswith("*"):
                if path.startswith(pattern[:-1]):
                    return True
            elif path == pattern:
                return True
        return False

    async def __call__(self, scope: dict, receive: Any, send: Any) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        path = scope.get("path", "")
        method = scope.get("method", "GET")

        # Only scan methods that have bodies
        if method not in ("POST", "PUT", "PATCH") or not self._path_matches(path):
            await self.app(scope, receive, send)
            return

        # Collect the request body
        body_parts: list[bytes] = []
        body_complete = False

        async def receive_wrapper() -> dict:
            nonlocal body_complete
            message = await receive()
            if message["type"] == "http.request":
                body_parts.append(message.get("body", b""))
                if not message.get("more_body", False):
                    body_complete = True
            return message

        # Buffer the body by consuming receive messages
        while not body_complete:
            await receive_wrapper()

        body = b"".join(body_parts)

        # Skip small payloads
        if len(body) < self.min_size or len(body) == 0:
            # Replay the body
            body_sent = False

            async def replay_receive() -> dict:
                nonlocal body_sent
                if not body_sent:
                    body_sent = True
                    return {"type": "http.request", "body": body, "more_body": False}
                return await receive()

            await self.app(scope, replay_receive, send)
            return

        # Scan the body
        try:
            if hasattr(self.client, "__aenter__"):
                result = await self.client.scan_payload(body, self.label)
            else:
                result = self.client.scan_payload(body, self.label)
        except Exception as e:
            if self.on_error:
                self.on_error(path, e)
            if not self.fail_open:
                await self._send_json(send, 503, {"error": "security scan unavailable"})
                return
            result = None

        # Check for threats
        if result and hasattr(result, "safety_score"):
            if result.safety_score.threat_level in self.reject_levels:
                if self.on_threat:
                    self.on_threat(path, result)
                await self._send_json(
                    send,
                    403,
                    {
                        "error": "request blocked by security scan",
                        "threatLevel": result.safety_score.threat_level,
                        "threat": result.safety_score.primary_threat,
                    },
                    headers={
                        "x-surface-scan-id": getattr(result, "request_id", "") or ""
                    },
                )
                return

        # Body is clean — replay it to the app
        body_sent = False

        async def replay_receive() -> dict:
            nonlocal body_sent
            if not body_sent:
                body_sent = True
                return {"type": "http.request", "body": body, "more_body": False}
            return await receive()

        await self.app(scope, replay_receive, send)

    @staticmethod
    async def _send_json(
        send: Any,
        status: int,
        data: dict,
        headers: dict[str, str] | None = None,
    ) -> None:
        import json

        body = json.dumps(data).encode()
        response_headers = [
            [b"content-type", b"application/json"],
            [b"content-length", str(len(body)).encode()],
        ]
        if headers:
            for k, v in headers.items():
                if v:
                    response_headers.append([k.encode(), v.encode()])

        await send(
            {
                "type": "http.response.start",
                "status": status,
                "headers": response_headers,
            }
        )
        await send({"type": "http.response.body", "body": body})
