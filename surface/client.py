"""Surface API client."""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import os
import socket
import time
from pathlib import Path
from typing import IO, Any, TypeVar, Union

import httpx
import pydantic

from .decorator import MaliciousFileError
from .errors import (
    AuthenticationError,
    NotFoundError,
    QuotaExceededError,
    RateLimitError,
    SurfaceError,
    SurfaceUnavailableError,
    ValidationError,
)
from .models import (
    STRICTNESS_LEVELS,
    ActionContext,
    DeferredScanResponse,
    ScanHistoryPage,
    ScanResult,
    Usage,
    parse_action_context,
)

FileInput = Union[str, Path, bytes, IO[bytes]]


_DEFAULT_BASE_URL = "https://app.tendrl.com/surface/api"


def _resolve_base_url(base_url: str | None) -> str:
    return (base_url or os.environ.get("SURFACE_BASE_URL") or _DEFAULT_BASE_URL).rstrip("/")


def _resolve_api_key(api_key: str | None, *, required: bool = True) -> str | None:
    """Resolve the hosted-API key.

    ``required=False`` for mode="local": the local scanner is unauthenticated,
    so a key is only needed if the caller later touches a hosted endpoint.
    """
    resolved = api_key or os.environ.get("SURFACE_KEY")
    if not resolved and required:
        raise AuthenticationError(
            "No API key provided. Pass api_key or set the SURFACE_KEY environment variable."
        )
    return resolved


def _context_body(context: ActionContext | dict | None, strictness: str | None) -> dict | None:
    """The request's context: the caller's, with the client's strictness filling a gap."""
    parsed = parse_action_context(context) if context is not None else None
    body = parsed.model_dump(exclude_none=True) if isinstance(parsed, ActionContext) else {}
    if strictness and "strictness" not in body:
        body["strictness"] = strictness
    return body or None


def _prepare_file(file: FileInput) -> tuple[str, bytes]:
    """Return (filename, content) from various input types."""
    if isinstance(file, (str, Path)):
        p = Path(file)
        return p.name, p.read_bytes()
    if isinstance(file, bytes):
        return "upload", file
    # file-like object
    name = getattr(file, "name", "upload")
    if isinstance(name, (str, Path)):
        name = Path(name).name
    return str(name), file.read()


# One budget per SDK call, covering every attempt and every wait between them.
DEFAULT_TIMEOUT = 60.0
# 500 is a real failure (no retry); 502/503/504 are a restarting or overloaded
# scanner — every hosted deploy answers 503 for ~45 s while it warms up.
_UNAVAILABLE_STATUSES = frozenset({500, 502, 503, 504})
_RETRY_STATUSES = frozenset({502, 503, 504})
_MAX_RETRIES = 10
_MAX_RETRY_WAIT = 10.0
# Waits without a Retry-After header; the last one repeats. Tests shrink this.
_BACKOFF = (1.0, 2.0, 4.0, 8.0)


def _retry_after(resp: httpx.Response | None) -> float | None:
    """The response's Retry-After in seconds, capped; None if absent or a date."""
    raw = resp.headers.get("retry-after") if resp is not None else None
    try:
        secs = float(raw) if raw else None
    except ValueError:
        return None
    if secs is None or secs < 0:
        return None
    return min(secs, _MAX_RETRY_WAIT)


def _retry_wait(resp: httpx.Response | None, attempt: int) -> float:
    after = _retry_after(resp)
    if after is not None:
        return after
    return _BACKOFF[min(attempt, len(_BACKOFF) - 1)]


def _retryable_transport_error(exc: httpx.TransportError) -> bool:
    """Refused or reset connections retry; DNS failures and timeouts don't."""
    if isinstance(exc, httpx.ConnectError):
        cause: BaseException | None = exc
        while cause is not None:
            if isinstance(cause, socket.gaierror):
                return False
            cause = cause.__cause__ or cause.__context__
        return True
    return isinstance(exc, (httpx.RemoteProtocolError, httpx.ReadError, httpx.WriteError))


def _timed_out(budget: float) -> SurfaceUnavailableError:
    return SurfaceUnavailableError(f"Surface did not answer within {budget:g}s")


def _unreachable(exc: httpx.TransportError) -> SurfaceUnavailableError:
    return SurfaceUnavailableError(f"Surface is unreachable: {exc or type(exc).__name__}")


def _send(http: httpx.Client, budget: float, method: str, url: str, **kw: Any) -> httpx.Response:
    """Send one SDK call's request, retrying transient unavailability within ``budget``.

    Returns the final response (which may still be an error for
    _raise_for_status to classify). Request bodies are rebuilt from ``kw`` on
    every attempt, so multipart uploads retry intact.
    """
    deadline = time.monotonic() + budget
    last: httpx.Response | None = None
    for attempt in range(_MAX_RETRIES + 1):
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            break
        try:
            last = http.request(method, url, timeout=remaining, **kw)
        except httpx.TimeoutException as e:
            # The budget is spent; report the last 5xx seen if there was one.
            if last is not None:
                return last
            raise _timed_out(budget) from e
        except httpx.TransportError as e:
            if attempt >= _MAX_RETRIES or not _retryable_transport_error(e):
                raise _unreachable(e) from e
            wait = _retry_wait(None, attempt)
            # Never start a wait that would end past the budget.
            if time.monotonic() + wait >= deadline:
                raise _unreachable(e) from e
        else:
            if attempt >= _MAX_RETRIES or last.status_code not in _RETRY_STATUSES:
                return last
            wait = _retry_wait(last, attempt)
            if time.monotonic() + wait >= deadline:
                return last
        time.sleep(wait)
    if last is not None:
        return last
    raise _timed_out(budget)


async def _asend(
    http: httpx.AsyncClient, budget: float, method: str, url: str, **kw: Any
) -> httpx.Response:
    """Async twin of :func:`_send`."""
    deadline = time.monotonic() + budget
    last: httpx.Response | None = None
    for attempt in range(_MAX_RETRIES + 1):
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            break
        try:
            last = await http.request(method, url, timeout=remaining, **kw)
        except httpx.TimeoutException as e:
            if last is not None:
                return last
            raise _timed_out(budget) from e
        except httpx.TransportError as e:
            if attempt >= _MAX_RETRIES or not _retryable_transport_error(e):
                raise _unreachable(e) from e
            wait = _retry_wait(None, attempt)
            if time.monotonic() + wait >= deadline:
                raise _unreachable(e) from e
        else:
            if attempt >= _MAX_RETRIES or last.status_code not in _RETRY_STATUSES:
                return last
            wait = _retry_wait(last, attempt)
            if time.monotonic() + wait >= deadline:
                return last
        await asyncio.sleep(wait)
    if last is not None:
        return last
    raise _timed_out(budget)


def _json_or_none(resp: httpx.Response) -> Any:
    try:
        return resp.json()
    except ValueError:
        return None


def _json(resp: httpx.Response) -> dict[str, Any]:
    """The response's JSON object, or SurfaceUnavailableError (e.g. an HTML page)."""
    body = _json_or_none(resp)
    if not isinstance(body, dict):
        raise SurfaceUnavailableError(
            f"Surface returned a non-JSON response (HTTP {resp.status_code})",
            status_code=resp.status_code,
        )
    return body


_M = TypeVar("_M", bound=pydantic.BaseModel)


def _parse(model: type[_M], resp: httpx.Response) -> _M:
    """Validate the response into ``model``; an unexpected shape is not a real answer."""
    try:
        return model.model_validate(_json(resp))
    except pydantic.ValidationError as e:
        raise SurfaceUnavailableError(
            f"Surface returned an unexpected response (HTTP {resp.status_code})",
            status_code=resp.status_code,
        ) from e


def _raise_for_status(resp: httpx.Response) -> None:
    if resp.is_success:
        return
    status = resp.status_code
    body = _json_or_none(resp)
    if not isinstance(body, dict):
        # The mapped 4xx keep their types with the raw text; anything else
        # without a JSON body came from something other than Surface.
        if status not in (400, 401, 404, 429):
            raise SurfaceUnavailableError(
                f"Surface returned a non-JSON response (HTTP {status})", status_code=status
            )
        body = {}
    msg = body.get("error") or resp.text
    rid = body.get("requestId")
    if status in _UNAVAILABLE_STATUSES:
        raise SurfaceUnavailableError(
            f"Surface is unavailable (HTTP {status}): {msg}", status_code=status, request_id=rid
        )
    if status == 401:
        raise AuthenticationError(msg, request_id=rid)
    if status == 404:
        raise NotFoundError(msg, request_id=rid)
    if status == 400:
        raise ValidationError(msg, request_id=rid)
    if status == 429:
        if "quota" in msg.lower() or "credit" in msg.lower():
            raise QuotaExceededError(msg, request_id=rid)
        raise RateLimitError(msg, request_id=rid)
    raise SurfaceError(msg, status_code=status, request_id=rid)


class SurfaceClient:
    """Client for the Surface file scanning API.

    Supports two scan modes:

    - ``"api"`` (default): sends files to the remote Surface API.
    - ``"local"``: sends scan requests to a local scanner daemon.

    Usage::

        # API mode (default)
        client = SurfaceClient("sfk_your_token_here")
        result = client.scan_file("malware.exe")

        # Local mode — requires the scanner daemon running on localhost
        client = SurfaceClient("sfk_your_token_here", mode="local")
        result = client.scan_file("malware.exe")

    ``timeout`` is the budget in seconds for each call, covering retries of
    502/503/504 and refused connections. When Surface gives no real answer in
    time the call raises :class:`SurfaceUnavailableError`.
    """

    def __init__(
        self,
        api_key: str | None = None,
        base_url: str | None = None,
        mode: str = "api",
        scanner_url: str = "http://127.0.0.1:8090",
        strictness: str | None = None,
        timeout: float = DEFAULT_TIMEOUT,
    ):
        if strictness is not None and strictness not in STRICTNESS_LEVELS:
            raise ValueError(f"strictness must be one of {', '.join(STRICTNESS_LEVELS)}")
        # Default ActionContext.strictness for scan_payload; a context that
        # sets its own wins. None leaves the scanner default (balanced).
        self.strictness = strictness
        # Seconds per SDK call, across all attempts and retry waits.
        self.timeout = timeout
        self.mode = mode
        self.base_url = _resolve_base_url(base_url)
        self.scanner_url = scanner_url.rstrip("/")
        self.api_key = _resolve_api_key(api_key, required=(mode != "local"))
        self._scanner_client: httpx.Client | None = None

        if mode == "local":
            self._scanner_client = httpx.Client(
                base_url=self.scanner_url,
                timeout=timeout,
            )

        # Local mode without a key gets no hosted client at all; _cloud raises a
        # clear error if a hosted-only method is called.
        self._client = (
            httpx.Client(
                base_url=self.base_url,
                headers={"Authorization": f"Bearer {self.api_key}"},
                timeout=timeout,
                http2=True,
            )
            if self.api_key
            else None
        )

    @property
    def _cloud(self) -> httpx.Client:
        """The hosted-API client, or a clear error explaining the key is needed."""
        if self._client is None:
            raise AuthenticationError(
                "This call needs the hosted Surface API. Pass api_key or set "
                "SURFACE_KEY (mode=\"local\" only covers scanning)."
            )
        return self._client

    def close(self) -> None:
        if self._client:
            self._client.close()
        if self._scanner_client:
            self._scanner_client.close()

    def __enter__(self) -> SurfaceClient:
        return self

    def __exit__(self, *args: Any) -> None:
        self.close()

    # ------------------------------------------------------------------
    # Scan endpoints
    # ------------------------------------------------------------------

    def scan_file(
        self,
        file: FileInput,
        *,
        defer_scan: bool = False,
        request_id: str | None = None,
        reject: str | list[str] | None = None,
    ) -> ScanResult | DeferredScanResponse:
        """Upload and scan a file.

        Args:
            file: Path string, Path object, bytes, or file-like object.
            defer_scan: If True, returns immediately with a scan ID to poll.
            request_id: Optional client-generated request ID for idempotency.
            reject: Threat levels ("Malicious"/"Suspicious") or recommended
                actions ("Block"/"Review") to reject. Raises MaliciousFileError if the
                scan result matches. E.g. ``reject=["malicious", "suspicious"]``.

        Returns:
            ScanResult on synchronous scan (HTTP 200), or
            DeferredScanResponse on deferred scan (HTTP 202).
        """
        filename, content = _prepare_file(file)

        params: dict[str, str] = {}
        if defer_scan:
            params["defer"] = "true"
        # The backend derives the request ID from the X-Request-ID header.
        headers = {"X-Request-ID": request_id} if request_id else None

        if self.mode == "local":
            assert self._scanner_client is not None, "Scanner client not initialized"
            resp = _send(
                self._scanner_client,
                self.timeout,
                "POST",
                "/scan",
                files={"file": (filename, content)},
                params=params,
                headers=headers,
            )
        else:
            resp = _send(
                self._cloud,
                self.timeout,
                "POST",
                "/scan",
                files={"file": (filename, content)},
                params=params,
                headers=headers,
            )

        _raise_for_status(resp)
        if resp.status_code == 202:
            return _parse(DeferredScanResponse, resp)

        result = _parse(ScanResult, resp)

        if reject:
            # reject matches on threat level ("Clean"/"Suspicious"/"Malicious")
            # OR recommended action ("Allow"/"Review"/"Block"); the two vocabularies
            # don't overlap, so one lowercased set covers both. Case-insensitive.
            reject_levels = {reject} if isinstance(reject, str) else set(reject)
            normalized = {level.lower() for level in reject_levels}
            if (
                result.safety_score.threat_level.lower() in normalized
                or result.safety_score.recommended_action.lower() in normalized
            ):
                raise MaliciousFileError(result)

        return result

    def scan_payload(
        self,
        payload: bytes | str,
        label: str = "payload.bin",
        *,
        defer_scan: bool = False,
        request_id: str | None = None,
        reject: str | list[str] | None = None,
        context: ActionContext | dict | None = None,
    ) -> ScanResult | DeferredScanResponse:
        """Scan a raw payload without file upload overhead.

        Useful for middleware scanning — scan API request/response bodies
        between services. Text payloads are sent as-is (no encoding overhead).
        Binary payloads are automatically base64-encoded.

        Args:
            payload: Raw string or bytes to scan. Strings are sent raw.
                Binary bytes are auto-base64-encoded.
            label: Optional label for the scan (e.g. "api-request").
            defer_scan: If True, returns immediately with a scan ID to poll.
            request_id: Optional client-generated request ID.
            reject: Threat levels ("Malicious"/"Suspicious") or recommended
                actions ("Block"/"Review") to reject. Raises MaliciousFileError if matched.
            context: Optional action-screening context. Fields you omit stay
                silent; values you pass are validated.

        Returns:
            ScanResult on synchronous scan (HTTP 200), or
            DeferredScanResponse on deferred scan (HTTP 202).
        """
        # Auto-detect: strings sent raw, non-UTF8 bytes sent as base64
        if isinstance(payload, str):
            body: dict[str, str] = {"payload": payload, "label": label}
        else:
            try:
                text = payload.decode("utf-8")
                body = {"payload": text, "label": label}
            except UnicodeDecodeError:
                import base64
                body = {
                    "payload": base64.b64encode(payload).decode("ascii"),
                    "encoding": "base64",
                    "label": label,
                }

        ctx_body = _context_body(context, self.strictness)
        if ctx_body:
            body["context"] = ctx_body

        params: dict[str, str] = {}
        if defer_scan:
            params["defer"] = "true"
        # The backend derives the request ID from the X-Request-ID header.
        headers = {"X-Request-ID": request_id} if request_id else None

        if self.mode == "local":
            assert self._scanner_client is not None, "Scanner client not initialized"
            resp = _send(
                self._scanner_client,
                self.timeout,
                "POST",
                "/scan/payload",
                json=body,
                params=params,
                headers=headers,
            )
        else:
            resp = _send(
                self._cloud,
                self.timeout,
                "POST",
                "/scan/payload",
                json=body,
                params=params,
                headers=headers,
            )

        _raise_for_status(resp)
        if resp.status_code == 202:
            return _parse(DeferredScanResponse, resp)

        result = _parse(ScanResult, resp)

        if reject:
            # reject matches on threat level ("Clean"/"Suspicious"/"Malicious")
            # OR recommended action ("Allow"/"Review"/"Block"); the two vocabularies
            # don't overlap, so one lowercased set covers both. Case-insensitive.
            reject_levels = {reject} if isinstance(reject, str) else set(reject)
            normalized = {level.lower() for level in reject_levels}
            if (
                result.safety_score.threat_level.lower() in normalized
                or result.safety_score.recommended_action.lower() in normalized
            ):
                raise MaliciousFileError(result)

        return result

    def get_scan(self, scan_id: str) -> dict[str, Any]:
        """Poll a deferred scan by ID. Returns raw dict (status may be 'pending' or 'complete')."""
        if self.mode == "local":
            assert self._scanner_client is not None, "Scanner client not initialized"
            resp = _send(self._scanner_client, self.timeout, "GET", f"/scan/{scan_id}")
        else:
            resp = _send(self._cloud, self.timeout, "GET", f"/scan/{scan_id}")
        _raise_for_status(resp)
        return _json(resp)

    # ------------------------------------------------------------------
    # Account / usage
    # ------------------------------------------------------------------

    def get_usage(self) -> Usage:
        resp = _send(self._cloud, self.timeout, "GET", "/account/usage")
        _raise_for_status(resp)
        return _parse(Usage, resp)

    def get_account(self) -> dict[str, Any]:
        resp = _send(self._cloud, self.timeout, "GET", "/account")
        _raise_for_status(resp)
        return _json(resp)

    # ------------------------------------------------------------------
    # Scan history
    # ------------------------------------------------------------------

    def get_scan_history(self, page: int = 1, limit: int = 25) -> ScanHistoryPage:
        resp = _send(
            self._cloud, self.timeout, "GET", "/account/history", params={"page": page, "limit": limit}
        )
        _raise_for_status(resp)
        return _parse(ScanHistoryPage, resp)


# ------------------------------------------------------------------
# Webhook signature verification (standalone function)
# ------------------------------------------------------------------

class AsyncSurfaceClient:
    """Async client for the Surface file scanning API.

    Usage::

        async with AsyncSurfaceClient("sfk_your_token_here") as client:
            result = await client.scan_file("malware.exe")

        # Batch scan multiple files concurrently
        async with AsyncSurfaceClient() as client:
            results = await client.scan_files(["a.exe", "b.pdf", "c.zip"])

    ``timeout`` works as on :class:`SurfaceClient`: seconds per call, retries
    included, then :class:`SurfaceUnavailableError`.
    """

    def __init__(
        self,
        api_key: str | None = None,
        base_url: str | None = None,
        max_concurrency: int = 10,
        mode: str = "api",
        scanner_url: str = "http://127.0.0.1:8090",
        strictness: str | None = None,
        timeout: float = DEFAULT_TIMEOUT,
    ):
        if strictness is not None and strictness not in STRICTNESS_LEVELS:
            raise ValueError(f"strictness must be one of {', '.join(STRICTNESS_LEVELS)}")
        # Default ActionContext.strictness for scan_payload; a context that
        # sets its own wins. None leaves the scanner default (balanced).
        self.strictness = strictness
        # Seconds per SDK call, across all attempts and retry waits.
        self.timeout = timeout
        self.mode = mode
        self.base_url = _resolve_base_url(base_url)
        self.scanner_url = scanner_url.rstrip("/")
        self.max_concurrency = max_concurrency
        self.api_key = _resolve_api_key(api_key, required=(mode != "local"))
        self._scanner_client: httpx.AsyncClient | None = None

        if mode == "local":
            self._scanner_client = httpx.AsyncClient(
                base_url=self.scanner_url,
                timeout=timeout,
            )

        # Local mode without a key gets no hosted client at all; _cloud raises a
        # clear error if a hosted-only method is called.
        self._client = (
            httpx.AsyncClient(
                base_url=self.base_url,
                headers={"Authorization": f"Bearer {self.api_key}"},
                timeout=timeout,
                http2=True,
            )
            if self.api_key
            else None
        )

    @property
    def _cloud(self) -> httpx.AsyncClient:
        """The hosted-API client, or a clear error explaining the key is needed."""
        if self._client is None:
            raise AuthenticationError(
                "This call needs the hosted Surface API. Pass api_key or set "
                "SURFACE_KEY (mode=\"local\" only covers scanning)."
            )
        return self._client

    async def close(self) -> None:
        if self._client:
            await self._client.aclose()
        if self._scanner_client:
            await self._scanner_client.aclose()

    async def __aenter__(self) -> AsyncSurfaceClient:
        return self

    async def __aexit__(self, *args: Any) -> None:
        await self.close()

    # ------------------------------------------------------------------
    # Scan endpoints
    # ------------------------------------------------------------------

    async def scan_file(
        self,
        file: FileInput,
        *,
        defer_scan: bool = False,
        request_id: str | None = None,
        reject: str | list[str] | None = None,
    ) -> ScanResult | DeferredScanResponse:
        """Upload and scan a file asynchronously."""
        filename, content = _prepare_file(file)

        params: dict[str, str] = {}
        if defer_scan:
            params["defer"] = "true"
        # The backend derives the request ID from the X-Request-ID header.
        headers = {"X-Request-ID": request_id} if request_id else None

        if self.mode == "local":
            assert self._scanner_client is not None, "Scanner client not initialized"
            resp = await _asend(
                self._scanner_client,
                self.timeout,
                "POST",
                "/scan",
                files={"file": (filename, content)},
                params=params,
                headers=headers,
            )
        else:
            resp = await _asend(
                self._cloud,
                self.timeout,
                "POST",
                "/scan",
                files={"file": (filename, content)},
                params=params,
                headers=headers,
            )

        _raise_for_status(resp)
        if resp.status_code == 202:
            return _parse(DeferredScanResponse, resp)

        result = _parse(ScanResult, resp)

        if reject:
            # reject matches on threat level ("Clean"/"Suspicious"/"Malicious")
            # OR recommended action ("Allow"/"Review"/"Block"); the two vocabularies
            # don't overlap, so one lowercased set covers both. Case-insensitive.
            reject_levels = {reject} if isinstance(reject, str) else set(reject)
            normalized = {level.lower() for level in reject_levels}
            if (
                result.safety_score.threat_level.lower() in normalized
                or result.safety_score.recommended_action.lower() in normalized
            ):
                raise MaliciousFileError(result)

        return result

    async def scan_payload(
        self,
        payload: bytes | str,
        label: str = "payload.bin",
        *,
        defer_scan: bool = False,
        request_id: str | None = None,
        reject: str | list[str] | None = None,
        context: ActionContext | dict | None = None,
    ) -> ScanResult | DeferredScanResponse:
        """Scan a raw payload without file upload overhead (async).

        Text payloads are sent raw. Binary payloads are auto-base64-encoded.

        Args:
            payload: Raw string or bytes to scan.
            label: Optional label for the scan.
            defer_scan: If True, returns immediately with a scan ID to poll.
            request_id: Optional client-generated request ID.
            reject: Threat levels ("Malicious"/"Suspicious") or recommended
                actions ("Block"/"Review") to reject.
            context: Optional action-screening context. Fields you omit stay
                silent; values you pass are validated.
        """
        if isinstance(payload, str):
            body: dict[str, str] = {"payload": payload, "label": label}
        else:
            try:
                text = payload.decode("utf-8")
                body = {"payload": text, "label": label}
            except UnicodeDecodeError:
                import base64
                body = {
                    "payload": base64.b64encode(payload).decode("ascii"),
                    "encoding": "base64",
                    "label": label,
                }

        ctx_body = _context_body(context, self.strictness)
        if ctx_body:
            body["context"] = ctx_body

        params: dict[str, str] = {}
        if defer_scan:
            params["defer"] = "true"
        # The backend derives the request ID from the X-Request-ID header.
        headers = {"X-Request-ID": request_id} if request_id else None

        if self.mode == "local":
            assert self._scanner_client is not None, "Scanner client not initialized"
            resp = await _asend(
                self._scanner_client,
                self.timeout,
                "POST",
                "/scan/payload",
                json=body,
                params=params,
                headers=headers,
            )
        else:
            resp = await _asend(
                self._cloud,
                self.timeout,
                "POST",
                "/scan/payload",
                json=body,
                params=params,
                headers=headers,
            )

        _raise_for_status(resp)
        if resp.status_code == 202:
            return _parse(DeferredScanResponse, resp)

        result = _parse(ScanResult, resp)

        if reject:
            # reject matches on threat level ("Clean"/"Suspicious"/"Malicious")
            # OR recommended action ("Allow"/"Review"/"Block"); the two vocabularies
            # don't overlap, so one lowercased set covers both. Case-insensitive.
            reject_levels = {reject} if isinstance(reject, str) else set(reject)
            normalized = {level.lower() for level in reject_levels}
            if (
                result.safety_score.threat_level.lower() in normalized
                or result.safety_score.recommended_action.lower() in normalized
            ):
                raise MaliciousFileError(result)

        return result

    async def scan_files(
        self,
        files: list[FileInput],
        *,
        defer_scan: bool = False,
        reject: str | list[str] | None = None,
    ) -> list[ScanResult | DeferredScanResponse]:
        """Scan multiple files concurrently.

        Uses a semaphore to limit concurrency to ``max_concurrency`` (default 10).
        Returns results in the same order as the input list.
        """
        import asyncio

        sem = asyncio.Semaphore(self.max_concurrency)

        async def _scan(f: FileInput) -> ScanResult | DeferredScanResponse:
            async with sem:
                return await self.scan_file(f, defer_scan=defer_scan, reject=reject)

        return list(await asyncio.gather(*[_scan(f) for f in files]))

    async def get_scan(self, scan_id: str) -> dict[str, Any]:
        if self.mode == "local":
            assert self._scanner_client is not None, "Scanner client not initialized"
            resp = await _asend(self._scanner_client, self.timeout, "GET", f"/scan/{scan_id}")
        else:
            resp = await _asend(self._cloud, self.timeout, "GET", f"/scan/{scan_id}")
        _raise_for_status(resp)
        return _json(resp)

    # ------------------------------------------------------------------
    # Account / usage
    # ------------------------------------------------------------------

    async def get_usage(self) -> Usage:
        resp = await _asend(self._cloud, self.timeout, "GET", "/account/usage")
        _raise_for_status(resp)
        return _parse(Usage, resp)

    async def get_account(self) -> dict[str, Any]:
        resp = await _asend(self._cloud, self.timeout, "GET", "/account")
        _raise_for_status(resp)
        return _json(resp)

    # ------------------------------------------------------------------
    # Scan history
    # ------------------------------------------------------------------

    async def get_scan_history(self, page: int = 1, limit: int = 25) -> ScanHistoryPage:
        resp = await _asend(
            self._cloud, self.timeout, "GET", "/account/history", params={"page": page, "limit": limit}
        )
        _raise_for_status(resp)
        return _parse(ScanHistoryPage, resp)


# ------------------------------------------------------------------
# Webhook signature verification (standalone function)
# ------------------------------------------------------------------

def verify_webhook_signature(body: bytes, secret: str, signature_header: str) -> bool:
    """Verify an HMAC-SHA256 webhook signature.

    Args:
        body: Raw request body bytes.
        secret: Webhook secret configured in the scan profile.
        signature_header: Value of the X-Surface-Signature header.

    Returns:
        True if the signature is valid.
    """
    expected = hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(f"sha256={expected}", signature_header)
