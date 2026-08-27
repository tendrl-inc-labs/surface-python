"""Surface API client."""

from __future__ import annotations

import hashlib
import hmac
import os
from pathlib import Path
from typing import IO, Any, Union

import httpx

from .decorator import MaliciousFileError
from .errors import (
    AuthenticationError,
    NotFoundError,
    QuotaExceededError,
    RateLimitError,
    SurfaceError,
    ValidationError,
)
from .models import (
    APIKey,
    DeferredScanResponse,
    ScanHistoryPage,
    ScanProfile,
    ScanResult,
    Usage,
)

FileInput = Union[str, Path, bytes, IO[bytes]]


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


def _raise_for_status(resp: httpx.Response) -> None:
    if resp.is_success:
        return
    body = resp.json() if resp.headers.get("content-type", "").startswith("application/json") else {}
    msg = body.get("error", resp.text)
    rid = body.get("requestId")
    if resp.status_code == 401:
        raise AuthenticationError(msg, request_id=rid)
    if resp.status_code == 404:
        raise NotFoundError(msg, request_id=rid)
    if resp.status_code == 400:
        raise ValidationError(msg, request_id=rid)
    if resp.status_code == 429:
        if "quota" in msg.lower() or "credit" in msg.lower():
            raise QuotaExceededError(msg, request_id=rid)
        raise RateLimitError(msg, request_id=rid)
    raise SurfaceError(msg, status_code=resp.status_code, request_id=rid)


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
    """

    def __init__(
        self,
        api_key: str | None = None,
        base_url: str = "https://app.tendrl.com/surface/api",
        mode: str = "api",
        scanner_url: str = "http://127.0.0.1:8090",
    ):
        self.mode = mode
        self.base_url = base_url.rstrip("/")
        self.scanner_url = scanner_url.rstrip("/")
        self.api_key = _resolve_api_key(api_key, required=(mode != "local"))
        self._scanner_client: httpx.Client | None = None

        if mode == "local":
            self._scanner_client = httpx.Client(
                base_url=self.scanner_url,
                timeout=120.0,
            )

        # Local mode without a key gets no hosted client at all; _cloud raises a
        # clear error if a hosted-only method is called.
        self._client = (
            httpx.Client(
                base_url=self.base_url,
                headers={"Authorization": f"Bearer {self.api_key}"},
                timeout=120.0,
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
            reject: Threat levels to reject. Raises MaliciousFileError if the
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
            resp = self._scanner_client.post(
                "/scan",
                files={"file": (filename, content)},
                params=params,
                headers=headers,
            )
        else:
            resp = self._cloud.post(
                "/scan",
                files={"file": (filename, content)},
                params=params,
                headers=headers,
            )

        _raise_for_status(resp)
        if resp.status_code == 202:
            return DeferredScanResponse.model_validate(resp.json())

        result = ScanResult.model_validate(resp.json())

        if reject:
            # threat_level is capitalized server-side ("Clean"/"Suspicious"/
            # "Malicious"); compare case-insensitively so reject=["malicious"] matches.
            reject_levels = {reject} if isinstance(reject, str) else set(reject)
            normalized = {level.lower() for level in reject_levels}
            if result.safety_score.threat_level.lower() in normalized:
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
            reject: Threat levels to reject. Raises MaliciousFileError if matched.

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

        params: dict[str, str] = {}
        if defer_scan:
            params["defer"] = "true"
        # The backend derives the request ID from the X-Request-ID header.
        headers = {"X-Request-ID": request_id} if request_id else None

        if self.mode == "local":
            assert self._scanner_client is not None, "Scanner client not initialized"
            resp = self._scanner_client.post(
                "/scan/payload",
                json=body,
                params=params,
                headers=headers,
            )
        else:
            resp = self._cloud.post(
                "/scan/payload",
                json=body,
                params=params,
                headers=headers,
            )

        _raise_for_status(resp)
        if resp.status_code == 202:
            return DeferredScanResponse.model_validate(resp.json())

        result = ScanResult.model_validate(resp.json())

        if reject:
            # threat_level is capitalized server-side ("Clean"/"Suspicious"/
            # "Malicious"); compare case-insensitively so reject=["malicious"] matches.
            reject_levels = {reject} if isinstance(reject, str) else set(reject)
            normalized = {level.lower() for level in reject_levels}
            if result.safety_score.threat_level.lower() in normalized:
                raise MaliciousFileError(result)

        return result

    def get_scan(self, scan_id: str) -> dict[str, Any]:
        """Poll a deferred scan by ID. Returns raw dict (status may be 'pending' or 'complete')."""
        if self.mode == "local":
            assert self._scanner_client is not None, "Scanner client not initialized"
            resp = self._scanner_client.get(f"/scan/{scan_id}")
        else:
            resp = self._cloud.get(f"/scan/{scan_id}")
        _raise_for_status(resp)
        return resp.json()

    # ------------------------------------------------------------------
    # Account / usage
    # ------------------------------------------------------------------

    def get_usage(self) -> Usage:
        resp = self._cloud.get("/account/usage")
        _raise_for_status(resp)
        return Usage.model_validate(resp.json())

    def get_account(self) -> dict[str, Any]:
        resp = self._cloud.get("/account")
        _raise_for_status(resp)
        return resp.json()


    # ------------------------------------------------------------------
    # Scan profiles
    # ------------------------------------------------------------------

    def list_profiles(self) -> list[ScanProfile]:
        resp = self._cloud.get("/account/profiles")
        _raise_for_status(resp)
        data = resp.json()
        items = data.get("profiles", data) if isinstance(data, dict) else data
        return [ScanProfile.model_validate(p) for p in items]

    def create_profile(self, **kwargs: Any) -> ScanProfile:
        resp = self._cloud.post("/account/profiles", json=kwargs)
        _raise_for_status(resp)
        return ScanProfile.model_validate(resp.json())

    def update_profile(self, profile_id: str, **kwargs: Any) -> ScanProfile:
        resp = self._cloud.put(f"/account/profiles/{profile_id}", json=kwargs)
        _raise_for_status(resp)
        return ScanProfile.model_validate(resp.json())

    def delete_profile(self, profile_id: str) -> None:
        resp = self._cloud.delete(f"/account/profiles/{profile_id}")
        _raise_for_status(resp)

    # ------------------------------------------------------------------
    # API keys
    # ------------------------------------------------------------------

    def list_api_keys(self) -> list[APIKey]:
        resp = self._cloud.get("/account/keys")
        _raise_for_status(resp)
        data = resp.json()
        items = data.get("keys", data) if isinstance(data, dict) else data
        return [APIKey.model_validate(k) for k in items]

    def create_api_key(self, label: str, profile_id: str | None = None) -> APIKey:
        body: dict[str, str] = {"label": label}
        if profile_id:
            body["profile_id"] = profile_id
        resp = self._cloud.post("/account/keys", json=body)
        _raise_for_status(resp)
        return APIKey.model_validate(resp.json())

    def delete_api_key(self, key_id: str) -> None:
        resp = self._cloud.delete(f"/account/keys/{key_id}")
        _raise_for_status(resp)

    # ------------------------------------------------------------------
    # Scan history
    # ------------------------------------------------------------------

    def get_scan_history(self, page: int = 1, limit: int = 25) -> ScanHistoryPage:
        resp = self._cloud.get("/account/history", params={"page": page, "limit": limit})
        _raise_for_status(resp)
        return ScanHistoryPage.model_validate(resp.json())


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
    """

    def __init__(
        self,
        api_key: str | None = None,
        base_url: str = "https://app.tendrl.com/surface/api",
        max_concurrency: int = 10,
        mode: str = "api",
        scanner_url: str = "http://127.0.0.1:8090",
    ):
        self.mode = mode
        self.base_url = base_url.rstrip("/")
        self.scanner_url = scanner_url.rstrip("/")
        self.max_concurrency = max_concurrency
        self.api_key = _resolve_api_key(api_key, required=(mode != "local"))
        self._scanner_client: httpx.AsyncClient | None = None

        if mode == "local":
            self._scanner_client = httpx.AsyncClient(
                base_url=self.scanner_url,
                timeout=120.0,
            )

        # Local mode without a key gets no hosted client at all; _cloud raises a
        # clear error if a hosted-only method is called.
        self._client = (
            httpx.AsyncClient(
                base_url=self.base_url,
                headers={"Authorization": f"Bearer {self.api_key}"},
                timeout=120.0,
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
            resp = await self._scanner_client.post(
                "/scan",
                files={"file": (filename, content)},
                params=params,
                headers=headers,
            )
        else:
            resp = await self._cloud.post(
                "/scan",
                files={"file": (filename, content)},
                params=params,
                headers=headers,
            )

        _raise_for_status(resp)
        if resp.status_code == 202:
            return DeferredScanResponse.model_validate(resp.json())

        result = ScanResult.model_validate(resp.json())

        if reject:
            # threat_level is capitalized server-side ("Clean"/"Suspicious"/
            # "Malicious"); compare case-insensitively so reject=["malicious"] matches.
            reject_levels = {reject} if isinstance(reject, str) else set(reject)
            normalized = {level.lower() for level in reject_levels}
            if result.safety_score.threat_level.lower() in normalized:
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
    ) -> ScanResult | DeferredScanResponse:
        """Scan a raw payload without file upload overhead (async).

        Text payloads are sent raw. Binary payloads are auto-base64-encoded.

        Args:
            payload: Raw string or bytes to scan.
            label: Optional label for the scan.
            defer_scan: If True, returns immediately with a scan ID to poll.
            request_id: Optional client-generated request ID.
            reject: Threat levels to reject.
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

        params: dict[str, str] = {}
        if defer_scan:
            params["defer"] = "true"
        # The backend derives the request ID from the X-Request-ID header.
        headers = {"X-Request-ID": request_id} if request_id else None

        if self.mode == "local":
            assert self._scanner_client is not None, "Scanner client not initialized"
            resp = await self._scanner_client.post(
                "/scan/payload",
                json=body,
                params=params,
                headers=headers,
            )
        else:
            resp = await self._cloud.post(
                "/scan/payload",
                json=body,
                params=params,
                headers=headers,
            )

        _raise_for_status(resp)
        if resp.status_code == 202:
            return DeferredScanResponse.model_validate(resp.json())

        result = ScanResult.model_validate(resp.json())

        if reject:
            # threat_level is capitalized server-side ("Clean"/"Suspicious"/
            # "Malicious"); compare case-insensitively so reject=["malicious"] matches.
            reject_levels = {reject} if isinstance(reject, str) else set(reject)
            normalized = {level.lower() for level in reject_levels}
            if result.safety_score.threat_level.lower() in normalized:
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
            resp = await self._scanner_client.get(f"/scan/{scan_id}")
        else:
            resp = await self._cloud.get(f"/scan/{scan_id}")
        _raise_for_status(resp)
        return resp.json()

    # ------------------------------------------------------------------
    # Account / usage
    # ------------------------------------------------------------------

    async def get_usage(self) -> Usage:
        resp = await self._cloud.get("/account/usage")
        _raise_for_status(resp)
        return Usage.model_validate(resp.json())

    async def get_account(self) -> dict[str, Any]:
        resp = await self._cloud.get("/account")
        _raise_for_status(resp)
        return resp.json()

    # ------------------------------------------------------------------
    # Scan profiles
    # ------------------------------------------------------------------

    async def list_profiles(self) -> list[ScanProfile]:
        resp = await self._cloud.get("/account/profiles")
        _raise_for_status(resp)
        data = resp.json()
        items = data.get("profiles", data) if isinstance(data, dict) else data
        return [ScanProfile.model_validate(p) for p in items]

    async def create_profile(self, **kwargs: Any) -> ScanProfile:
        resp = await self._cloud.post("/account/profiles", json=kwargs)
        _raise_for_status(resp)
        return ScanProfile.model_validate(resp.json())

    async def update_profile(self, profile_id: str, **kwargs: Any) -> ScanProfile:
        resp = await self._cloud.put(f"/account/profiles/{profile_id}", json=kwargs)
        _raise_for_status(resp)
        return ScanProfile.model_validate(resp.json())

    async def delete_profile(self, profile_id: str) -> None:
        resp = await self._cloud.delete(f"/account/profiles/{profile_id}")
        _raise_for_status(resp)

    # ------------------------------------------------------------------
    # API keys
    # ------------------------------------------------------------------

    async def list_api_keys(self) -> list[APIKey]:
        resp = await self._cloud.get("/account/keys")
        _raise_for_status(resp)
        data = resp.json()
        items = data.get("keys", data) if isinstance(data, dict) else data
        return [APIKey.model_validate(k) for k in items]

    async def create_api_key(self, label: str, profile_id: str | None = None) -> APIKey:
        body: dict[str, str] = {"label": label}
        if profile_id:
            body["profile_id"] = profile_id
        resp = await self._cloud.post("/account/keys", json=body)
        _raise_for_status(resp)
        return APIKey.model_validate(resp.json())

    async def delete_api_key(self, key_id: str) -> None:
        resp = await self._cloud.delete(f"/account/keys/{key_id}")
        _raise_for_status(resp)

    # ------------------------------------------------------------------
    # Scan history
    # ------------------------------------------------------------------

    async def get_scan_history(self, page: int = 1, limit: int = 25) -> ScanHistoryPage:
        resp = await self._cloud.get("/account/history", params={"page": page, "limit": limit})
        _raise_for_status(resp)
        return ScanHistoryPage.model_validate(resp.json())


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
