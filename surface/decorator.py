"""@scan decorator — scan files automatically before processing."""

from __future__ import annotations

import functools
from typing import TYPE_CHECKING, Any, Callable

from .models import ScanResult

if TYPE_CHECKING:
    # Imported only for type hints. A runtime import here would create a cycle:
    # client imports MaliciousFileError from this module, so this module must not
    # import client at load time. SurfaceClient is imported lazily below instead.
    from .client import FileInput, SurfaceClient


class MaliciousFileError(Exception):
    """Raised when a scanned file is rejected by the ``reject`` policy."""

    def __init__(self, result: ScanResult):
        self.result = result
        level = result.safety_score.threat_level
        summary = result.safety_score.threat_summary
        super().__init__(f"File rejected: {level} — {summary}")


def scan(
    _fn: Callable[..., Any] | None = None,
    *,
    client: SurfaceClient | None = None,
    api_key: str | None = None,
    mode: str = "api",
    scanner_url: str = "http://127.0.0.1:8090",
    reject: str | list[str] | None = None,
) -> Any:
    """Scan decorator — caller passes a file, function receives a ScanResult.

    Usage::

        @scan
        def process(result: ScanResult):
            ...                             # no filtering

        @scan(reject="malicious")
        def process(result: ScanResult):
            ...                             # rejects malicious

        @scan(reject=["malicious", "suspicious"])
        def process(result: ScanResult):
            ...                             # rejects malicious + suspicious

        @scan(reject="malicious", mode="local")
        def process(result: ScanResult):
            ...                             # local scanner + filtering
    """
    # threat_level is capitalized server-side ("Clean"/"Suspicious"/"Malicious");
    # normalize to lowercase so reject="malicious" matches.
    reject_levels: set[str] = set()
    if isinstance(reject, str):
        reject_levels = {reject.lower()}
    elif reject:
        reject_levels = {level.lower() for level in reject}

    def decorator(fn: Callable[..., Any]) -> Callable[..., Any]:
        _cached_client: list[SurfaceClient | None] = [client]

        def _get_client() -> SurfaceClient:
            if _cached_client[0] is None:
                from .client import SurfaceClient

                _cached_client[0] = SurfaceClient(
                    api_key=api_key, mode=mode, scanner_url=scanner_url,
                )
            return _cached_client[0]

        @functools.wraps(fn)
        def wrapper(file: FileInput, *args: Any, **kwargs: Any) -> Any:
            result = _get_client().scan_file(file)

            if not isinstance(result, ScanResult):
                raise TypeError(
                    f"Expected ScanResult, got {type(result).__name__}. "
                    "The @scan decorator does not support deferred scans."
                )

            if reject_levels and result.safety_score.threat_level.lower() in reject_levels:
                raise MaliciousFileError(result)

            return fn(result, *args, **kwargs)

        return wrapper

    if _fn is not None:
        return decorator(_fn)
    return decorator
