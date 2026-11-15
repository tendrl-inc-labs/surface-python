"""Exception hierarchy for the Surface SDK."""

from __future__ import annotations


class SurfaceError(Exception):
    """Base exception for all Surface API errors."""

    def __init__(
        self,
        message: str,
        status_code: int = 0,
        request_id: str | None = None,
        code: str | None = None,
    ):
        self.message = message
        self.status_code = status_code
        self.request_id = request_id
        #: The server's machine-readable ``code`` field (e.g. ``"plan_required"``), if it sent one.
        self.code = code
        super().__init__(message)


class AuthenticationError(SurfaceError):
    """Raised on 401 — invalid or missing API key."""

    def __init__(self, message: str = "Invalid or missing API key", request_id: str | None = None):
        super().__init__(message, status_code=401, request_id=request_id)


class NotFoundError(SurfaceError):
    """Raised on 404 — resource not found."""

    def __init__(self, message: str = "Resource not found", request_id: str | None = None):
        super().__init__(message, status_code=404, request_id=request_id)


class ValidationError(SurfaceError):
    """Raised on 400 — invalid request parameters."""

    def __init__(self, message: str = "Invalid request", request_id: str | None = None):
        super().__init__(message, status_code=400, request_id=request_id)


class PermissionDeniedError(SurfaceError):
    """Raised on 403 — the key is valid but may not do this.

    Surface answers 403 for an RBAC denial (``permission denied: …``), a
    blocked client IP, a scan profile with payload scanning turned off, and a
    feature the plan does not include (see :class:`PlanRequiredError`).
    ``message`` is the server's text and ``code`` its ``code`` field, if any.
    An invalid or missing key is 401 and raises :class:`AuthenticationError`.
    """

    def __init__(
        self,
        message: str = "Permission denied",
        status_code: int = 403,
        request_id: str | None = None,
        code: str | None = None,
    ):
        super().__init__(message, status_code=status_code, request_id=request_id, code=code)


class PlanRequiredError(PermissionDeniedError):
    """Raised when the account's plan does not include what was asked for.

    Usually a 403 with ``code == "plan_required"``. Surface also answers 402
    with the same shape (``feature``, ``current_plan``, ``upgrade``) when
    ``defer_scan=True`` is used on a plan without async scanning; that is a
    plan wall, not quota exhaustion. ``feature`` and ``current_plan`` hold the
    server's fields when present.
    """

    def __init__(
        self,
        message: str = "Not included on the current plan",
        status_code: int = 403,
        request_id: str | None = None,
        code: str | None = "plan_required",
        feature: str | None = None,
        current_plan: str | None = None,
    ):
        super().__init__(message, status_code=status_code, request_id=request_id, code=code)
        self.feature = feature
        self.current_plan = current_plan


class QuotaExceededError(SurfaceError):
    """Raised on 402 when the monthly scan quota is used up.

    The message is the server's, e.g. ``monthly scan quota exceeded (N/M scans used)``.
    A 429 is a rate limit and raises :class:`RateLimitError` instead.
    """

    def __init__(
        self,
        message: str = "Monthly scan quota exceeded",
        request_id: str | None = None,
        status_code: int = 402,
    ):
        super().__init__(message, status_code=status_code, request_id=request_id)


class RateLimitError(SurfaceError):
    """Raised on 429 — too many requests; wait (see ``Retry-After``) and retry."""

    def __init__(self, message: str = "Rate limit exceeded", request_id: str | None = None):
        super().__init__(message, status_code=429, request_id=request_id)


class SurfaceUnavailableError(SurfaceError):
    """Raised when Surface gave no real answer.

    Covers transport failures (refused, reset, DNS), the call's ``timeout``
    running out, HTTP 500/502/503/504, and a body that is not the JSON the SDK
    expects (e.g. a proxy's HTML error page). ``status_code`` is 0 when there
    was no HTTP response.
    """

    def __init__(self, message: str = "Surface is unavailable", status_code: int = 0, request_id: str | None = None):
        super().__init__(message, status_code=status_code, request_id=request_id)
