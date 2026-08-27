"""Exception hierarchy for the Surface SDK."""

from __future__ import annotations


class SurfaceError(Exception):
    """Base exception for all Surface API errors."""

    def __init__(self, message: str, status_code: int = 0, request_id: str | None = None):
        self.message = message
        self.status_code = status_code
        self.request_id = request_id
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


class QuotaExceededError(SurfaceError):
    """Raised on 429 when monthly credit quota is exhausted."""

    def __init__(self, message: str = "Monthly scan quota exceeded", request_id: str | None = None):
        super().__init__(message, status_code=429, request_id=request_id)


class RateLimitError(SurfaceError):
    """Raised on 429 when per-minute rate limit is hit."""

    def __init__(self, message: str = "Rate limit exceeded", request_id: str | None = None):
        super().__init__(message, status_code=429, request_id=request_id)
