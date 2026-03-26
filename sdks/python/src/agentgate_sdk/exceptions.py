"""Custom exceptions for the AgentGate SDK."""

from __future__ import annotations

import httpx


class AgentGateError(Exception):
    """Base exception for all AgentGate SDK errors."""

    def __init__(
        self,
        message: str,
        status_code: int | None = None,
        response_body: dict | None = None,
    ) -> None:
        self.status_code = status_code
        self.response_body = response_body or {}
        super().__init__(message)


class AuthenticationError(AgentGateError):
    """Raised when authentication fails (HTTP 401)."""


class AuthorizationError(AgentGateError):
    """Raised when authorization fails (HTTP 403)."""


class NotFoundError(AgentGateError):
    """Raised when a resource is not found (HTTP 404)."""


class RateLimitError(AgentGateError):
    """Raised when rate limit is exceeded (HTTP 429)."""


class ValidationError(AgentGateError):
    """Raised when request validation fails (HTTP 422)."""


class ServerError(AgentGateError):
    """Raised when the server returns a 5xx error."""


_STATUS_TO_EXCEPTION: dict[int, type[AgentGateError]] = {
    401: AuthenticationError,
    403: AuthorizationError,
    404: NotFoundError,
    422: ValidationError,
    429: RateLimitError,
}


def raise_for_status(response: httpx.Response) -> None:
    """Raise a typed exception based on the HTTP status code."""
    code = response.status_code
    if code < 400:
        return

    try:
        body = response.json()
    except (ValueError, UnicodeDecodeError):
        body = {"detail": response.text}

    detail = body.get("detail", response.text)

    exc_cls = _STATUS_TO_EXCEPTION.get(code)
    if exc_cls is None:
        if code >= 500:
            exc_cls = ServerError
        else:
            exc_cls = AgentGateError

    raise exc_cls(
        message=f"HTTP {code}: {detail}",
        status_code=code,
        response_body=body,
    )
