"""Request validation middleware — body size, path sanitization, header checks."""

from __future__ import annotations

import re

from fastapi import Request, Response
from loguru import logger
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint

# Max request body size: 1 MB
MAX_BODY_SIZE = 1 * 1024 * 1024

# Max URL path length (prevents performance degradation on adversarial long paths)
MAX_PATH_LENGTH = 2048

# Patterns that indicate path traversal
_PATH_TRAVERSAL_RE = re.compile(r"(\.\./|\.\.\\|%2[eE]%2[eE]|%252[eE])")

# Headers that must not contain newlines (header injection)
_INJECTABLE_HEADERS = ("x-agent-key", "x-master-key", "authorization")


class RequestValidationMiddleware(BaseHTTPMiddleware):
    """Validates incoming requests before they reach route handlers."""

    async def dispatch(
        self, request: Request, call_next: RequestResponseEndpoint
    ) -> Response:
        # 0. Path length check (prevents performance attacks)
        raw_path = request.url.path
        if len(raw_path) > MAX_PATH_LENGTH:
            logger.warning(f"Path too long blocked: {len(raw_path)} chars")
            return _json_error(
                414, "path_too_long", f"Path exceeds maximum length of {MAX_PATH_LENGTH}"
            )

        # 1. Path traversal check
        if _PATH_TRAVERSAL_RE.search(raw_path):
            logger.warning(f"Path traversal attempt blocked: {raw_path}")
            return _json_error(
                400, "invalid_path", "Path contains illegal traversal sequences"
            )

        # 2. Null byte in path
        if "\x00" in raw_path or "%00" in raw_path:
            logger.warning(f"Null byte in path blocked: {raw_path!r}")
            return _json_error(400, "invalid_path", "Path contains null bytes")

        # 3. Header injection check (newlines in sensitive headers)
        for header_name in _INJECTABLE_HEADERS:
            value = request.headers.get(header_name, "")
            if "\n" in value or "\r" in value:
                logger.warning(f"Header injection attempt in {header_name}")
                return _json_error(
                    400,
                    "invalid_header",
                    f"Header {header_name} contains illegal characters",
                )

        # 4. Body size check (only for proxy routes with body)
        if request.method in ("POST", "PUT", "PATCH") and raw_path.startswith(
            "/proxy/"
        ):
            content_length = request.headers.get("content-length")
            if content_length and int(content_length) > MAX_BODY_SIZE:
                logger.warning(
                    f"Body too large: {content_length} bytes (max {MAX_BODY_SIZE})"
                )
                return _json_error(
                    413, "body_too_large", f"Request body exceeds {MAX_BODY_SIZE} bytes"
                )

        return await call_next(request)


def _json_error(status_code: int, error: str, detail: str) -> Response:
    import json

    return Response(
        content=json.dumps({"error": error, "detail": detail}),
        status_code=status_code,
        media_type="application/json",
    )
