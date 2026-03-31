"""Path normalization — deterministic sanitization for authorization bypass prevention.

Handles:
- Double/multiple slashes: //a///b -> /a/b
- Dot segments: /a/./b -> /a/b, /a/../b -> /b
- Percent-encoding: /%63 -> /c (single decode pass)
- Unicode slash lookalikes: U+2215, U+FF0F -> /
- Trailing slashes: /a/b/ -> /a/b
- Maximum path length enforcement
"""

from __future__ import annotations

import re
import unicodedata
import urllib.parse

# Maximum path length to prevent performance degradation on adversarial inputs
MAX_PATH_LENGTH = 2048

# Unicode characters that look like '/' but aren't ASCII slash
_UNICODE_SLASH_MAP = str.maketrans({
    "\u2215": "/",  # DIVISION SLASH
    "\uff0f": "/",  # FULLWIDTH SOLIDUS
    "\u2044": "/",  # FRACTION SLASH
    "\u29f8": "/",  # BIG SOLIDUS
})

# Collapse multiple slashes
_MULTI_SLASH_RE = re.compile(r"/{2,}")


def normalize_path(path: str) -> str:
    """Normalize a URL path to a canonical form for safe matching.

    This is the single source of truth for path canonicalization.
    Must be called before intent analysis and policy evaluation.

    Steps (order matters):
    1. Unicode slash normalization
    2. Percent-decoding (single pass — no recursive decode)
    3. Collapse multiple slashes
    4. Resolve dot segments (RFC 3986 §5.2.4)
    5. Strip trailing slash (unless path is "/")
    6. Enforce max length
    """
    if not path:
        return "/"

    # 1. Unicode slash lookalikes → ASCII slash
    path = path.translate(_UNICODE_SLASH_MAP)

    # 2. Percent-decode (single pass to prevent double-decode attacks)
    path = urllib.parse.unquote(path)

    # 3. Collapse // -> /
    path = _MULTI_SLASH_RE.sub("/", path)

    # 4. Resolve /./ and /../ segments (RFC 3986 algorithm)
    path = _resolve_dot_segments(path)

    # 5. Strip trailing slash (preserve root)
    if len(path) > 1 and path.endswith("/"):
        path = path.rstrip("/")

    # 6. Enforce maximum length
    if len(path) > MAX_PATH_LENGTH:
        path = path[:MAX_PATH_LENGTH]

    return path or "/"


def _resolve_dot_segments(path: str) -> str:
    """Remove dot segments per RFC 3986 §5.2.4."""
    # Split into segments and rebuild
    segments = path.split("/")
    resolved: list[str] = []

    for seg in segments:
        if seg == ".":
            continue
        elif seg == "..":
            if resolved and resolved[-1] != "":
                resolved.pop()
        else:
            resolved.append(seg)

    result = "/".join(resolved)
    # Ensure leading slash
    if not result.startswith("/"):
        result = "/" + result
    return result
