"""Base connector — abstract interface for API provider adapters."""

from __future__ import annotations

from abc import ABC, abstractmethod

from fastapi import Request


class BaseConnector(ABC):
    """Abstract base for provider-specific API connectors."""

    @property
    @abstractmethod
    def name(self) -> str:
        """Provider identifier (e.g. 'google', 'microsoft', 'slack')."""

    @property
    @abstractmethod
    def base_url(self) -> str:
        """Upstream API base URL."""

    def translate_path(self, path: str) -> str:
        """Optionally transform the proxy path for this provider.

        Default: pass through as-is.
        """
        return path

    def build_forward_headers(self, request: Request) -> dict[str, str]:
        """Build headers to forward to the upstream API.

        Default: forward Authorization and Content-Type.
        """
        headers: dict[str, str] = {}
        if "authorization" in request.headers:
            headers["Authorization"] = request.headers["authorization"]
        if "content-type" in request.headers:
            headers["Content-Type"] = request.headers["content-type"]
        return headers

    def build_target_url(self, path: str, query: str) -> str:
        """Construct the full upstream URL."""
        translated = self.translate_path(path)
        url = f"{self.base_url.rstrip('/')}{translated}"
        if query:
            url = f"{url}?{query}"
        return url
