"""Notion API connector."""

from __future__ import annotations

from fastapi import Request

from .base import BaseConnector


class NotionConnector(BaseConnector):
    """Connector for Notion API v1."""

    @property
    def name(self) -> str:
        return "notion"

    @property
    def base_url(self) -> str:
        return "https://api.notion.com/v1"

    def build_forward_headers(self, request: Request) -> dict[str, str]:
        headers = super().build_forward_headers(request)
        headers["Notion-Version"] = "2022-06-28"
        return headers
