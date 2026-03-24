"""Agent registry — in-memory store for MVP, backed by JSON file."""

from __future__ import annotations

import json
import secrets
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from loguru import logger

# Type alias for agent data dictionaries
AgentDict = dict[str, Any]


def _generate_api_key() -> str:
    """Generate a cryptographically secure API key with 'ag_' prefix."""
    return f"ag_{secrets.token_hex(24)}"


class AgentStore:
    """Simple file-backed agent registry."""

    def __init__(self, path: str = "agents.json") -> None:
        self._path = Path(path)
        self._agents: dict[str, AgentDict] = {}
        self._load()

    def _load(self) -> None:
        """Load agents from the JSON file on disk."""
        if self._path.exists():
            try:
                self._agents = json.loads(self._path.read_text(encoding="utf-8"))
                logger.info(f"Loaded {len(self._agents)} agents from {self._path}")
            except (json.JSONDecodeError, OSError) as exc:
                logger.error(f"Failed to load agents: {exc}")

    def _save(self) -> None:
        """Persist the current agent registry to disk."""
        self._path.write_text(
            json.dumps(self._agents, indent=2, ensure_ascii=False),
            encoding="utf-8",
        )

    def create(self, name: str, description: str = "", policy: str = "default") -> AgentDict:
        """Register a new agent and return its data."""
        agent_id = str(uuid.uuid4())
        api_key = _generate_api_key()
        agent: AgentDict = {
            "agent_id": agent_id,
            "name": name,
            "description": description,
            "api_key": api_key,
            "policy": policy,
            "created_at": datetime.now(timezone.utc).isoformat(),
        }
        self._agents[agent_id] = agent
        self._save()
        logger.info(f"Agent created: {name} ({agent_id}), policy={policy}")
        return agent

    def get_by_api_key(self, api_key: str) -> AgentDict | None:
        """Look up an agent by its API key (linear scan)."""
        for agent in self._agents.values():
            if agent["api_key"] == api_key:
                return agent
        return None

    def get_by_id(self, agent_id: str) -> AgentDict | None:
        """Look up an agent by its unique ID."""
        return self._agents.get(agent_id)

    def list_all(self) -> list[AgentDict]:
        """Return all registered agents."""
        return list(self._agents.values())

    def delete(self, agent_id: str) -> bool:
        """Remove an agent. Returns True if it existed, False otherwise."""
        if agent_id in self._agents:
            del self._agents[agent_id]
            self._save()
            return True
        return False

    @property
    def count(self) -> int:
        """Number of registered agents."""
        return len(self._agents)
