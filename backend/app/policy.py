"""Policy engine — loads YAML rules and evaluates requests."""

from __future__ import annotations

import fnmatch
import os
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from zoneinfo import ZoneInfo

import yaml
from loguru import logger


@dataclass
class PolicyDecision:
    effect: str  # "allow" | "deny"
    reason: str | None = None
    matched_rule: dict | None = None


@dataclass
class TimeRestriction:
    enabled: bool = False
    timezone: str = "Asia/Tokyo"
    allowed_hours_start: str = "00:00"
    allowed_hours_end: str = "23:59"
    allowed_days: list[str] = field(
        default_factory=lambda: ["mon", "tue", "wed", "thu", "fri", "sat", "sun"]
    )


@dataclass
class Policy:
    name: str
    description: str
    rules: list[dict]
    default_effect: str = "deny"
    default_reason: str = "Denied by default policy"
    time_restriction: TimeRestriction = field(default_factory=TimeRestriction)


class PolicyEngine:
    """Loads policies from YAML and evaluates requests against them."""

    def __init__(self, policy_dir: str = "policies") -> None:
        self._policies: dict[str, Policy] = {}
        self._policy_dir = policy_dir
        self.load_all()

    def load_all(self) -> None:
        policy_path = Path(self._policy_dir)
        if not policy_path.exists():
            logger.warning(f"Policy directory not found: {policy_path.absolute()}")
            return

        for f in policy_path.glob("*.yaml"):
            try:
                self._load_file(f)
            except Exception as e:
                logger.error(f"Failed to load policy {f.name}: {e}")

        logger.info(f"Loaded {len(self._policies)} policies: {list(self._policies.keys())}")

    def _load_file(self, path: Path) -> None:
        with open(path, encoding="utf-8") as fh:
            data = yaml.safe_load(fh)

        tr_data = data.get("time_restrictions", {})
        time_restriction = TimeRestriction(
            enabled=tr_data.get("enabled", False),
            timezone=tr_data.get("timezone", "Asia/Tokyo"),
            allowed_hours_start=tr_data.get("allowed_hours", {}).get("start", "00:00"),
            allowed_hours_end=tr_data.get("allowed_hours", {}).get("end", "23:59"),
            allowed_days=tr_data.get("allowed_days", ["mon", "tue", "wed", "thu", "fri", "sat", "sun"]),
        )

        policy = Policy(
            name=data["name"],
            description=data.get("description", ""),
            rules=data.get("rules", []),
            default_effect=data.get("default_effect", "deny"),
            default_reason=data.get("default_reason", "Denied by default policy"),
            time_restriction=time_restriction,
        )
        self._policies[policy.name] = policy

    def get_policy(self, name: str) -> Policy | None:
        return self._policies.get(name)

    @property
    def policy_names(self) -> list[str]:
        return list(self._policies.keys())

    def evaluate(self, policy_name: str, method: str, path: str) -> PolicyDecision:
        """Evaluate a request against a named policy.

        Returns a PolicyDecision with effect="allow" or effect="deny".
        """
        policy = self._policies.get(policy_name)
        if policy is None:
            return PolicyDecision(
                effect="deny",
                reason=f"Policy '{policy_name}' not found",
            )

        # Check time restrictions first
        if policy.time_restriction.enabled:
            decision = self._check_time(policy.time_restriction)
            if decision is not None:
                return decision

        # Evaluate rules in order (first match wins)
        method_upper = method.upper()
        for rule in policy.rules:
            if self._matches(rule, method_upper, path):
                return PolicyDecision(
                    effect=rule["effect"],
                    reason=rule.get("reason"),
                    matched_rule=rule,
                )

        # No rule matched — use default
        return PolicyDecision(
            effect=policy.default_effect,
            reason=policy.default_reason,
        )

    @staticmethod
    def _matches(rule: dict, method: str, path: str) -> bool:
        """Check if a rule matches the given method + path."""
        rule_methods = [m.upper() for m in rule.get("methods", [])]
        if method not in rule_methods:
            return False

        resource_pattern = rule.get("resource", "")
        return fnmatch.fnmatch(path, resource_pattern)

    @staticmethod
    def _check_time(tr: TimeRestriction) -> PolicyDecision | None:
        """Return a deny decision if outside allowed time window, else None."""
        try:
            tz = ZoneInfo(tr.timezone)
        except KeyError:
            tz = ZoneInfo("UTC")

        now = datetime.now(tz)
        day_abbr = now.strftime("%a").lower()[:3]

        if day_abbr not in tr.allowed_days:
            return PolicyDecision(
                effect="deny",
                reason=f"Access denied: {day_abbr} is not in allowed days {tr.allowed_days}",
            )

        start_h, start_m = (int(x) for x in tr.allowed_hours_start.split(":"))
        end_h, end_m = (int(x) for x in tr.allowed_hours_end.split(":"))
        start_minutes = start_h * 60 + start_m
        end_minutes = end_h * 60 + end_m
        now_minutes = now.hour * 60 + now.minute

        if not (start_minutes <= now_minutes <= end_minutes):
            return PolicyDecision(
                effect="deny",
                reason=f"Access denied: current time {now.strftime('%H:%M')} is outside allowed hours {tr.allowed_hours_start}-{tr.allowed_hours_end}",
            )

        return None
