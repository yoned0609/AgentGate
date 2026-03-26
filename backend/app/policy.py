"""Policy engine v2 — YAML rules with intent-based matching, hot reload, and validation."""

from __future__ import annotations

import fnmatch
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from zoneinfo import ZoneInfo

import yaml
from loguru import logger

from .rate_limiter import RateLimitConfig

# ── Required fields for YAML schema validation ─────────────────────

_REQUIRED_POLICY_FIELDS = {"name"}
_VALID_EFFECTS = {"allow", "deny"}
_VALID_RULE_FIELDS = {
    "resource",
    "methods",
    "effect",
    "reason",
    "intent",
    "conditions",
}


class PolicyValidationError(ValueError):
    """Raised when a policy YAML file fails schema validation."""


# ── Data classes ────────────────────────────────────────────────────


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
    rate_limit: RateLimitConfig = field(default_factory=RateLimitConfig)


# ── Policy Engine ───────────────────────────────────────────────────


class PolicyEngine:
    """Loads policies from YAML and evaluates requests against them.

    v2 features:
    - Intent-based rule matching (match on intent_type in addition to method+path)
    - Hot reload via reload_if_changed() using file mtime tracking
    - YAML schema validation on load
    - Compound conditions (AND/OR) in rules
    """

    def __init__(self, policy_dir: str = "policies") -> None:
        self._policies: dict[str, Policy] = {}
        self._policy_dir = policy_dir
        self._file_mtimes: dict[str, float] = {}
        self.load_all()

    def load_all(self) -> None:
        policy_path = Path(self._policy_dir)
        if not policy_path.exists():
            logger.warning(f"Policy directory not found: {policy_path.absolute()}")
            return

        self._policies.clear()
        self._file_mtimes.clear()

        for f in policy_path.glob("*.yaml"):
            try:
                self._load_file(f)
                self._file_mtimes[str(f)] = f.stat().st_mtime
            except PolicyValidationError as e:
                logger.error(f"Policy validation failed for {f.name}: {e}")
            except Exception as e:
                logger.error(f"Failed to load policy {f.name}: {e}")

        logger.info(
            f"Loaded {len(self._policies)} policies: {list(self._policies.keys())}"
        )

    def reload_if_changed(self) -> bool:
        """Check for modified/new/deleted policy files and reload if needed.

        Returns True if any policies were reloaded.
        """
        policy_path = Path(self._policy_dir)
        if not policy_path.exists():
            return False

        current_files = {str(f): f.stat().st_mtime for f in policy_path.glob("*.yaml")}

        changed = False
        # Check for new or modified files
        for fpath, mtime in current_files.items():
            if fpath not in self._file_mtimes or self._file_mtimes[fpath] < mtime:
                changed = True
                break

        # Check for deleted files
        if not changed:
            for fpath in self._file_mtimes:
                if fpath not in current_files:
                    changed = True
                    break

        if changed:
            logger.info("Policy files changed — reloading")
            self.load_all()

        return changed

    def _load_file(self, path: Path) -> None:
        with open(path, encoding="utf-8") as fh:
            data = yaml.safe_load(fh)

        _validate_policy_schema(data, path.name)

        tr_data = data.get("time_restrictions", {})
        time_restriction = TimeRestriction(
            enabled=tr_data.get("enabled", False),
            timezone=tr_data.get("timezone", "Asia/Tokyo"),
            allowed_hours_start=tr_data.get("allowed_hours", {}).get("start", "00:00"),
            allowed_hours_end=tr_data.get("allowed_hours", {}).get("end", "23:59"),
            allowed_days=tr_data.get(
                "allowed_days", ["mon", "tue", "wed", "thu", "fri", "sat", "sun"]
            ),
        )

        rl_data = data.get("rate_limit", {})
        rate_limit = RateLimitConfig(
            enabled=rl_data.get("enabled", True),
            requests_per_minute=rl_data.get("requests_per_minute", 60),
            requests_per_hour=rl_data.get("requests_per_hour", 1000),
        )

        policy = Policy(
            name=data["name"],
            description=data.get("description", ""),
            rules=data.get("rules", []),
            default_effect=data.get("default_effect", "deny"),
            default_reason=data.get("default_reason", "Denied by default policy"),
            time_restriction=time_restriction,
            rate_limit=rate_limit,
        )
        self._policies[policy.name] = policy

    def get_policy(self, name: str) -> Policy | None:
        return self._policies.get(name)

    @property
    def policy_names(self) -> list[str]:
        return list(self._policies.keys())

    def evaluate(
        self,
        policy_name: str,
        method: str,
        path: str,
        *,
        intent: object | None = None,
    ) -> PolicyDecision:
        """Evaluate a request against a named policy.

        Args:
            policy_name: Name of the policy to evaluate.
            method: HTTP method.
            path: Request path.
            intent: Optional IntentResult for semantic rule evaluation.

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
            if self._matches(rule, method_upper, path, intent):
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
    def _matches(
        rule: dict, method: str, path: str, intent: object | None = None
    ) -> bool:
        """Check if a rule matches the given method + path + optional intent."""
        # Method matching
        rule_methods = [m.upper() for m in rule.get("methods", [])]
        if rule_methods and method not in rule_methods:
            return False

        # Resource path matching
        resource_pattern = rule.get("resource", "")
        if resource_pattern and not fnmatch.fnmatch(path, resource_pattern):
            return False

        # Intent matching (v2): match on intent_type field
        rule_intent = rule.get("intent")
        if rule_intent is not None:
            if intent is None:
                return False
            intent_type = getattr(intent, "intent_type", None)
            if isinstance(rule_intent, list):
                if intent_type not in rule_intent:
                    return False
            elif intent_type != rule_intent:
                return False

        # Compound conditions (v2): AND/OR logic
        conditions = rule.get("conditions")
        if conditions:
            if not _evaluate_conditions(conditions, method, path, intent):
                return False

        # At least one of resource/methods/intent must be specified
        if not resource_pattern and not rule_methods and rule_intent is None:
            return False

        return True

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


# ── Schema validation ──────────────────────────────────────────────


def _validate_policy_schema(data: dict, filename: str) -> None:
    """Validate that a policy YAML has the required structure."""
    if not isinstance(data, dict):
        raise PolicyValidationError(f"{filename}: root must be a mapping")

    for field_name in _REQUIRED_POLICY_FIELDS:
        if field_name not in data:
            raise PolicyValidationError(
                f"{filename}: missing required field '{field_name}'"
            )

    # Validate default_effect
    default_effect = data.get("default_effect", "deny")
    if default_effect not in _VALID_EFFECTS:
        raise PolicyValidationError(
            f"{filename}: default_effect must be one of {_VALID_EFFECTS}, got '{default_effect}'"
        )

    # Validate rules
    rules = data.get("rules", [])
    if not isinstance(rules, list):
        raise PolicyValidationError(f"{filename}: 'rules' must be a list")

    for i, rule in enumerate(rules):
        if not isinstance(rule, dict):
            raise PolicyValidationError(f"{filename}: rule[{i}] must be a mapping")

        # Check for unknown fields
        unknown = set(rule.keys()) - _VALID_RULE_FIELDS
        if unknown:
            logger.warning(f"{filename}: rule[{i}] has unknown fields: {unknown}")

        # Effect is required
        if "effect" not in rule:
            raise PolicyValidationError(f"{filename}: rule[{i}] missing 'effect'")
        if rule["effect"] not in _VALID_EFFECTS:
            raise PolicyValidationError(
                f"{filename}: rule[{i}] effect must be one of {_VALID_EFFECTS}"
            )

        # Methods must be a list if present
        if "methods" in rule and not isinstance(rule["methods"], list):
            raise PolicyValidationError(
                f"{filename}: rule[{i}] 'methods' must be a list"
            )

        # At least one matching criterion
        has_resource = bool(rule.get("resource"))
        has_methods = bool(rule.get("methods"))
        has_intent = rule.get("intent") is not None
        if not has_resource and not has_methods and not has_intent:
            raise PolicyValidationError(
                f"{filename}: rule[{i}] must have at least one of 'resource', 'methods', or 'intent'"
            )

    # Validate rate_limit if present
    rl = data.get("rate_limit", {})
    if rl:
        rpm = rl.get("requests_per_minute")
        if rpm is not None and (not isinstance(rpm, int) or rpm < 0):
            raise PolicyValidationError(
                f"{filename}: rate_limit.requests_per_minute must be a non-negative integer"
            )
        rph = rl.get("requests_per_hour")
        if rph is not None and (not isinstance(rph, int) or rph < 0):
            raise PolicyValidationError(
                f"{filename}: rate_limit.requests_per_hour must be a non-negative integer"
            )


# ── Compound conditions ────────────────────────────────────────────


def _evaluate_conditions(
    conditions: dict, method: str, path: str, intent: object | None
) -> bool:
    """Evaluate compound conditions with AND/OR logic.

    Example YAML:
        conditions:
          and:
            - intent: read
            - resource: "/calendars/*"
          or:
            - methods: ["GET"]
            - intent: read

    'and' requires all sub-conditions to match.
    'or' requires at least one sub-condition to match.
    """
    if "and" in conditions:
        return all(
            _evaluate_single_condition(c, method, path, intent)
            for c in conditions["and"]
        )
    if "or" in conditions:
        return any(
            _evaluate_single_condition(c, method, path, intent)
            for c in conditions["or"]
        )
    # Single condition dict — treat as AND with one element
    return _evaluate_single_condition(conditions, method, path, intent)


def _evaluate_single_condition(
    cond: dict, method: str, path: str, intent: object | None
) -> bool:
    """Evaluate a single condition within a compound expression."""
    if "resource" in cond:
        if not fnmatch.fnmatch(path, cond["resource"]):
            return False
    if "methods" in cond:
        if method not in [m.upper() for m in cond["methods"]]:
            return False
    if "intent" in cond:
        if intent is None:
            return False
        intent_type = getattr(intent, "intent_type", None)
        target = cond["intent"]
        if isinstance(target, list):
            if intent_type not in target:
                return False
        elif intent_type != target:
            return False
    return True
