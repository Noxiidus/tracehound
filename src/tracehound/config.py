"""Tuning configuration.

Without tuning, a triage tool run against a real internet-facing host reports an SSH
brute-force every single day — because the internet brute-forces every SSH port every
day. A report nobody reads is worth nothing, so suppression has to be a first-class
feature rather than an afterthought.

Config is loaded from JSON (always available) or YAML (if PyYAML is installed).
Everything is optional; an empty :class:`Config` reproduces the default behaviour.
"""

from __future__ import annotations

import fnmatch
import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

DEFAULT_PRIVILEGED_GROUPS = frozenset({"sudo", "wheel", "admin", "adm", "root", "docker", "lxd"})


class ConfigError(ValueError):
    """Raised when a configuration file is malformed or unreadable."""


@dataclass(slots=True)
class Config:
    """Suppression lists and thresholds applied across all detections."""

    #: Source addresses whose activity is expected — jump hosts, admin workstations,
    #: monitoring. Findings anchored to these are suppressed.
    known_ips: set[str] = field(default_factory=set)

    #: Accounts whose creation and privileged use is routine (deployment automation,
    #: configuration management).
    service_accounts: set[str] = field(default_factory=set)

    #: Glob patterns for cron commands that are known-good.
    expected_cron: list[str] = field(default_factory=list)

    #: Groups treated as conferring administrative privilege.
    privileged_groups: set[str] = field(default_factory=lambda: set(DEFAULT_PRIVILEGED_GROUPS))

    #: Rule IDs to disable outright.
    disabled_rules: set[str] = field(default_factory=set)

    #: Minimum deduplicated failures before a brute-force is reported.
    brute_force_threshold: int = 10

    #: Width of the burst window, in seconds.
    brute_force_window: int = 60

    #: Distinct usernames before an attack is treated as spraying.
    spray_user_threshold: int = 5

    #: Minutes of silence in an otherwise active log before it is reported as a gap.
    gap_minutes: int = 30

    def ip_allowed(self, ip: str | None) -> bool:
        return ip is not None and ip in self.known_ips

    def account_allowed(self, user: str | None) -> bool:
        return user is not None and user in self.service_accounts

    def cron_allowed(self, command: str) -> bool:
        return any(fnmatch.fnmatch(command, pattern) for pattern in self.expected_cron)

    def rule_enabled(self, rule_id: str) -> bool:
        return rule_id not in self.disabled_rules

    def is_privileged_group(self, group: str) -> bool:
        return group.lower() in self.privileged_groups

    @classmethod
    def from_mapping(cls, data: dict[str, Any]) -> Config:
        known = cls()
        unknown = set(data) - {f for f in _FIELD_NAMES}
        if unknown:
            raise ConfigError(f"unknown configuration key(s): {', '.join(sorted(unknown))}")

        def as_set(key: str, fallback: set[str]) -> set[str]:
            value = data.get(key)
            if value is None:
                return fallback
            if not isinstance(value, list):
                raise ConfigError(f"'{key}' must be a list")
            return {str(v) for v in value}

        def as_int(key: str, fallback: int) -> int:
            value = data.get(key)
            if value is None:
                return fallback
            if not isinstance(value, int) or isinstance(value, bool):
                raise ConfigError(f"'{key}' must be an integer")
            if value < 1:
                raise ConfigError(f"'{key}' must be positive")
            return value

        expected = data.get("expected_cron", [])
        if not isinstance(expected, list):
            raise ConfigError("'expected_cron' must be a list")

        return cls(
            known_ips=as_set("known_ips", known.known_ips),
            service_accounts=as_set("service_accounts", known.service_accounts),
            expected_cron=[str(p) for p in expected],
            privileged_groups={
                g.lower() for g in as_set("privileged_groups", known.privileged_groups)
            },
            disabled_rules=as_set("disabled_rules", known.disabled_rules),
            brute_force_threshold=as_int("brute_force_threshold", known.brute_force_threshold),
            brute_force_window=as_int("brute_force_window", known.brute_force_window),
            spray_user_threshold=as_int("spray_user_threshold", known.spray_user_threshold),
            gap_minutes=as_int("gap_minutes", known.gap_minutes),
        )

    @classmethod
    def load(cls, path: Path) -> Config:
        """Load JSON, or YAML when PyYAML is available."""
        try:
            text = path.read_text(encoding="utf-8")
        except OSError as exc:
            raise ConfigError(f"cannot read {path}: {exc}") from exc

        if path.suffix.lower() in {".yaml", ".yml"}:
            data = _load_yaml(text, path)
        else:
            try:
                data = json.loads(text)
            except json.JSONDecodeError as exc:
                raise ConfigError(f"invalid JSON in {path}: {exc}") from exc

        if not isinstance(data, dict):
            raise ConfigError(f"{path}: top level must be a mapping")
        return cls.from_mapping(data)


def _load_yaml(text: str, path: Path) -> Any:
    try:
        import yaml
    except ImportError as exc:  # pragma: no cover - depends on optional extra
        raise ConfigError(
            f"{path} is YAML but PyYAML is not installed; install tracehound[yaml] or use JSON"
        ) from exc
    try:
        return yaml.safe_load(text)
    except yaml.YAMLError as exc:  # pragma: no cover - passthrough
        raise ConfigError(f"invalid YAML in {path}: {exc}") from exc


_FIELD_NAMES = {
    "known_ips",
    "service_accounts",
    "expected_cron",
    "privileged_groups",
    "disabled_rules",
    "brute_force_threshold",
    "brute_force_window",
    "spray_user_threshold",
    "gap_minutes",
}

# Kept for callers that want to compile cron globs once.
CRON_GLOB_RE = re.compile(r"[*?\[\]]")
