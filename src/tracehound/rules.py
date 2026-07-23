"""Declarative detection rules.

Built-in detections are Python classes because they express relationships that need real
logic — correlating an account creation with a later privilege grant, for instance. Most
rules are not like that. Most rules are "flag events of this type whose command matches
this pattern", and requiring Python for those puts rule-writing out of reach of the
people most likely to have the domain knowledge.

A rule file looks like this::

    rules:
      - id: LOCAL-0001
        title: Access to deployment secrets
        severity: high
        description: Someone read the deployment key material.
        attack: [T1552.001]
        match:
          event_type: [privilege_escalation, command_executed]
          command: "/etc/deploy/(id_rsa|secrets\\\\.env)"

      - id: LOCAL-0002
        title: Repeated sudo failures
        severity: medium
        match:
          event_type: login_failure
        threshold:
          count: 5
          window_seconds: 300
          group_by: user

``match`` narrows which events qualify; every key must hold. ``threshold`` turns the rule
from "report each match" into "report only when enough matches cluster together".
"""

from __future__ import annotations

import json
import re
from collections.abc import Iterator
from dataclasses import dataclass, field
from datetime import timedelta
from pathlib import Path
from typing import Any, ClassVar

from .config import Config
from .detections.base import Detection
from .models import Event, EventType, Finding, Severity
from .timeline import Timeline


class RuleError(ValueError):
    """Raised when a rule file is malformed."""


_GROUPABLE = {"source_ip", "user", "process", "terminal"}


@dataclass(slots=True)
class RuleSpec:
    rule_id: str
    title: str
    severity: Severity
    description: str
    attack_techniques: list[str] = field(default_factory=list)
    event_types: set[EventType] = field(default_factory=set)
    message_pattern: re.Pattern[str] | None = None
    field_patterns: dict[str, re.Pattern[str]] = field(default_factory=dict)
    users: set[str] = field(default_factory=set)
    source_ips: set[str] = field(default_factory=set)
    threshold_count: int | None = None
    threshold_window: int = 300
    group_by: str | None = None

    def matches(self, event: Event) -> bool:
        if self.event_types and event.event_type not in self.event_types:
            return False
        if self.message_pattern and not self.message_pattern.search(event.message):
            return False
        if self.users and event.user not in self.users:
            return False
        if self.source_ips and event.source_ip not in self.source_ips:
            return False
        for name, pattern in self.field_patterns.items():
            value = event.metadata.get(name)
            if value is None or not pattern.search(str(value)):
                return False
        return True


class DeclarativeDetection(Detection):
    """A :class:`~tracehound.detections.base.Detection` driven by a :class:`RuleSpec`."""

    # Set per-instance from the spec; the ClassVar declarations satisfy the base contract.
    rule_id: ClassVar[str] = ""
    title: ClassVar[str] = ""
    severity: ClassVar[Severity] = Severity.MEDIUM
    description: ClassVar[str] = ""
    attack_techniques: ClassVar[list[str]] = []

    def __init__(self, spec: RuleSpec) -> None:
        self.spec = spec
        # Shadow the class attributes so registry listings and run_all see real values.
        self.rule_id = spec.rule_id  # type: ignore[misc]
        self.title = spec.title  # type: ignore[misc]
        self.severity = spec.severity  # type: ignore[misc]
        self.description = spec.description  # type: ignore[misc]
        self.attack_techniques = list(spec.attack_techniques)  # type: ignore[misc]

    def run(self, timeline: Timeline, config: Config) -> Iterator[Finding]:
        spec = self.spec
        matched = [
            e
            for e in timeline
            if spec.matches(e)
            and not config.ip_allowed(e.source_ip)
            and not config.account_allowed(e.user)
        ]
        if not matched:
            return

        if spec.threshold_count is None:
            for event in matched:
                yield self._finding(spec.title, [event])
            return

        window = timedelta(seconds=spec.threshold_window)
        for key, events in _group(matched, spec.group_by).items():
            events.sort(key=lambda e: e.timestamp)
            burst = _densest(events, window)
            if len(burst) < spec.threshold_count:
                continue
            label = f"{spec.title} ({key})" if key else spec.title
            yield self._finding(label, burst, extra={"group": key, "count": len(burst)})

    def _finding(
        self, title: str, events: list[Event], extra: dict[str, Any] | None = None
    ) -> Finding:
        return Finding(
            rule_id=self.spec.rule_id,
            title=title,
            severity=self.spec.severity,
            description=self.spec.description,
            events=events,
            attack_techniques=list(self.spec.attack_techniques),
            metadata={"declarative": True, **(extra or {})},
        )


def _group(events: list[Event], key: str | None) -> dict[str, list[Event]]:
    if key is None:
        return {"": list(events)}
    grouped: dict[str, list[Event]] = {}
    for event in events:
        value = getattr(event, key, None)
        if value is None:
            continue
        grouped.setdefault(str(value), []).append(event)
    return grouped


def _densest(events: list[Event], window: timedelta) -> list[Event]:
    best: list[Event] = []
    start = 0
    for end in range(len(events)):
        while events[end].timestamp - events[start].timestamp > window:
            start += 1
        if end - start + 1 > len(best):
            best = events[start : end + 1]
    return best


def _compile(pattern: str, rule_id: str, where: str) -> re.Pattern[str]:
    try:
        return re.compile(pattern)
    except re.error as exc:
        raise RuleError(f"{rule_id}: invalid regex in '{where}': {exc}") from exc


def _as_list(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [value]
    if isinstance(value, list):
        return [str(v) for v in value]
    raise RuleError(f"expected a string or list, got {type(value).__name__}")


def spec_from_mapping(data: dict[str, Any]) -> RuleSpec:
    rule_id = str(data.get("id", "")).strip()
    if not rule_id:
        raise RuleError("every rule needs an 'id'")
    title = str(data.get("title", "")).strip()
    if not title:
        raise RuleError(f"{rule_id}: 'title' is required")

    severity_text = str(data.get("severity", "medium")).lower()
    try:
        severity = Severity(severity_text)
    except ValueError as exc:
        valid = ", ".join(s.value for s in Severity)
        raise RuleError(f"{rule_id}: unknown severity '{severity_text}' (use: {valid})") from exc

    match = data.get("match") or {}
    if not isinstance(match, dict):
        raise RuleError(f"{rule_id}: 'match' must be a mapping")

    event_types: set[EventType] = set()
    for name in _as_list(match.get("event_type")):
        try:
            event_types.add(EventType(name))
        except ValueError as exc:
            raise RuleError(f"{rule_id}: unknown event_type '{name}'") from exc

    reserved = {"event_type", "message", "user", "source_ip"}
    field_patterns = {
        key: _compile(str(value), rule_id, key)
        for key, value in match.items()
        if key not in reserved
    }

    message = match.get("message")
    threshold = data.get("threshold") or {}
    if not isinstance(threshold, dict):
        raise RuleError(f"{rule_id}: 'threshold' must be a mapping")

    group_by = threshold.get("group_by")
    if group_by is not None and str(group_by) not in _GROUPABLE:
        raise RuleError(
            f"{rule_id}: cannot group by '{group_by}' (use one of: {', '.join(sorted(_GROUPABLE))})"
        )

    count = threshold.get("count")
    if count is not None and (not isinstance(count, int) or count < 1):
        raise RuleError(f"{rule_id}: threshold.count must be a positive integer")

    return RuleSpec(
        rule_id=rule_id,
        title=title,
        severity=severity,
        description=str(data.get("description", title)),
        attack_techniques=_as_list(data.get("attack")),
        event_types=event_types,
        message_pattern=_compile(str(message), rule_id, "message") if message else None,
        field_patterns=field_patterns,
        users=set(_as_list(match.get("user"))),
        source_ips=set(_as_list(match.get("source_ip"))),
        threshold_count=count,
        threshold_window=int(threshold.get("window_seconds", 300)),
        group_by=str(group_by) if group_by else None,
    )


def load_rules(path: Path) -> list[Detection]:
    """Load declarative rules from a JSON or YAML file."""
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise RuleError(f"cannot read {path}: {exc}") from exc

    if path.suffix.lower() in {".yaml", ".yml"}:
        try:
            import yaml
        except ImportError as exc:  # pragma: no cover - depends on optional extra
            raise RuleError(
                f"{path} is YAML but PyYAML is not installed; install tracehound[yaml] or use JSON"
            ) from exc
        data = yaml.safe_load(text)
    else:
        try:
            data = json.loads(text)
        except json.JSONDecodeError as exc:
            raise RuleError(f"invalid JSON in {path}: {exc}") from exc

    if isinstance(data, dict):
        entries = data.get("rules", [])
    elif isinstance(data, list):
        entries = data
    else:
        raise RuleError(f"{path}: expected a mapping with 'rules', or a list")

    if not isinstance(entries, list):
        raise RuleError(f"{path}: 'rules' must be a list")

    detections: list[Detection] = []
    seen: set[str] = set()
    for entry in entries:
        if not isinstance(entry, dict):
            raise RuleError(f"{path}: each rule must be a mapping")
        spec = spec_from_mapping(entry)
        if spec.rule_id in seen:
            raise RuleError(f"{path}: duplicate rule id '{spec.rule_id}'")
        seen.add(spec.rule_id)
        detections.append(DeclarativeDetection(spec))
    return detections
