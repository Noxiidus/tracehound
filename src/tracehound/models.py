"""Core data model.

Everything the parsers emit is an :class:`Event`; everything the detections emit is a
:class:`Finding`. Keeping both deliberately flat makes them trivial to serialise and to
reason about in a report.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any


class EventType(str, Enum):
    """Normalised event vocabulary shared across every artifact source.

    Parsers translate source-specific wording into these, so a detection can ask
    "was there a failed login" without caring whether it came from auth.log or btmp.
    """

    LOGIN_SUCCESS = "login_success"
    LOGIN_FAILURE = "login_failure"
    LOGOUT = "logout"
    SESSION_OPEN = "session_open"
    SESSION_CLOSE = "session_close"
    INVALID_USER = "invalid_user"
    ACCOUNT_CREATED = "account_created"
    ACCOUNT_DELETED = "account_deleted"
    ACCOUNT_MODIFIED = "account_modified"
    GROUP_CREATED = "group_created"
    GROUP_MEMBER_ADDED = "group_member_added"
    PASSWORD_CHANGED = "password_changed"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    COMMAND_EXECUTED = "command_executed"
    CRON_JOB = "cron_job"
    SERVICE_EVENT = "service_event"
    BOOT = "boot"
    SHUTDOWN = "shutdown"
    OTHER = "other"


class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        return _SEVERITY_RANK[self]


_SEVERITY_RANK: dict[Severity, int] = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}


@dataclass(slots=True)
class Event:
    """A single timestamped observation recovered from one artifact.

    ``timestamp`` is always timezone-aware and always UTC. Parsers are responsible for
    converting; downstream code may assume it. This is not pedantry — a local-time
    timestamp silently shifts an entire investigation, and that mistake is invisible
    until someone checks the answers.
    """

    timestamp: datetime
    source: str
    event_type: EventType
    message: str
    user: str | None = None
    source_ip: str | None = None
    process: str | None = None
    pid: int | None = None
    terminal: str | None = None
    raw: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.timestamp.tzinfo is None:
            raise ValueError(
                f"naive timestamp from source {self.source!r}; "
                "parsers must emit UTC-aware datetimes"
            )
        if self.timestamp.utcoffset() != timezone.utc.utcoffset(None):
            self.timestamp = self.timestamp.astimezone(timezone.utc)

    def to_dict(self) -> dict[str, Any]:
        return {
            "timestamp": self.timestamp.isoformat(),
            "source": self.source,
            "event_type": self.event_type.value,
            "message": self.message,
            "user": self.user,
            "source_ip": self.source_ip,
            "process": self.process,
            "pid": self.pid,
            "terminal": self.terminal,
            "raw": self.raw,
            "metadata": self.metadata,
        }


@dataclass(slots=True)
class Finding:
    """A conclusion drawn from one or more events by a detection rule."""

    rule_id: str
    title: str
    severity: Severity
    description: str
    events: list[Event] = field(default_factory=list)
    attack_techniques: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def first_seen(self) -> datetime | None:
        return min((e.timestamp for e in self.events), default=None)

    @property
    def last_seen(self) -> datetime | None:
        return max((e.timestamp for e in self.events), default=None)

    def to_dict(self, *, include_events: bool = True) -> dict[str, Any]:
        first, last = self.first_seen, self.last_seen
        out: dict[str, Any] = {
            "rule_id": self.rule_id,
            "title": self.title,
            "severity": self.severity.value,
            "description": self.description,
            "attack_techniques": self.attack_techniques,
            "first_seen": first.isoformat() if first else None,
            "last_seen": last.isoformat() if last else None,
            "event_count": len(self.events),
            "metadata": self.metadata,
        }
        if include_events:
            out["events"] = [e.to_dict() for e in self.events]
        return out
