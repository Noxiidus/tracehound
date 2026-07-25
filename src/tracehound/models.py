"""Core data model.

Everything the timeline parsers emit is an :class:`Event`; the state parsers emit a
:class:`Fact`; everything the detections emit is a :class:`Finding`. Keeping all three
deliberately flat makes them trivial to serialise and to reason about in a report.

An :class:`Event` is something that *happened* at a moment in time. A :class:`Fact` is
something that *is* — the current contents of a state artifact such as ``/etc/passwd`` or
a systemd unit. Facts have no meaningful timestamp, so they deliberately do not carry one:
inventing a time the evidence does not support is exactly the mistake this project refuses
to make everywhere else.
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
class Fact:
    """A single attribute of some state artifact, recovered as it stands right now.

    Modelled as an entity-attribute-value triple so a detection can ask a flat question
    ("which subjects have ``uid`` equal to ``0``") without parsing structure a second time.
    ``subject`` is namespaced by kind — ``account:root``, ``group:sudo``, ``sudo:%wheel``,
    ``sshkey:...``, ``unit:evil.service`` — so unrelated artifacts never collide.

    There is deliberately no timestamp. A fact describes what is true in the snapshot that
    was collected; when it *became* true is a different question the artifact rarely
    answers, and this project does not guess at times.
    """

    subject: str
    attribute: str
    value: str
    source: str
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def kind(self) -> str:
        """The namespace of ``subject`` — ``account`` for ``account:root``."""
        return self.subject.split(":", 1)[0]

    @property
    def name(self) -> str:
        """The bare identifier of ``subject`` — ``root`` for ``account:root``."""
        return self.subject.split(":", 1)[1] if ":" in self.subject else self.subject

    def to_dict(self) -> dict[str, Any]:
        return {
            "subject": self.subject,
            "attribute": self.attribute,
            "value": self.value,
            "source": self.source,
            "metadata": self.metadata,
        }


@dataclass(slots=True)
class Finding:
    """A conclusion drawn from one or more events *or facts* by a detection rule.

    Event-based rules populate ``events``; state-based rules populate ``facts``. A finding
    may carry either, and its time window is derived only from the events it holds — a
    fact-only finding has no window, and says so rather than inventing one.
    """

    rule_id: str
    title: str
    severity: Severity
    description: str
    events: list[Event] = field(default_factory=list)
    facts: list[Fact] = field(default_factory=list)
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
            "fact_count": len(self.facts),
            "metadata": self.metadata,
        }
        if include_events:
            out["events"] = [e.to_dict() for e in self.events]
            out["facts"] = [f.to_dict() for f in self.facts]
        return out
