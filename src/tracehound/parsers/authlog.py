"""Parser for ``/var/log/auth.log`` and ``/var/log/secure``.

Handles both the traditional syslog timestamp (``Mar  6 06:18:01``) and the ISO-8601
form emitted by newer rsyslog/systemd configurations.
"""

from __future__ import annotations

import re
from collections.abc import Iterator
from datetime import datetime, timezone
from pathlib import Path
from typing import ClassVar

from ..models import Event, EventType
from .base import ParseContext, Parser, register

_MONTHS = {
    "Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4, "May": 5, "Jun": 6,
    "Jul": 7, "Aug": 8, "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12,
}  # fmt: skip

# "Mar  6 06:18:01 host process[123]: message"
_SYSLOG_RE = re.compile(
    r"^(?P<mon>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+"
    r"(?P<time>\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+"
    r"(?P<proc>[\w\-./]+)(?:\[(?P<pid>\d+)\])?:\s*"
    r"(?P<msg>.*)$"
)

# "2024-03-06T06:18:01.123456+00:00 host process[123]: message"
_ISO_RE = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2}))\s+"
    r"(?P<host>\S+)\s+"
    r"(?P<proc>[\w\-./]+)(?:\[(?P<pid>\d+)\])?:\s*"
    r"(?P<msg>.*)$"
)

_IP = r"(?P<ip>\d{1,3}(?:\.\d{1,3}){3}|[0-9a-fA-F:]{3,})"

# Ordered: the first pattern that matches wins, so put specific before general.
_MESSAGE_RULES: list[tuple[re.Pattern[str], EventType]] = [
    (
        re.compile(rf"^Accepted \S+ for (?P<user>\S+) from {_IP} port (?P<port>\d+)"),
        EventType.LOGIN_SUCCESS,
    ),
    (
        re.compile(rf"^Failed \S+ for invalid user (?P<user>\S+) from {_IP} port (?P<port>\d+)"),
        EventType.LOGIN_FAILURE,
    ),
    (
        re.compile(rf"^Failed \S+ for (?P<user>\S+) from {_IP} port (?P<port>\d+)"),
        EventType.LOGIN_FAILURE,
    ),
    (re.compile(rf"^Invalid user (?P<user>\S+) from {_IP}"), EventType.INVALID_USER),
    (
        re.compile(rf"^Connection closed by authenticating user (?P<user>\S+) {_IP}"),
        EventType.LOGIN_FAILURE,
    ),
    (
        re.compile(r"^pam_unix\(\S+:auth\): authentication failure;.*?(?:user=(?P<user>\S+))?$"),
        EventType.LOGIN_FAILURE,
    ),
    (
        re.compile(r"^pam_unix\(\S+:session\): session opened for user (?P<user>[^\s(]+)"),
        EventType.SESSION_OPEN,
    ),
    (
        re.compile(r"^pam_unix\(\S+:session\): session closed for user (?P<user>[^\s(]+)"),
        EventType.SESSION_CLOSE,
    ),
    (re.compile(r"^new user: name=(?P<user>[^,]+)"), EventType.ACCOUNT_CREATED),
    (re.compile(r"^new group: name=(?P<group>[^,]+)"), EventType.GROUP_CREATED),
    (
        re.compile(r"^add '(?P<user>[^']+)' to group '(?P<group>[^']+)'"),
        EventType.GROUP_MEMBER_ADDED,
    ),
    (re.compile(r"^delete user '(?P<user>[^']+)'"), EventType.ACCOUNT_DELETED),
    (re.compile(r"^password changed for (?P<user>\S+)"), EventType.PASSWORD_CHANGED),
    (re.compile(r"^changed user '(?P<user>[^']+)' information"), EventType.ACCOUNT_MODIFIED),
    (
        re.compile(
            r"^(?P<user>\S+)\s*:\s*TTY=(?P<tty>\S*)\s*;\s*PWD=(?P<pwd>\S*)\s*;\s*"
            r"USER=(?P<target>\S*)\s*;\s*COMMAND=(?P<command>.*)$"
        ),
        EventType.PRIVILEGE_ESCALATION,
    ),
    (re.compile(r"^New session (?P<session>\d+) of user (?P<user>\S+)"), EventType.SESSION_OPEN),
    (re.compile(r"^Session (?P<session>\d+) logged out"), EventType.SESSION_CLOSE),
    (re.compile(r"^Removed session (?P<session>\d+)"), EventType.SESSION_CLOSE),
]


def _clean_user(value: str | None) -> str | None:
    if not value:
        return None
    return value.rstrip(":,").strip() or None


def classify_message(message: str) -> tuple[EventType, str | None, str | None, dict[str, object]]:
    """Map a syslog message body to ``(event_type, user, source_ip, metadata)``.

    Exposed separately from the parser because the journal carries the *same* message
    wording inside a different envelope — only the transport differs, so the vocabulary
    should be defined once and shared rather than duplicated and allowed to drift.
    """
    for pattern, candidate_type in _MESSAGE_RULES:
        found = pattern.match(message)
        if found is None:
            continue
        groups = found.groupdict()
        metadata: dict[str, object] = {
            k: v for k, v in groups.items() if v and k not in {"user", "ip"}
        }
        return candidate_type, _clean_user(groups.get("user")), groups.get("ip"), metadata
    return EventType.OTHER, None, None, {}


@register
class AuthLogParser(Parser):
    name = "auth.log"
    description = "Linux authentication log (auth.log / secure)"
    priority: ClassVar[int] = 90  # catch-all for syslog; specific formats must go first

    def sniff(self, path: Path) -> bool:
        if path.suffix in {".pcap", ".pcapng"}:
            return False
        try:
            with path.open("r", encoding="utf-8", errors="replace") as fh:
                for _ in range(40):
                    line = fh.readline()
                    if not line:
                        break
                    if _SYSLOG_RE.match(line) or _ISO_RE.match(line):
                        return True
        except (OSError, UnicodeDecodeError):
            return False
        return False

    def parse(self, path: Path, ctx: ParseContext) -> Iterator[Event]:
        year = ctx.default_year
        previous_month: int | None = None

        with path.open("r", encoding="utf-8", errors="replace") as fh:
            for raw_line in fh:
                line = raw_line.rstrip("\n")
                if not line.strip():
                    continue

                parsed = self._parse_line(line, year, previous_month)
                if parsed is None:
                    continue
                event, previous_month, year = parsed
                yield event

    def _parse_line(
        self, line: str, year: int | None, previous_month: int | None
    ) -> tuple[Event, int | None, int | None] | None:
        iso_match = _ISO_RE.match(line)
        if iso_match:
            ts = datetime.fromisoformat(iso_match.group("ts").replace("Z", "+00:00"))
            return (
                self._build(ts, iso_match, line),
                previous_month,
                year,
            )

        match = _SYSLOG_RE.match(line)
        if match is None:
            return None

        month = _MONTHS.get(match.group("mon"))
        if month is None:
            return None

        # Syslog omits the year. If the month goes backwards we have crossed a new
        # year boundary reading forwards, so bump the counter.
        effective_year = year if year is not None else datetime.now(timezone.utc).year
        if previous_month is not None and month < previous_month:
            effective_year += 1
            year = effective_year

        hour, minute, second = (int(p) for p in match.group("time").split(":"))
        try:
            ts = datetime(
                effective_year,
                month,
                int(match.group("day")),
                hour,
                minute,
                second,
                tzinfo=timezone.utc,
            )
        except ValueError:
            return None

        return self._build(ts, match, line), month, year

    def _build(self, ts: datetime, match: re.Match[str], raw: str) -> Event:
        message = match.group("msg")
        process = match.group("proc")
        pid_text = match.group("pid")

        event_type, user, source_ip, metadata = classify_message(message)

        if process == "CRON" and event_type in {EventType.SESSION_OPEN, EventType.SESSION_CLOSE}:
            event_type = EventType.CRON_JOB

        tty = metadata.get("tty")
        terminal = tty if isinstance(tty, str) else None

        return Event(
            timestamp=ts,
            source=self.name,
            event_type=event_type,
            message=message,
            user=user,
            source_ip=source_ip,
            process=process,
            pid=int(pid_text) if pid_text else None,
            terminal=terminal,
            raw=raw,
            metadata=metadata,
        )
