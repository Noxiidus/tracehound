"""Parser for cron logs (``/var/log/cron``, ``/var/log/cron.log``).

Cron logs share the syslog envelope with ``auth.log``, so this parser has a higher
priority and sniffs for the ``CROND``/``cron`` tag specifically. Two message shapes
matter::

    (root) CMD (/usr/lib64/sa/sa1 1 1)
    (root) RELOAD (/var/spool/cron/root)

The ``CMD`` form is the interesting one: it records every command cron actually ran,
which is where scheduled-task persistence shows up.
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

_LINE_RE = re.compile(
    r"^(?:(?P<mon>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})"
    r"|(?P<iso>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})))\s+"
    r"(?P<host>\S+)\s+"
    r"(?P<proc>CROND|CRON|crond|cron|anacron)(?:\[(?P<pid>\d+)\])?:\s*"
    r"(?P<msg>.*)$"
)

_ACTION_RE = re.compile(r"^\((?P<user>[^)]+)\)\s+(?P<action>[A-Z]+)\s*\((?P<detail>.*)\)\s*$")


@register
class CronLogParser(Parser):
    name = "cron"
    description = "Cron execution log (cron / cron.log)"
    priority: ClassVar[int] = 30  # more specific than auth.log, which also matches syslog

    def sniff(self, path: Path) -> bool:
        if path.suffix in {".pcap", ".pcapng"}:
            return False
        try:
            with path.open("r", encoding="utf-8", errors="replace") as fh:
                hits = 0
                for _ in range(60):
                    line = fh.readline()
                    if not line:
                        break
                    if _LINE_RE.match(line):
                        hits += 1
                        if hits >= 2:
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
                match = _LINE_RE.match(line)
                if match is None:
                    continue

                if match.group("iso"):
                    ts = datetime.fromisoformat(match.group("iso").replace("Z", "+00:00"))
                else:
                    month = _MONTHS.get(match.group("mon") or "")
                    if month is None:
                        continue
                    effective = year if year is not None else datetime.now(timezone.utc).year
                    if previous_month is not None and month < previous_month:
                        effective += 1
                        year = effective
                    previous_month = month
                    hour, minute, second = (int(p) for p in match.group("time").split(":"))
                    try:
                        ts = datetime(
                            effective,
                            month,
                            int(match.group("day")),
                            hour,
                            minute,
                            second,
                            tzinfo=timezone.utc,
                        )
                    except ValueError:
                        continue

                message = match.group("msg")
                action = _ACTION_RE.match(message)
                metadata: dict[str, object] = {}
                user: str | None = None

                if action is not None:
                    user = action.group("user")
                    metadata = {
                        "action": action.group("action"),
                        "command": action.group("detail"),
                    }

                pid_text = match.group("pid")
                yield Event(
                    timestamp=ts,
                    source=self.name,
                    event_type=EventType.CRON_JOB,
                    message=message,
                    user=user,
                    process=match.group("proc"),
                    pid=int(pid_text) if pid_text else None,
                    raw=line,
                    metadata=metadata,
                )
