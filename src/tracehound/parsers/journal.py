"""Parser for systemd journal exports (``journalctl -o json``).

On modern distributions and in containers, ``/var/log/auth.log`` frequently does not
exist — the journal is the only log. Without this parser tracehound simply finds nothing
on those hosts, which is a worse failure than finding nothing interesting.

The native journal file format is intricate and versioned; parsing it directly would be
a disproportionate amount of work for a triage tool. Collecting via ``journalctl`` is
also better forensic practice, because it produces a stable artifact that can be hashed::

    journalctl -o json --no-pager > journal.json
    journalctl -o json --no-pager -u ssh --since "2024-03-01" > ssh.json

Both JSON Lines (one object per line, what ``-o json`` emits) and a single JSON array
are accepted.
"""

from __future__ import annotations

import json
from collections.abc import Iterator
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, ClassVar

from ..models import Event, EventType
from .authlog import classify_message
from .base import ParseContext, Parser, register

_REQUIRED_HINTS = ("__REALTIME_TIMESTAMP", "MESSAGE")


@register
class JournalParser(Parser):
    name = "journal"
    description = "systemd journal export (journalctl -o json)"
    priority: ClassVar[int] = 25

    def sniff(self, path: Path) -> bool:
        if path.suffix.lower() not in {".json", ".jsonl", ".ndjson", ""}:
            return False
        try:
            with path.open("r", encoding="utf-8", errors="replace") as fh:
                head = fh.read(4096)
        except (OSError, UnicodeDecodeError):
            return False
        return all(hint in head for hint in _REQUIRED_HINTS)

    def parse(self, path: Path, ctx: ParseContext) -> Iterator[Event]:
        for entry in self._entries(path):
            event = self._build(entry)
            if event is not None:
                yield event

    def _entries(self, path: Path) -> Iterator[dict[str, Any]]:
        text = path.read_text(encoding="utf-8", errors="replace").strip()
        if not text:
            return

        if text.startswith("["):
            try:
                payload = json.loads(text)
            except json.JSONDecodeError:
                return
            if isinstance(payload, list):
                for item in payload:
                    if isinstance(item, dict):
                        yield item
            return

        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                item = json.loads(line)
            except json.JSONDecodeError:
                continue  # a truncated final line is common; skip rather than abort
            if isinstance(item, dict):
                yield item

    def _build(self, entry: dict[str, Any]) -> Event | None:
        raw_ts = entry.get("__REALTIME_TIMESTAMP")
        if raw_ts is None:
            return None
        try:
            # journald stores microseconds since the epoch, as a string.
            micros = int(raw_ts)
        except (TypeError, ValueError):
            return None
        try:
            ts = datetime.fromtimestamp(micros / 1_000_000, tz=timezone.utc)
        except (OverflowError, OSError, ValueError):
            return None

        message = _as_text(entry.get("MESSAGE"))
        if message is None:
            return None

        process = _as_text(entry.get("SYSLOG_IDENTIFIER")) or _as_text(entry.get("_COMM"))

        pid_text = _as_text(entry.get("_PID")) or _as_text(entry.get("SYSLOG_PID"))
        try:
            pid = int(pid_text) if pid_text else None
        except ValueError:
            pid = None

        # Journal messages carry the same wording as syslog, so the auth.log message
        # vocabulary applies unchanged — only the envelope differs.
        event_type, user, source_ip, metadata = classify_message(message)

        if process in {"CROND", "CRON", "crond", "cron"} and event_type in {
            EventType.SESSION_OPEN,
            EventType.SESSION_CLOSE,
        }:
            event_type = EventType.CRON_JOB

        unit = _as_text(entry.get("_SYSTEMD_UNIT"))
        if unit:
            metadata["unit"] = unit

        tty = metadata.get("tty")
        return Event(
            timestamp=ts,
            source=self.name,
            event_type=event_type,
            message=message,
            user=user,
            source_ip=source_ip,
            process=process,
            pid=pid,
            terminal=tty if isinstance(tty, str) else None,
            raw=json.dumps(entry, sort_keys=True)[:2000],
            metadata=metadata,
        )


def _as_text(value: Any) -> str | None:
    """Journal values are usually strings, but binary fields arrive as byte arrays."""
    if value is None:
        return None
    if isinstance(value, str):
        return value
    if isinstance(value, list):
        try:
            return bytes(value).decode("utf-8", "replace")
        except (TypeError, ValueError):
            return None
    return str(value)
