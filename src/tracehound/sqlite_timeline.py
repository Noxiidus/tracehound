"""On-disk timeline backend — the same query surface as :class:`~tracehound.timeline.Timeline`,
backed by SQLite instead of a Python list.

A triage snapshot fits comfortably in memory; a year of ``auth.log`` from a busy host runs to
millions of lines and does not. This backend keeps the events on disk (or in an in-process
SQLite database) and answers the :class:`~tracehound.timeline.TimelineLike` queries with SQL,
so a detection cannot tell which backend it is running against.

Timestamps are stored as ISO-8601 strings. Because every event is UTC (the model enforces it),
those strings sort lexically in chronological order, so ``ORDER BY ts, source, message`` gives
exactly the ``(timestamp, source, message)`` order the in-memory backend produces — output is
identical whichever store is used. Only ``sqlite3`` from the standard library is required, so
the package stays dependency-free.
"""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Iterable, Iterator
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

from .models import Event, EventType

_COLUMNS = "ts, source, event_type, message, user, source_ip, process, pid, terminal, raw, metadata"
_INSERT = f"INSERT INTO events ({_COLUMNS}) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
_ORDER = "ORDER BY ts, source, message"
_BATCH = 1000


def _to_row(event: Event) -> tuple[Any, ...]:
    return (
        event.timestamp.isoformat(),
        event.source,
        event.event_type.value,
        event.message,
        event.user,
        event.source_ip,
        event.process,
        event.pid,
        event.terminal,
        event.raw,
        json.dumps(event.metadata),
    )


def _to_event(row: tuple[Any, ...]) -> Event:
    ts, source, event_type, message, user, source_ip, process, pid, terminal, raw, metadata = row
    return Event(
        timestamp=datetime.fromisoformat(str(ts)),
        source=str(source),
        event_type=EventType(event_type),
        message=str(message),
        user=str(user) if user is not None else None,
        source_ip=str(source_ip) if source_ip is not None else None,
        process=str(process) if process is not None else None,
        pid=int(pid) if pid is not None else None,
        terminal=str(terminal) if terminal is not None else None,
        raw=str(raw),
        metadata=json.loads(str(metadata)) if metadata else {},
    )


class SqliteTimeline:
    """SQLite-backed implementation of :class:`~tracehound.timeline.TimelineLike`.

    Pass a filesystem path to spill to disk, or omit it for an in-process database (the
    default) that still keeps event *objects* out of memory — only query results are
    materialised.
    """

    def __init__(self, path: str | Path = ":memory:") -> None:
        self._conn = sqlite3.connect(str(path))
        self._conn.execute(
            """
            CREATE TABLE IF NOT EXISTS events (
                seq        INTEGER PRIMARY KEY AUTOINCREMENT,
                ts         TEXT NOT NULL,
                source     TEXT NOT NULL,
                event_type TEXT NOT NULL,
                message    TEXT NOT NULL,
                user       TEXT,
                source_ip  TEXT,
                process    TEXT,
                pid        INTEGER,
                terminal   TEXT,
                raw        TEXT NOT NULL,
                metadata   TEXT NOT NULL
            )
            """
        )
        self._conn.execute("CREATE INDEX IF NOT EXISTS idx_ts ON events(ts, source, message)")
        self._conn.execute("CREATE INDEX IF NOT EXISTS idx_ip ON events(source_ip)")
        self._conn.execute("CREATE INDEX IF NOT EXISTS idx_user ON events(user)")
        self._conn.execute("CREATE INDEX IF NOT EXISTS idx_type ON events(event_type)")
        self._conn.commit()

    def close(self) -> None:
        self._conn.close()

    def __len__(self) -> int:
        (count,) = self._conn.execute("SELECT COUNT(*) FROM events").fetchone()
        return int(count)

    def __iter__(self) -> Iterator[Event]:
        # A fresh cursor streams rows without materialising the whole table.
        cursor = self._conn.execute(f"SELECT {_COLUMNS} FROM events {_ORDER}")
        for row in cursor:
            yield _to_event(row)

    def add(self, events: Iterable[Event]) -> int:
        """Insert ``events`` (a possibly-lazy iterator) in batches; return how many landed."""
        count = 0
        batch: list[tuple[object, ...]] = []
        for event in events:
            batch.append(_to_row(event))
            if len(batch) >= _BATCH:
                self._conn.executemany(_INSERT, batch)
                count += len(batch)
                batch.clear()
        if batch:
            self._conn.executemany(_INSERT, batch)
            count += len(batch)
        self._conn.commit()
        return count

    def sort(self) -> None:
        """A no-op: order is enforced on every read by ``ORDER BY ts, source, message``."""

    @property
    def start(self) -> datetime | None:
        (value,) = self._conn.execute("SELECT MIN(ts) FROM events").fetchone()
        return datetime.fromisoformat(value) if value is not None else None

    @property
    def end(self) -> datetime | None:
        (value,) = self._conn.execute("SELECT MAX(ts) FROM events").fetchone()
        return datetime.fromisoformat(value) if value is not None else None

    def _select(self, where: str, params: tuple[object, ...]) -> list[Event]:
        rows = self._conn.execute(
            f"SELECT {_COLUMNS} FROM events WHERE {where} {_ORDER}", params
        ).fetchall()
        return [_to_event(row) for row in rows]

    def of_type(self, *types: EventType) -> list[Event]:
        if not types:
            return []
        placeholders = ", ".join("?" for _ in types)
        return self._select(f"event_type IN ({placeholders})", tuple(t.value for t in types))

    def by_ip(self, ip: str) -> list[Event]:
        return self._select("source_ip = ?", (ip,))

    def by_user(self, user: str) -> list[Event]:
        return self._select("user = ?", (user,))

    def between(self, start: datetime, end: datetime) -> list[Event]:
        return self._select("ts BETWEEN ? AND ?", (start.isoformat(), end.isoformat()))

    def window(self, anchor: Event, before: timedelta, after: timedelta) -> list[Event]:
        return self.between(anchor.timestamp - before, anchor.timestamp + after)

    def sources(self) -> dict[str, int]:
        rows = self._conn.execute("SELECT source, COUNT(*) FROM events GROUP BY source")
        return {str(source): int(count) for source, count in rows}
