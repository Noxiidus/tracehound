"""Timeline assembly — merge events from every parser into one ordered sequence."""

from __future__ import annotations

from collections.abc import Iterable, Iterator
from dataclasses import dataclass, field
from datetime import datetime, timedelta

from .models import Event, EventType


@dataclass(slots=True)
class Timeline:
    """An ordered collection of events, with the slicing helpers detections need."""

    events: list[Event] = field(default_factory=list)

    def __len__(self) -> int:
        return len(self.events)

    def __iter__(self) -> Iterator[Event]:
        return iter(self.events)

    def add(self, events: Iterable[Event]) -> None:
        self.events.extend(events)

    def sort(self) -> None:
        """Order by time, then by source, so equal-timestamp output is deterministic.

        Second-granularity log formats routinely produce ties — a stable secondary key
        keeps reports reproducible across runs.
        """
        self.events.sort(key=lambda e: (e.timestamp, e.source, e.message))

    @property
    def start(self) -> datetime | None:
        return self.events[0].timestamp if self.events else None

    @property
    def end(self) -> datetime | None:
        return self.events[-1].timestamp if self.events else None

    def of_type(self, *types: EventType) -> list[Event]:
        wanted = set(types)
        return [e for e in self.events if e.event_type in wanted]

    def by_ip(self, ip: str) -> list[Event]:
        return [e for e in self.events if e.source_ip == ip]

    def by_user(self, user: str) -> list[Event]:
        return [e for e in self.events if e.user == user]

    def between(self, start: datetime, end: datetime) -> list[Event]:
        return [e for e in self.events if start <= e.timestamp <= end]

    def window(self, anchor: Event, before: timedelta, after: timedelta) -> list[Event]:
        """Events surrounding ``anchor`` — the usual "what happened around this" pivot."""
        return self.between(anchor.timestamp - before, anchor.timestamp + after)

    def sources(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for event in self.events:
            counts[event.source] = counts.get(event.source, 0) + 1
        return counts
