"""Timeline assembly — merge events from every parser into one ordered sequence.

:class:`Timeline` is the in-memory backend. The query surface it exposes — iteration,
:meth:`~Timeline.of_type`, :meth:`~Timeline.by_ip`, :meth:`~Timeline.between` and friends —
is captured as the :class:`TimelineLike` protocol, which is the *only* thing detections
touch. A second backend (an on-disk SQLite store, planned for 0.9.0) that satisfies the same
protocol can be swapped in without any detection changing, because none of them reach past
these methods to the underlying ``events`` list.
"""

from __future__ import annotations

from collections.abc import Iterable, Iterator
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Protocol, runtime_checkable

from .models import Event, EventType


@runtime_checkable
class TimelineLike(Protocol):
    """The query surface every timeline backend must provide.

    Detections and reports are written against this, not against :class:`Timeline`, so an
    alternative backend is a drop-in. The slicing helpers return *materialised lists* of
    subsets (usually small — failures for one IP, say), while iteration streams the whole
    timeline; ``start``/``end`` are the earliest/latest timestamps (valid once :meth:`sort`
    has run). Implementations must yield events in the same deterministic order —
    ``(timestamp, source, message)`` — so output does not depend on which backend is used.
    """

    def __len__(self) -> int: ...
    def __iter__(self) -> Iterator[Event]: ...
    def add(self, events: Iterable[Event]) -> int: ...
    def sort(self) -> None: ...
    @property
    def start(self) -> datetime | None: ...
    @property
    def end(self) -> datetime | None: ...
    def of_type(self, *types: EventType) -> list[Event]: ...
    def by_ip(self, ip: str) -> list[Event]: ...
    def by_user(self, user: str) -> list[Event]: ...
    def between(self, start: datetime, end: datetime) -> list[Event]: ...
    def window(self, anchor: Event, before: timedelta, after: timedelta) -> list[Event]: ...
    def sources(self) -> dict[str, int]: ...


@dataclass(slots=True)
class Timeline:
    """An ordered collection of events, with the slicing helpers detections need.

    The in-memory implementation of :class:`TimelineLike`. Fine for a triage snapshot; the
    on-disk backend exists for datasets that do not fit in RAM.
    """

    events: list[Event] = field(default_factory=list)

    def __len__(self) -> int:
        return len(self.events)

    def __iter__(self) -> Iterator[Event]:
        return iter(self.events)

    def add(self, events: Iterable[Event]) -> int:
        """Append ``events`` (which may be a lazy iterator) and return how many were added."""
        before = len(self.events)
        self.events.extend(events)
        return len(self.events) - before

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
