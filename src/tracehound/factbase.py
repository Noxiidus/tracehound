"""Fact assembly — the state-artifact counterpart to :class:`~tracehound.timeline.Timeline`.

Where a :class:`Timeline` is ordered by time, a :class:`FactBase` has no order that means
anything — a fact is a standing attribute, not an event — so it is indexed for lookup
instead. Detections ask it flat questions: every subject with ``uid == 0``, every value of
``ExecStart`` for a unit, every account that has a ``shell`` at all.
"""

from __future__ import annotations

from collections.abc import Iterable, Iterator
from dataclasses import dataclass, field

from .models import Fact


@dataclass(slots=True)
class FactBase:
    """An unordered collection of facts, with the grouping helpers detections need."""

    facts: list[Fact] = field(default_factory=list)

    def __len__(self) -> int:
        return len(self.facts)

    def __iter__(self) -> Iterator[Fact]:
        return iter(self.facts)

    def add(self, facts: Iterable[Fact]) -> None:
        self.facts.extend(facts)

    def sort(self) -> None:
        """Order by subject, then attribute, then source, so output is reproducible.

        Facts have no natural order, but a report that lists them still has to list them
        the same way every run — otherwise a diff between two reports is all noise.
        """
        self.facts.sort(key=lambda f: (f.subject, f.attribute, f.source, f.value))

    def subjects(self) -> list[str]:
        """Distinct subjects, in first-seen order."""
        seen: dict[str, None] = {}
        for fact in self.facts:
            seen.setdefault(fact.subject, None)
        return list(seen)

    def of_kind(self, kind: str) -> list[str]:
        """Distinct subjects whose namespace is ``kind`` (e.g. ``account``)."""
        prefix = f"{kind}:"
        seen: dict[str, None] = {}
        for fact in self.facts:
            if fact.subject.startswith(prefix):
                seen.setdefault(fact.subject, None)
        return list(seen)

    def for_subject(self, subject: str) -> list[Fact]:
        return [f for f in self.facts if f.subject == subject]

    def with_attribute(self, attribute: str) -> list[Fact]:
        return [f for f in self.facts if f.attribute == attribute]

    def value(self, subject: str, attribute: str) -> str | None:
        """The first value of ``attribute`` for ``subject``, or ``None`` if absent.

        Most attributes are single-valued (an account has one ``uid``); the rare repeated
        attribute — a unit with several ``ExecStart`` lines — is served by :meth:`values`.
        """
        for fact in self.facts:
            if fact.subject == subject and fact.attribute == attribute:
                return fact.value
        return None

    def values(self, subject: str, attribute: str) -> list[str]:
        return [f.value for f in self.facts if f.subject == subject and f.attribute == attribute]

    def sources(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for fact in self.facts:
            counts[fact.source] = counts.get(fact.source, 0) + 1
        return counts
