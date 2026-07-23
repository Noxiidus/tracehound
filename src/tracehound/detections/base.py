"""Detection interface and registry."""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Iterator
from typing import ClassVar

from ..models import Finding, Severity
from ..timeline import Timeline


class Detection(ABC):
    """A rule that turns timeline events into findings.

    Detections read the whole timeline rather than a stream, because most meaningful
    conclusions are relational — a successful login only matters once you know what
    preceded it.
    """

    rule_id: ClassVar[str]
    title: ClassVar[str]
    severity: ClassVar[Severity]
    description: ClassVar[str]
    attack_techniques: ClassVar[list[str]] = []

    @abstractmethod
    def run(self, timeline: Timeline) -> Iterator[Finding]:
        """Yield findings for ``timeline``."""


_REGISTRY: list[Detection] = []


def register(cls: type[Detection]) -> type[Detection]:
    _REGISTRY.append(cls())
    return cls


def all_detections() -> list[Detection]:
    return list(_REGISTRY)


def run_all(timeline: Timeline) -> list[Finding]:
    """Run every registered detection, most severe finding first."""
    findings: list[Finding] = []
    for detection in _REGISTRY:
        findings.extend(detection.run(timeline))
    findings.sort(
        key=lambda f: (-f.severity.rank, f.first_seen.timestamp() if f.first_seen else 0.0)
    )
    return findings
