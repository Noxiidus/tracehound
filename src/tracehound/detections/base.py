"""Detection interface and registry."""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Iterator
from typing import ClassVar

from ..config import Config
from ..models import Finding, Severity
from ..timeline import Timeline


class Detection(ABC):
    """A rule that turns timeline events into findings.

    Detections read the whole timeline rather than a stream, because most meaningful
    conclusions are relational — a successful login only matters once you know what
    preceded it.

    Every rule receives the :class:`~tracehound.config.Config` so suppression is applied
    at the point of judgement rather than filtered out afterwards. Filtering later would
    lose the reason a finding was dropped; deciding here keeps that reasoning local to
    the rule that owns it.
    """

    rule_id: ClassVar[str]
    title: ClassVar[str]
    severity: ClassVar[Severity]
    description: ClassVar[str]
    attack_techniques: ClassVar[list[str]] = []

    @abstractmethod
    def run(self, timeline: Timeline, config: Config) -> Iterator[Finding]:
        """Yield findings for ``timeline``."""


_REGISTRY: list[Detection] = []


def register(cls: type[Detection]) -> type[Detection]:
    _REGISTRY.append(cls())
    return cls


def all_detections() -> list[Detection]:
    return sorted(_REGISTRY, key=lambda d: d.rule_id)


def run_all(
    timeline: Timeline,
    config: Config | None = None,
    extra: list[Detection] | None = None,
) -> list[Finding]:
    """Run every enabled detection, most severe finding first.

    ``extra`` carries rules loaded at runtime (see :mod:`tracehound.rules`). They are not
    added to the global registry, so loading a rule file cannot leak into another scan in
    the same process.
    """
    active = config or Config()
    findings: list[Finding] = []

    for detection in [*all_detections(), *(extra or [])]:
        if not active.rule_enabled(detection.rule_id):
            continue
        findings.extend(detection.run(timeline, active))

    findings.sort(
        key=lambda f: (-f.severity.rank, f.first_seen.timestamp() if f.first_seen else 0.0)
    )
    return findings
