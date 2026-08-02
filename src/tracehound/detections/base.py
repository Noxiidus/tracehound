"""Detection interfaces and registries.

Two families mirror the two parser families. A :class:`Detection` reasons over a
:class:`~tracehound.timeline.Timeline` of events; a :class:`FactDetection` reasons over a
:class:`~tracehound.factbase.FactBase` of state facts. Both emit the same
:class:`~tracehound.models.Finding`, so the report never has to care which produced it.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Iterator
from typing import ClassVar

from ..config import Config
from ..factbase import FactBase
from ..models import Finding, Severity
from ..timeline import TimelineLike


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
    def run(self, timeline: TimelineLike, config: Config) -> Iterator[Finding]:
        """Yield findings for ``timeline``."""


_REGISTRY: list[Detection] = []


def register(cls: type[Detection]) -> type[Detection]:
    _REGISTRY.append(cls())
    return cls


def all_detections() -> list[Detection]:
    return sorted(_REGISTRY, key=lambda d: d.rule_id)


def order_findings(findings: list[Finding]) -> list[Finding]:
    """Sort in place by severity (most severe first), then by time, then by rule.

    Fact-only findings have no ``first_seen``; they sort after timed findings of the same
    severity (via the ``has_time`` key) and among themselves by rule id, so a state-only
    scan is still deterministic.
    """
    findings.sort(
        key=lambda f: (
            -f.severity.rank,
            0 if f.first_seen else 1,
            f.first_seen.timestamp() if f.first_seen else 0.0,
            f.rule_id,
        )
    )
    return findings


def run_all(
    timeline: TimelineLike,
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

    return order_findings(findings)


class FactDetection(ABC):
    """A rule that turns state facts into findings.

    The counterpart to :class:`Detection`. It reads the whole :class:`FactBase` because,
    as with events, most conclusions are relational — a second UID-0 account only matters
    once you have seen the first. The same :class:`~tracehound.config.Config` is passed so
    suppression stays inside the rule, and because rule ids share one namespace, disabling
    a fact rule works exactly like disabling an event rule.
    """

    rule_id: ClassVar[str]
    title: ClassVar[str]
    severity: ClassVar[Severity]
    description: ClassVar[str]
    attack_techniques: ClassVar[list[str]] = []

    @abstractmethod
    def run(self, facts: FactBase, config: Config) -> Iterator[Finding]:
        """Yield findings for ``facts``."""


_FACT_REGISTRY: list[FactDetection] = []


def register_fact(cls: type[FactDetection]) -> type[FactDetection]:
    _FACT_REGISTRY.append(cls())
    return cls


def all_fact_detections() -> list[FactDetection]:
    return sorted(_FACT_REGISTRY, key=lambda d: d.rule_id)


def run_all_facts(
    facts: FactBase,
    config: Config | None = None,
    extra: list[FactDetection] | None = None,
) -> list[Finding]:
    """Run every enabled fact detection, most severe finding first."""
    active = config or Config()
    findings: list[Finding] = []

    for detection in [*all_fact_detections(), *(extra or [])]:
        if not active.rule_enabled(detection.rule_id):
            continue
        findings.extend(detection.run(facts, active))

    return order_findings(findings)
