"""Multi-host investigations.

A single compromised machine is rarely the whole story. The questions that matter in a
real incident — where did this start, how did it spread, which account carried it — can
only be answered by looking at several hosts together.

Doing that correctly means confronting a problem that does not exist in single-host work:
**the clocks do not agree**. A few seconds of drift is irrelevant when every event comes
from one machine, because everything shifts together. Across machines the same drift can
invert cause and effect, making it look as though the second host infected the first.

This module therefore treats clock offset as something that is *declared and tracked*,
never silently inferred. Where two hosts both show activity from one attacker, the
apparent difference in timing is genuinely ambiguous — it may be drift, or the attacker
may simply have reached one host before the other — and no amount of arithmetic can
separate those from artifacts alone. Rather than guess, tracehound records what it knows,
applies only offsets a human supplied, and refuses to assert an ordering it cannot stand
behind (see ``THN-1004``).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

from .config import Config
from .core import ScanResult, scan
from .models import Event, Finding
from .timeline import Timeline


class ClockConfidence(str):
    """How much the timestamps from a host can be trusted relative to other hosts."""

    DECLARED = "declared"
    ASSUMED = "assumed"


@dataclass(slots=True)
class Host:
    """One machine's evidence, plus what is known about its clock."""

    name: str
    result: ScanResult

    #: Correction added to this host's timestamps to bring them onto the case timeline.
    #: Positive means the host's clock ran slow.
    clock_offset: timedelta = timedelta(0)

    #: ``declared`` when a human supplied the offset (from a collection manifest or
    #: direct measurement); ``assumed`` when we simply took the timestamps at face value.
    clock_confidence: str = ClockConfidence.ASSUMED

    @property
    def clock_verified(self) -> bool:
        return self.clock_confidence == ClockConfidence.DECLARED

    def adjusted_events(self) -> list[Event]:
        """This host's events, shifted onto the case timeline and tagged with the host."""
        adjusted: list[Event] = []
        for event in self.result.timeline:
            copy = Event(
                timestamp=event.timestamp + self.clock_offset,
                source=event.source,
                event_type=event.event_type,
                message=event.message,
                user=event.user,
                source_ip=event.source_ip,
                process=event.process,
                pid=event.pid,
                terminal=event.terminal,
                raw=event.raw,
                metadata={
                    **event.metadata,
                    "host": self.name,
                    "clock_offset_seconds": int(self.clock_offset.total_seconds()),
                    "clock_confidence": self.clock_confidence,
                },
            )
            adjusted.append(copy)
        return adjusted

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "event_count": len(self.result.timeline),
            "finding_count": len(self.result.findings),
            "clock_offset_seconds": int(self.clock_offset.total_seconds()),
            "clock_confidence": self.clock_confidence,
            "artifacts": [a.to_dict() for a in self.result.artifacts],
        }


@dataclass(slots=True)
class Case:
    """Several hosts examined as one investigation."""

    hosts: list[Host] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)

    def host(self, name: str) -> Host | None:
        return next((h for h in self.hosts if h.name == name), None)

    @property
    def all_clocks_verified(self) -> bool:
        return all(h.clock_verified for h in self.hosts)

    def merged_timeline(self) -> Timeline:
        """Every host's events on one ordered timeline, offsets applied."""
        timeline = Timeline()
        for host in self.hosts:
            timeline.add(host.adjusted_events())
        timeline.sort()
        return timeline

    def events_by_ip(self, ip: str) -> dict[str, list[Event]]:
        """Events attributable to ``ip``, grouped by host name."""
        grouped: dict[str, list[Event]] = {}
        for host in self.hosts:
            matching = [e for e in host.adjusted_events() if e.source_ip == ip]
            if matching:
                grouped[host.name] = sorted(matching, key=lambda e: e.timestamp)
        return grouped

    def first_contact(self, ip: str) -> list[tuple[str, datetime]]:
        """(host, earliest event) for ``ip``, earliest first — the patient-zero ordering."""
        pairs = [
            (name, events[0].timestamp) for name, events in self.events_by_ip(ip).items() if events
        ]
        return sorted(pairs, key=lambda pair: pair[1])

    def to_dict(self) -> dict[str, Any]:
        return {
            "hosts": [h.to_dict() for h in self.hosts],
            "all_clocks_verified": self.all_clocks_verified,
            "findings": [f.to_dict(include_events=False) for f in self.findings],
        }


def build_case(
    sources: dict[str, list[Path]],
    *,
    year: int | None = None,
    config: Config | None = None,
    offsets: dict[str, timedelta] | None = None,
) -> Case:
    """Scan each host's evidence and assemble a :class:`Case`.

    ``offsets`` maps host name to a declared clock correction. Hosts absent from it keep
    their timestamps unchanged and are marked ``assumed`` — which downstream rules treat
    as a reason to hedge, not as a reason to stay silent.
    """
    from .detections.crosshost import run_cross_host

    declared = offsets or {}
    active = config or Config()
    case = Case()

    for name in sorted(sources):
        result = scan(sources[name], year=year, config=active)
        offset = declared.get(name)
        case.hosts.append(
            Host(
                name=name,
                result=result,
                clock_offset=offset if offset is not None else timedelta(0),
                clock_confidence=(
                    ClockConfidence.DECLARED if offset is not None else ClockConfidence.ASSUMED
                ),
            )
        )

    case.findings = run_cross_host(case, active)
    return case
