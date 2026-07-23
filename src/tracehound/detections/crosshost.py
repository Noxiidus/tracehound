"""Detections that reason across hosts.

Single-host rules cannot see a campaign. An address that fails ten times on one machine
is background noise; the same address touching four machines in sequence is an operation.
An account created on one host is worth a look; that account then authenticating on a
second host is lateral movement.

Ordering is the hazard here. Every claim of the form "A happened before B, therefore A
caused B" depends on the two hosts agreeing about time, and unverified clocks routinely
drift by minutes. Rules in this module state ordering only when the margin comfortably
exceeds plausible drift, and ``ClockUncertaintyDetection`` exists to say so out loud when
it does not.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Iterator
from datetime import timedelta
from typing import TYPE_CHECKING, ClassVar

from ..config import Config
from ..models import Event, EventType, Finding, Severity

if TYPE_CHECKING:
    from ..case import Case

#: Below this, a cross-host ordering claim is not safe against unverified clock drift.
#: Chosen because hosts without NTP routinely drift by seconds to minutes, while a real
#: intrusion sequence normally spans much longer.
SAFE_ORDERING_MARGIN = timedelta(minutes=5)

FAILURE_TYPES = (EventType.LOGIN_FAILURE, EventType.INVALID_USER)


class CrossHostDetection(ABC):
    """A rule that inspects a whole :class:`~tracehound.case.Case`."""

    rule_id: ClassVar[str]
    title: ClassVar[str]
    severity: ClassVar[Severity]
    description: ClassVar[str]
    attack_techniques: ClassVar[list[str]] = []

    @abstractmethod
    def run(self, case: Case, config: Config) -> Iterator[Finding]:
        """Yield findings for ``case``."""


_REGISTRY: list[CrossHostDetection] = []


def register(cls: type[CrossHostDetection]) -> type[CrossHostDetection]:
    _REGISTRY.append(cls())
    return cls


def all_cross_host_detections() -> list[CrossHostDetection]:
    return sorted(_REGISTRY, key=lambda d: d.rule_id)


def run_cross_host(case: Case, config: Config | None = None) -> list[Finding]:
    active = config or Config()
    findings: list[Finding] = []
    for detection in all_cross_host_detections():
        if not active.rule_enabled(detection.rule_id):
            continue
        findings.extend(detection.run(case, active))
    findings.sort(
        key=lambda f: (-f.severity.rank, f.first_seen.timestamp() if f.first_seen else 0.0)
    )
    return findings


def _hostile_ips(case: Case, config: Config) -> dict[str, dict[str, list[Event]]]:
    """Map each non-allowlisted source IP to the hosts it appears on."""
    per_ip: dict[str, dict[str, list[Event]]] = {}
    for host in case.hosts:
        for event in host.adjusted_events():
            ip = event.source_ip
            if not ip or config.ip_allowed(ip):
                continue
            per_ip.setdefault(ip, {}).setdefault(host.name, []).append(event)
    for hosts in per_ip.values():
        for events in hosts.values():
            events.sort(key=lambda e: e.timestamp)
    return per_ip


@register
class SharedAttackerDetection(CrossHostDetection):
    rule_id: ClassVar[str] = "THN-1001"
    title: ClassVar[str] = "Shared attacker infrastructure"
    severity: ClassVar[Severity] = Severity.HIGH
    description: ClassVar[str] = "One source address was active against multiple hosts."
    attack_techniques: ClassVar[list[str]] = ["T1595"]

    def run(self, case: Case, config: Config) -> Iterator[Finding]:
        if len(case.hosts) < 2:
            return

        for ip, per_host in sorted(_hostile_ips(case, config).items()):
            if len(per_host) < 2:
                continue

            hostile = any(
                e.event_type in FAILURE_TYPES or e.event_type is EventType.LOGIN_SUCCESS
                for events in per_host.values()
                for e in events
            )
            if not hostile:
                continue

            ordering = case.first_contact(ip)
            sequence = " → ".join(f"{name} ({ts.strftime('%H:%M:%S')})" for name, ts in ordering)
            events = [events[0] for events in per_host.values()]

            yield Finding(
                rule_id=self.rule_id,
                title=f"{ip} active against {len(per_host)} hosts",
                severity=self.severity,
                description=(
                    f"{ip} generated authentication activity on {len(per_host)} hosts: "
                    f"{', '.join(sorted(per_host))}.\n"
                    f"Order of first contact: {sequence}\n"
                    "Activity from one source across several machines indicates a "
                    "campaign rather than opportunistic scanning of a single target."
                ),
                events=sorted(events, key=lambda e: e.timestamp),
                attack_techniques=list(self.attack_techniques),
                metadata={
                    "source_ip": ip,
                    "hosts": sorted(per_host),
                    "host_count": len(per_host),
                    "first_contact": [
                        {"host": name, "time": ts.isoformat()} for name, ts in ordering
                    ],
                },
            )


@register
class LateralMovementDetection(CrossHostDetection):
    rule_id: ClassVar[str] = "THN-1002"
    title: ClassVar[str] = "Account reused across hosts"
    severity: ClassVar[Severity] = Severity.CRITICAL
    description: ClassVar[str] = (
        "An account created on one host subsequently authenticated on another."
    )
    attack_techniques: ClassVar[list[str]] = ["T1078", "T1021.004"]

    def run(self, case: Case, config: Config) -> Iterator[Finding]:
        if len(case.hosts) < 2:
            return

        created: dict[str, tuple[str, Event]] = {}
        for host in case.hosts:
            for event in host.adjusted_events():
                if event.event_type is EventType.ACCOUNT_CREATED and event.user:
                    created.setdefault(event.user, (host.name, event))

        for host in case.hosts:
            for event in host.adjusted_events():
                if event.event_type is not EventType.LOGIN_SUCCESS or not event.user:
                    continue
                origin = created.get(event.user)
                if origin is None:
                    continue
                origin_host, creation = origin
                if origin_host == host.name or config.account_allowed(event.user):
                    continue

                gap = event.timestamp - creation.timestamp
                if gap < timedelta(0):
                    continue

                certain = case.all_clocks_verified or gap > SAFE_ORDERING_MARGIN
                hedge = (
                    ""
                    if certain
                    else (
                        "\nThe two hosts are only "
                        f"{int(gap.total_seconds())}s apart and their clocks are not "
                        "verified against a common source, so this ordering is not "
                        "established — see THN-1004."
                    )
                )

                yield Finding(
                    rule_id=self.rule_id,
                    title=f"Account '{event.user}' created on {origin_host}, used on {host.name}",
                    severity=self.severity,
                    description=(
                        f"'{event.user}' was created on {origin_host} at "
                        f"{creation.timestamp.strftime('%Y-%m-%d %H:%M:%S')} UTC and "
                        f"authenticated on {host.name} "
                        f"{int(gap.total_seconds())}s later"
                        f"{' from ' + event.source_ip if event.source_ip else ''}.\n"
                        "An account crossing hosts is lateral movement unless it is "
                        "known shared infrastructure." + hedge
                    ),
                    events=[creation, event],
                    attack_techniques=list(self.attack_techniques),
                    metadata={
                        "account": event.user,
                        "origin_host": origin_host,
                        "target_host": host.name,
                        "seconds_between": int(gap.total_seconds()),
                        "ordering_established": certain,
                    },
                )


@register
class PatientZeroDetection(CrossHostDetection):
    rule_id: ClassVar[str] = "THN-1003"
    title: ClassVar[str] = "Earliest compromised host"
    severity: ClassVar[Severity] = Severity.INFO
    description: ClassVar[str] = "The host an attacker reached first, where determinable."
    attack_techniques: ClassVar[list[str]] = []

    def run(self, case: Case, config: Config) -> Iterator[Finding]:
        if len(case.hosts) < 2:
            return

        compromised: dict[str, list[tuple[str, Event]]] = {}
        for host in case.hosts:
            for event in host.adjusted_events():
                ip = event.source_ip
                if (
                    event.event_type is not EventType.LOGIN_SUCCESS
                    or not ip
                    or config.ip_allowed(ip)
                ):
                    continue
                compromised.setdefault(ip, []).append((host.name, event))

        for ip, entries in sorted(compromised.items()):
            by_host: dict[str, Event] = {}
            for name, event in entries:
                current = by_host.get(name)
                if current is None or event.timestamp < current.timestamp:
                    by_host[name] = event
            if len(by_host) < 2:
                continue

            ordered = sorted(by_host.items(), key=lambda pair: pair[1].timestamp)
            first_host, first_event = ordered[0]
            second_gap = ordered[1][1].timestamp - first_event.timestamp
            certain = case.all_clocks_verified or second_gap > SAFE_ORDERING_MARGIN

            yield Finding(
                rule_id=self.rule_id,
                title=(
                    f"{first_host} was reached first by {ip}"
                    if certain
                    else f"{first_host} appears first for {ip} (ordering unverified)"
                ),
                severity=Severity.MEDIUM if certain else Severity.INFO,
                description=(
                    f"{ip} authenticated successfully on {len(by_host)} hosts. The "
                    f"earliest was {first_host} at "
                    f"{first_event.timestamp.strftime('%Y-%m-%d %H:%M:%S')} UTC, "
                    f"{int(second_gap.total_seconds())}s before the next.\n"
                    + (
                        "Begin the investigation there — it is the most likely entry point."
                        if certain
                        else "That margin is inside plausible clock drift between "
                        "unverified hosts, so this is a candidate rather than a "
                        "conclusion."
                    )
                ),
                events=[event for _, event in ordered],
                attack_techniques=list(self.attack_techniques),
                metadata={
                    "source_ip": ip,
                    "candidate_patient_zero": first_host,
                    "margin_seconds": int(second_gap.total_seconds()),
                    "ordering_established": certain,
                    "sequence": [
                        {"host": name, "time": event.timestamp.isoformat()}
                        for name, event in ordered
                    ],
                },
            )


@register
class ClockUncertaintyDetection(CrossHostDetection):
    rule_id: ClassVar[str] = "THN-1004"
    title: ClassVar[str] = "Cross-host ordering not established"
    severity: ClassVar[Severity] = Severity.MEDIUM
    description: ClassVar[str] = (
        "Hosts with unverified clocks show events too close together to order safely."
    )
    attack_techniques: ClassVar[list[str]] = []

    def run(self, case: Case, config: Config) -> Iterator[Finding]:
        if len(case.hosts) < 2 or case.all_clocks_verified:
            return

        unverified = sorted(h.name for h in case.hosts if not h.clock_verified)

        tight: list[Event] = []
        for per_host in _hostile_ips(case, config).values():
            if len(per_host) < 2:
                continue
            firsts = sorted((events[0] for events in per_host.values()), key=lambda e: e.timestamp)
            span = firsts[-1].timestamp - firsts[0].timestamp
            if span <= SAFE_ORDERING_MARGIN:
                tight.extend(firsts[:2])

        if not tight:
            return

        yield Finding(
            rule_id=self.rule_id,
            title=f"Clock offsets unverified on {len(unverified)} host(s)",
            severity=self.severity,
            description=(
                f"No clock offset was supplied for: {', '.join(unverified)}.\n"
                "Their timestamps were taken at face value, and events on different "
                "hosts fall within "
                f"{int(SAFE_ORDERING_MARGIN.total_seconds())}s of each other — close "
                "enough that ordinary drift could reverse their order, and with it any "
                "conclusion about which host was compromised first.\n"
                "Supply measured offsets (recorded at collection time, or derived from a "
                "common NTP source) to turn these into safe orderings."
            ),
            events=sorted(tight, key=lambda e: e.timestamp)[:6],
            attack_techniques=list(self.attack_techniques),
            metadata={
                "unverified_hosts": unverified,
                "safe_margin_seconds": int(SAFE_ORDERING_MARGIN.total_seconds()),
            },
        )
