"""Credential-attack detections."""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Iterator
from datetime import timedelta
from typing import ClassVar

from ..models import Event, EventType, Finding, Severity
from ..timeline import Timeline
from .base import Detection, register

FAILURE_TYPES = (EventType.LOGIN_FAILURE, EventType.INVALID_USER)

BURST_THRESHOLD = 10
BURST_WINDOW = timedelta(minutes=1)
SPRAY_USER_THRESHOLD = 5


def _dedupe_attempts(events: list[Event]) -> list[Event]:
    """Collapse the several log lines sshd writes per credential attempt into one.

    A single failed SSH attempt produces an ``Invalid user`` line, one or two
    ``pam_unix`` lines and a ``Failed password`` line — all sharing the connection's
    pid. Counting lines rather than attempts inflates the total several-fold and
    produces a report that overstates what happened, so events are keyed by
    ``(source_ip, user, pid)`` wherever a pid is available.
    """
    seen: dict[tuple[object, ...], Event] = {}
    for event in events:
        key: tuple[object, ...] = (
            (event.source_ip, event.user, event.pid)
            if event.pid is not None
            else (event.source_ip, event.user, event.timestamp)
        )
        seen.setdefault(key, event)
    return sorted(seen.values(), key=lambda e: e.timestamp)


def _group_by_ip(events: list[Event]) -> dict[str, list[Event]]:
    grouped: dict[str, list[Event]] = defaultdict(list)
    for event in _dedupe_attempts(events):
        if event.source_ip:
            grouped[event.source_ip].append(event)
    return grouped


@register
class BruteForceDetection(Detection):
    rule_id: ClassVar[str] = "THN-0001"
    title: ClassVar[str] = "SSH brute-force attempt"
    severity: ClassVar[Severity] = Severity.HIGH
    description: ClassVar[str] = (
        "A high volume of authentication failures from a single source address."
    )
    attack_techniques: ClassVar[list[str]] = ["T1110", "T1110.001"]

    def run(self, timeline: Timeline) -> Iterator[Finding]:
        failures = timeline.of_type(*FAILURE_TYPES)

        for ip, events in sorted(_group_by_ip(failures).items()):
            events.sort(key=lambda e: e.timestamp)
            burst = _densest_window(events, BURST_WINDOW)
            if len(burst) < BURST_THRESHOLD:
                continue

            users = sorted({e.user for e in events if e.user})
            duration = events[-1].timestamp - events[0].timestamp

            yield Finding(
                rule_id=self.rule_id,
                title=f"Brute-force attempt from {ip}",
                severity=self.severity,
                description=(
                    f"{len(events)} authentication failures from {ip} across "
                    f"{_humanise(duration)}, peaking at {len(burst)} within "
                    f"{int(BURST_WINDOW.total_seconds())}s. "
                    f"{len(users)} distinct username(s) targeted."
                ),
                events=events,
                attack_techniques=list(self.attack_techniques),
                metadata={
                    "source_ip": ip,
                    "failure_count": len(events),
                    "peak_per_window": len(burst),
                    "targeted_users": users,
                    "duration_seconds": int(duration.total_seconds()),
                },
            )


@register
class SuccessfulBruteForceDetection(Detection):
    rule_id: ClassVar[str] = "THN-0002"
    title: ClassVar[str] = "Successful login after brute-force"
    severity: ClassVar[Severity] = Severity.CRITICAL
    description: ClassVar[str] = (
        "An address that generated repeated failures subsequently authenticated."
    )
    attack_techniques: ClassVar[list[str]] = ["T1110", "T1078"]

    def run(self, timeline: Timeline) -> Iterator[Finding]:
        failures = _group_by_ip(timeline.of_type(*FAILURE_TYPES))
        successes = _group_by_ip(timeline.of_type(EventType.LOGIN_SUCCESS))

        for ip, wins in sorted(successes.items()):
            prior = failures.get(ip, [])
            if len(prior) < BURST_THRESHOLD:
                continue

            for success in sorted(wins, key=lambda e: e.timestamp):
                preceding = [e for e in prior if e.timestamp < success.timestamp]
                if len(preceding) < BURST_THRESHOLD:
                    continue

                yield Finding(
                    rule_id=self.rule_id,
                    title=f"Compromised account '{success.user}' via brute-force from {ip}",
                    severity=self.severity,
                    description=(
                        f"{len(preceding)} failed attempts from {ip} preceded a successful "
                        f"login as '{success.user}' at "
                        f"{success.timestamp.strftime('%Y-%m-%d %H:%M:%S')} UTC. "
                        "Treat this account as compromised."
                    ),
                    events=[*preceding[-5:], success],
                    attack_techniques=list(self.attack_techniques),
                    metadata={
                        "source_ip": ip,
                        "compromised_user": success.user,
                        "preceding_failures": len(preceding),
                        "success_time": success.timestamp.isoformat(),
                    },
                )
                break  # first success is the compromise; later ones are follow-on access


@register
class PasswordSprayDetection(Detection):
    rule_id: ClassVar[str] = "THN-0003"
    title: ClassVar[str] = "Password spraying"
    severity: ClassVar[Severity] = Severity.MEDIUM
    description: ClassVar[str] = "One source tried many distinct usernames with few attempts each."
    attack_techniques: ClassVar[list[str]] = ["T1110.003"]

    def run(self, timeline: Timeline) -> Iterator[Finding]:
        for ip, events in sorted(_group_by_ip(timeline.of_type(*FAILURE_TYPES)).items()):
            users = {e.user for e in events if e.user}
            if len(users) < SPRAY_USER_THRESHOLD:
                continue
            # Spraying is wide and shallow; a deep single-user grind is plain brute force.
            if len(events) / len(users) > 3:
                continue

            yield Finding(
                rule_id=self.rule_id,
                title=f"Password spraying from {ip}",
                severity=self.severity,
                description=(
                    f"{ip} attempted {len(users)} distinct usernames with an average of "
                    f"{len(events) / len(users):.1f} attempts each — consistent with "
                    "spraying rather than targeting a single account."
                ),
                events=events,
                attack_techniques=list(self.attack_techniques),
                metadata={"source_ip": ip, "user_count": len(users), "users": sorted(users)},
            )


def _densest_window(events: list[Event], window: timedelta) -> list[Event]:
    """Return the largest set of events falling inside any ``window``-wide span."""
    best: list[Event] = []
    start = 0
    for end in range(len(events)):
        while events[end].timestamp - events[start].timestamp > window:
            start += 1
        if end - start + 1 > len(best):
            best = events[start : end + 1]
    return best


def _humanise(delta: timedelta) -> str:
    seconds = int(delta.total_seconds())
    if seconds < 60:
        return f"{seconds}s"
    if seconds < 3600:
        return f"{seconds // 60}m {seconds % 60}s"
    return f"{seconds // 3600}h {(seconds % 3600) // 60}m"
