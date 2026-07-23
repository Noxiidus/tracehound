"""Anti-forensics detections — reasoning about what is *missing*.

Every other rule in this package reacts to events that exist. An attacker who cleans up
after themselves removes exactly those events, so rules built solely on presence get
quieter the more thorough the intruder was.

These rules invert that. A log that falls silent for half an hour on an otherwise busy
host, a ``wtmp`` whose size is not a whole number of records, an empty shell history
belonging to an account that demonstrably ran commands — none of those are events, and
all of them are evidence.

Absence is weaker evidence than presence, so everything here is deliberately
conservative: gaps are only reported against an established baseline of activity, and
findings state plainly that a benign explanation may exist.
"""

from __future__ import annotations

import statistics
from collections.abc import Iterator
from datetime import timedelta
from itertools import pairwise
from typing import ClassVar

from ..config import Config
from ..models import Event, EventType, Finding, Severity
from ..timeline import Timeline
from .base import Detection, register

#: A gap is only meaningful if the log was otherwise chatty enough for silence to stand out.
MIN_EVENTS_FOR_BASELINE = 30

#: How many times the median inter-event interval a gap must exceed to be reported.
GAP_MULTIPLIER = 20


@register
class LogGapDetection(Detection):
    rule_id: ClassVar[str] = "THN-0030"
    title: ClassVar[str] = "Gap in log coverage"
    severity: ClassVar[Severity] = Severity.MEDIUM
    description: ClassVar[str] = (
        "A log fell silent for an extended period despite being otherwise active."
    )
    attack_techniques: ClassVar[list[str]] = ["T1070.002"]

    def run(self, timeline: Timeline, config: Config) -> Iterator[Finding]:
        threshold = timedelta(minutes=config.gap_minutes)

        for source, events in _by_source(timeline).items():
            if len(events) < MIN_EVENTS_FOR_BASELINE:
                continue

            intervals = [(b.timestamp - a.timestamp).total_seconds() for a, b in pairwise(events)]
            positive = [i for i in intervals if i > 0]
            if not positive:
                continue

            median = statistics.median(positive)
            # Require both an absolute floor and a large multiple of this log's own
            # rhythm — a quiet log should not be judged by a busy log's standards.
            floor = max(threshold.total_seconds(), median * GAP_MULTIPLIER)

            for before, after in pairwise(events):
                delta = (after.timestamp - before.timestamp).total_seconds()
                if delta < floor:
                    continue

                yield Finding(
                    rule_id=self.rule_id,
                    title=f"{int(delta // 60)}-minute gap in {source}",
                    severity=self.severity,
                    description=(
                        f"{source} recorded nothing between "
                        f"{before.timestamp.strftime('%Y-%m-%d %H:%M:%S')} and "
                        f"{after.timestamp.strftime('%Y-%m-%d %H:%M:%S')} UTC "
                        f"({int(delta // 60)} minutes), against a median interval of "
                        f"{median:.0f}s across {len(events)} events.\n"
                        "Log deletion truncates a file's middle as cleanly as its end. "
                        "A shutdown, a quiet period or log rotation would also explain "
                        "this — confirm against uptime before concluding tampering."
                    ),
                    events=[before, after],
                    attack_techniques=list(self.attack_techniques),
                    metadata={
                        "source": source,
                        "gap_seconds": int(delta),
                        "median_interval_seconds": round(median, 1),
                        "gap_start": before.timestamp.isoformat(),
                        "gap_end": after.timestamp.isoformat(),
                    },
                )


@register
class TruncatedRecordDetection(Detection):
    rule_id: ClassVar[str] = "THN-0031"
    title: ClassVar[str] = "Truncated binary login record"
    severity: ClassVar[Severity] = Severity.HIGH
    description: ClassVar[str] = (
        "A fixed-size login database ended mid-record, indicating truncation."
    )
    attack_techniques: ClassVar[list[str]] = ["T1070.002"]

    def run(self, timeline: Timeline, config: Config) -> Iterator[Finding]:
        # Surfaced by the parser during ingestion; see UtmpParser.
        for event in timeline.of_type(EventType.OTHER):
            if event.metadata.get("anomaly") != "truncated":
                continue
            yield Finding(
                rule_id=self.rule_id,
                title=f"{event.source} is truncated mid-record",
                severity=self.severity,
                description=(
                    f"{event.source} does not contain a whole number of records — "
                    f"{event.metadata.get('trailing_bytes')} trailing bytes remain.\n"
                    "These files are only ever appended to in fixed-size units, so a "
                    "partial record means something rewrote the file rather than the "
                    "system writing it normally."
                ),
                events=[event],
                attack_techniques=list(self.attack_techniques),
                metadata=dict(event.metadata),
            )


@register
class ClearedHistoryDetection(Detection):
    rule_id: ClassVar[str] = "THN-0032"
    title: ClassVar[str] = "Shell history cleared for an active account"
    severity: ClassVar[Severity] = Severity.HIGH
    description: ClassVar[str] = (
        "An account ran privileged commands but has an empty or absent shell history."
    )
    attack_techniques: ClassVar[list[str]] = ["T1070.003"]

    def run(self, timeline: Timeline, config: Config) -> Iterator[Finding]:
        active: dict[str, Event] = {}
        for event in timeline.of_type(EventType.PRIVILEGE_ESCALATION):
            if event.user and not config.account_allowed(event.user):
                active.setdefault(event.user, event)

        if not active:
            return

        with_history = {e.user for e in timeline.of_type(EventType.COMMAND_EXECUTED) if e.user}
        history_seen = any(e.source == "shell_history" for e in timeline)
        if not history_seen:
            # No history file was collected at all — that is a collection gap, not
            # evidence of tampering, and saying otherwise would be a false accusation.
            return

        for user, first in sorted(active.items()):
            if user in with_history:
                continue
            yield Finding(
                rule_id=self.rule_id,
                title=f"No shell history for active account '{user}'",
                severity=self.severity,
                description=(
                    f"'{user}' ran privileged commands from "
                    f"{first.timestamp.strftime('%Y-%m-%d %H:%M:%S')} UTC, yet no shell "
                    "history was recovered for that account while history exists for "
                    "others.\n"
                    "This is consistent with history being cleared or redirected to "
                    "/dev/null. A non-interactive or automation account would also "
                    "explain it."
                ),
                events=[first],
                attack_techniques=list(self.attack_techniques),
                metadata={"account": user, "first_privileged_use": first.timestamp.isoformat()},
            )


def _by_source(timeline: Timeline) -> dict[str, list[Event]]:
    grouped: dict[str, list[Event]] = {}
    for event in timeline:
        grouped.setdefault(event.source, []).append(event)
    for events in grouped.values():
        events.sort(key=lambda e: e.timestamp)
    return grouped
