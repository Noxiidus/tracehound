"""Detections over executed commands — shell history and cron."""

from __future__ import annotations

import re
from collections.abc import Iterator
from typing import ClassVar

from ..config import Config
from ..models import EventType, Finding, Severity
from ..timeline import Timeline
from .base import Detection, register
from .persistence import SENSITIVE_COMMANDS

#: Paths a scheduled job has no ordinary reason to reference.
SUSPICIOUS_CRON_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"/tmp/|/dev/shm/|/var/tmp/"), "runs from a world-writable directory"),
    (re.compile(r"\b(curl|wget)\b.*\|\s*(ba)?sh"), "pipes a download straight into a shell"),
    (re.compile(r"\bnc\b|\bncat\b|/dev/tcp/"), "opens a network connection"),
    (re.compile(r"base64\s+-d|openssl\s+enc\s+-d"), "decodes an encoded payload"),
    (re.compile(r"python[23]?\s+-c|perl\s+-e|ruby\s+-e"), "executes an inline interpreter"),
]


@register
class SuspiciousShellCommandDetection(Detection):
    rule_id: ClassVar[str] = "THN-0020"
    title: ClassVar[str] = "Suspicious command in shell history"
    severity: ClassVar[Severity] = Severity.MEDIUM
    description: ClassVar[str] = "A recorded shell command matched a known abuse pattern."
    attack_techniques: ClassVar[list[str]] = ["T1059.004"]

    def run(self, timeline: Timeline, config: Config) -> Iterator[Finding]:
        for event in timeline.of_type(EventType.COMMAND_EXECUTED):
            command = str(event.metadata.get("command", event.message))
            if not command or config.account_allowed(event.user):
                continue

            for pattern, reason, techniques in SENSITIVE_COMMANDS:
                if not pattern.search(command):
                    continue

                estimated = event.metadata.get("timestamp_precision") == "file_mtime"
                caveat = (
                    "\n    Note: this history file carries no timestamps, so the time shown "
                    "is the file's mtime, not the execution time."
                    if estimated
                    else ""
                )
                who = event.user or "<unknown>"
                yield Finding(
                    rule_id=self.rule_id,
                    title=f"{reason.capitalize()} in {who}'s shell history",
                    severity=self.severity,
                    description=f"Recorded command flagged as {reason}:\n    {command}{caveat}",
                    events=[event],
                    attack_techniques=[*self.attack_techniques, *techniques],
                    metadata={
                        "account": who,
                        "command": command,
                        "reason": reason,
                        "timestamp_estimated": estimated,
                    },
                )
                break


@register
class CronPersistenceDetection(Detection):
    rule_id: ClassVar[str] = "THN-0021"
    title: ClassVar[str] = "Suspicious scheduled task"
    severity: ClassVar[Severity] = Severity.HIGH
    description: ClassVar[str] = (
        "A cron job referenced a path or technique associated with persistence."
    )
    attack_techniques: ClassVar[list[str]] = ["T1053.003"]

    def run(self, timeline: Timeline, config: Config) -> Iterator[Finding]:
        for event in timeline.of_type(EventType.CRON_JOB):
            command = str(event.metadata.get("command", ""))
            if not command or config.cron_allowed(command):
                continue

            for pattern, reason in SUSPICIOUS_CRON_PATTERNS:
                if not pattern.search(command):
                    continue
                who = event.user or "<unknown>"
                yield Finding(
                    rule_id=self.rule_id,
                    title=f"Cron job for '{who}' {reason}",
                    severity=self.severity,
                    description=(
                        f"A scheduled task running as '{who}' {reason}:\n    {command}\n"
                        "Scheduled tasks survive reboots, making this a durable foothold."
                    ),
                    events=[event],
                    attack_techniques=list(self.attack_techniques),
                    metadata={"account": who, "command": command, "reason": reason},
                )
                break
