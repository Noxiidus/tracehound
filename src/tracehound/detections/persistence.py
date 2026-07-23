"""Persistence and privilege-abuse detections."""

from __future__ import annotations

import re
from collections.abc import Iterator
from typing import ClassVar

from ..models import EventType, Finding, Severity
from ..timeline import Timeline
from .base import Detection, register

PRIVILEGED_GROUPS = {"sudo", "wheel", "admin", "adm", "root", "docker", "lxd"}

# Commands worth surfacing when run through sudo. Each entry is (pattern, why, techniques).
SENSITIVE_COMMANDS: list[tuple[re.Pattern[str], str, list[str]]] = [
    (re.compile(r"/etc/(shadow|gshadow)"), "credential store access", ["T1003.008"]),
    (re.compile(r"\b(curl|wget)\b"), "remote file download", ["T1105"]),
    (re.compile(r"\bnc\b|\bncat\b|\bsocat\b"), "network utility", ["T1059.004"]),
    (
        re.compile(r"chmod\s+[ug]?\+s|chmod\s+[0-7]?[2467][0-7]{3}"),
        "setuid bit change",
        ["T1548.003"],
    ),
    (re.compile(r"\b(useradd|adduser|usermod|groupadd)\b"), "account management", ["T1136.001"]),
    (re.compile(r"\bcrontab\b|/etc/cron"), "scheduled task modification", ["T1053.003"]),
    (re.compile(r"authorized_keys"), "SSH key manipulation", ["T1021.004"]),
    (
        re.compile(r"\b(shred|truncate)\b|>\s*/var/log/|\brm\b.*/var/log/"),
        "log destruction",
        ["T1070.002"],
    ),
    (re.compile(r"\bhistory\s+-c\b|\.bash_history"), "shell history tampering", ["T1070.002"]),
]


@register
class AccountCreationDetection(Detection):
    rule_id: ClassVar[str] = "THN-0010"
    title: ClassVar[str] = "New account created"
    severity: ClassVar[Severity] = Severity.MEDIUM
    description: ClassVar[str] = "A local account was created — a common persistence mechanism."
    attack_techniques: ClassVar[list[str]] = ["T1136.001"]

    def run(self, timeline: Timeline) -> Iterator[Finding]:
        for event in timeline.of_type(EventType.ACCOUNT_CREATED):
            name = event.user or event.metadata.get("name") or "<unknown>"
            yield Finding(
                rule_id=self.rule_id,
                title=f"Account '{name}' created",
                severity=self.severity,
                description=(
                    f"Local account '{name}' was created at "
                    f"{event.timestamp.strftime('%Y-%m-%d %H:%M:%S')} UTC. "
                    "Confirm this was an authorised change."
                ),
                events=[event],
                attack_techniques=list(self.attack_techniques),
                metadata={"account": name, **event.metadata},
            )


@register
class PrivilegedGroupDetection(Detection):
    rule_id: ClassVar[str] = "THN-0011"
    title: ClassVar[str] = "Account added to privileged group"
    severity: ClassVar[Severity] = Severity.HIGH
    description: ClassVar[str] = "A user was granted membership of an administrative group."
    attack_techniques: ClassVar[list[str]] = ["T1098", "T1548.003"]

    def run(self, timeline: Timeline) -> Iterator[Finding]:
        for event in timeline.of_type(EventType.GROUP_MEMBER_ADDED):
            group = str(event.metadata.get("group", "")).lower()
            if group not in PRIVILEGED_GROUPS:
                continue
            user = event.user or "<unknown>"
            yield Finding(
                rule_id=self.rule_id,
                title=f"'{user}' added to privileged group '{group}'",
                severity=self.severity,
                description=(
                    f"'{user}' was granted membership of '{group}', conferring "
                    "administrative privileges."
                ),
                events=[event],
                attack_techniques=list(self.attack_techniques),
                metadata={"account": user, "group": group},
            )


@register
class BackdoorAccountDetection(Detection):
    rule_id: ClassVar[str] = "THN-0012"
    title: ClassVar[str] = "Backdoor account created and privileged"
    severity: ClassVar[Severity] = Severity.CRITICAL
    description: ClassVar[str] = (
        "An account was created and granted administrative access shortly after."
    )
    attack_techniques: ClassVar[list[str]] = ["T1136.001", "T1098"]

    def run(self, timeline: Timeline) -> Iterator[Finding]:
        created = {e.user: e for e in timeline.of_type(EventType.ACCOUNT_CREATED) if e.user}
        if not created:
            return

        for grant in timeline.of_type(EventType.GROUP_MEMBER_ADDED):
            group = str(grant.metadata.get("group", "")).lower()
            if group not in PRIVILEGED_GROUPS or grant.user not in created:
                continue

            creation = created[grant.user]
            if grant.timestamp < creation.timestamp:
                continue
            gap = grant.timestamp - creation.timestamp

            yield Finding(
                rule_id=self.rule_id,
                title=f"Backdoor account '{grant.user}' created with admin rights",
                severity=self.severity,
                description=(
                    f"Account '{grant.user}' was created and added to '{group}' "
                    f"{int(gap.total_seconds())}s later. The tight sequence is "
                    "characteristic of an attacker establishing persistence rather than "
                    "routine administration."
                ),
                events=[creation, grant],
                attack_techniques=list(self.attack_techniques),
                metadata={
                    "account": grant.user,
                    "group": group,
                    "seconds_between": int(gap.total_seconds()),
                },
            )


@register
class SensitiveSudoDetection(Detection):
    rule_id: ClassVar[str] = "THN-0013"
    title: ClassVar[str] = "Sensitive command via sudo"
    severity: ClassVar[Severity] = Severity.HIGH
    description: ClassVar[str] = "A privileged command matching a known abuse pattern was executed."
    attack_techniques: ClassVar[list[str]] = ["T1548.003"]

    def run(self, timeline: Timeline) -> Iterator[Finding]:
        for event in timeline.of_type(EventType.PRIVILEGE_ESCALATION):
            command = str(event.metadata.get("command", ""))
            if not command:
                continue

            for pattern, reason, techniques in SENSITIVE_COMMANDS:
                if not pattern.search(command):
                    continue
                user = event.user or "<unknown>"
                yield Finding(
                    rule_id=self.rule_id,
                    title=f"{reason.capitalize()} by '{user}' via sudo",
                    severity=self.severity,
                    description=(
                        f"'{user}' ran a privileged command flagged as {reason}:\n    {command}"
                    ),
                    events=[event],
                    attack_techniques=[*self.attack_techniques, *techniques],
                    metadata={
                        "account": user,
                        "command": command,
                        "reason": reason,
                        "target_user": event.metadata.get("target"),
                    },
                )
                break
