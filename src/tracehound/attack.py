"""Minimal MITRE ATT&CK lookup for the techniques this tool reports.

Deliberately a static table rather than a dependency on the full ATT&CK dataset: the
tool references a small, stable subset, and a hard-coded map keeps the package free of
runtime downloads and multi-megabyte JSON.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class Technique:
    technique_id: str
    name: str
    tactic: str
    tactic_id: str

    @property
    def url(self) -> str:
        path = self.technique_id.replace(".", "/")
        return f"https://attack.mitre.org/techniques/{path}/"


_TECHNIQUES: dict[str, Technique] = {
    t.technique_id: t
    for t in (
        Technique("T1110", "Brute Force", "Credential Access", "TA0006"),
        Technique("T1110.001", "Brute Force: Password Guessing", "Credential Access", "TA0006"),
        Technique("T1110.003", "Brute Force: Password Spraying", "Credential Access", "TA0006"),
        Technique("T1078", "Valid Accounts", "Defense Evasion", "TA0005"),
        Technique("T1136", "Create Account", "Persistence", "TA0003"),
        Technique("T1136.001", "Create Account: Local Account", "Persistence", "TA0003"),
        Technique("T1098", "Account Manipulation", "Persistence", "TA0003"),
        Technique("T1548.003", "Sudo and Sudo Caching", "Privilege Escalation", "TA0004"),
        Technique(
            "T1003.008",
            "OS Credential Dumping: /etc/passwd and /etc/shadow",
            "Credential Access",
            "TA0006",
        ),
        Technique("T1105", "Ingress Tool Transfer", "Command and Control", "TA0011"),
        Technique(
            "T1059.004", "Command and Scripting Interpreter: Unix Shell", "Execution", "TA0002"
        ),
        Technique("T1053.003", "Scheduled Task/Job: Cron", "Persistence", "TA0003"),
        Technique(
            "T1070.002",
            "Indicator Removal: Clear Linux or Mac System Logs",
            "Defense Evasion",
            "TA0005",
        ),
        Technique(
            "T1070.003",
            "Indicator Removal: Clear Command History",
            "Defense Evasion",
            "TA0005",
        ),
        Technique("T1021.004", "Remote Services: SSH", "Lateral Movement", "TA0008"),
        Technique("T1595", "Active Scanning", "Reconnaissance", "TA0043"),
        Technique(
            "T1552.001",
            "Unsecured Credentials: Credentials In Files",
            "Credential Access",
            "TA0006",
        ),
    )
}


def lookup(technique_id: str) -> Technique | None:
    return _TECHNIQUES.get(technique_id)


def describe(technique_id: str) -> str:
    """Return ``T1110 — Brute Force (Credential Access)``, or the bare id if unknown."""
    technique = lookup(technique_id)
    if technique is None:
        return technique_id
    return f"{technique.technique_id} — {technique.name} ({technique.tactic})"
