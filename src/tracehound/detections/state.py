"""State-artifact detections (THN-0040..0044).

These reason over the :class:`~tracehound.factbase.FactBase` rather than the timeline.
They answer a different question from the event rules: not "what did the attacker do", but
"what did they leave behind" — a standing account, grant, key or unit that will let them
back in long after the logs have rolled over. Each rule states the innocent reading
alongside the suspicious one, because a system account with a login shell or a second UID-0
entry can, occasionally, be legitimate.
"""

from __future__ import annotations

import re
from collections.abc import Iterator
from typing import ClassVar

from ..config import Config
from ..factbase import FactBase
from ..models import Finding, Severity
from .base import FactDetection, register_fact

# Shells that mean "this account cannot log in interactively". Anything else on a system
# account is the thing worth surfacing.
NOLOGIN_SHELLS = frozenset(
    {"/usr/sbin/nologin", "/sbin/nologin", "/bin/false", "/usr/bin/false", "/dev/null", ""}
)

# Interactive shells, matched on basename so /bin/bash and /usr/bin/bash are one thing.
LOGIN_SHELL_NAMES = frozenset({"sh", "bash", "zsh", "dash", "ksh", "fish", "csh", "tcsh", "ash"})

# Key algorithms no longer considered safe. DSA keys are 1024-bit by definition and
# OpenSSH disables them by default; a live one is either very old or freshly planted.
DEPRECATED_KEY_TYPES = frozenset({"ssh-dss"})

# Directories any user can write to. A unit or forced command running from here is running
# code the owner of the file may not control.
WORLD_WRITABLE_ROOTS = ("/tmp", "/var/tmp", "/dev/shm")

# Interpreters that turn a forced SSH command or a unit ExecStart into arbitrary execution.
_INTERPRETER_RE = re.compile(
    r"\b(bash|sh|zsh|dash|ksh|python[0-9.]*|perl|ruby|php|nc|ncat|netcat|socat)\b"
)

_UID_ROOT = "0"
_SYSTEM_UID_MAX = 1000


def _int(value: str | None) -> int | None:
    if value is None:
        return None
    try:
        return int(value)
    except ValueError:
        return None


def _exec_path(directive: str) -> str:
    """The executable a systemd Exec* directive runs, past its ``-@+!:`` prefixes."""
    body = directive.lstrip("-@+!:").strip()
    return body.split()[0] if body else ""


def _under_world_writable(path: str) -> bool:
    return any(path == root or path.startswith(root + "/") for root in WORLD_WRITABLE_ROOTS)


@register_fact
class DuplicateRootDetection(FactDetection):
    rule_id: ClassVar[str] = "THN-0040"
    title: ClassVar[str] = "Multiple accounts with UID 0"
    severity: ClassVar[Severity] = Severity.CRITICAL
    description: ClassVar[str] = (
        "More than one account, or a non-root account, holds UID 0 — full root authority "
        "under a second name."
    )
    attack_techniques: ClassVar[list[str]] = ["T1136.001", "T1078.003"]

    def run(self, facts: FactBase, config: Config) -> Iterator[Finding]:
        root_facts = [
            f
            for f in facts.with_attribute("uid")
            if f.value == _UID_ROOT and f.kind == "account" and not config.account_allowed(f.name)
        ]
        names = [f.name for f in root_facts]
        # One account named root with UID 0 is the expected state, not a finding.
        if names == ["root"] or not names:
            return

        others = [n for n in names if n != "root"]
        yield Finding(
            rule_id=self.rule_id,
            title=f"UID 0 shared by {len(names)} account(s): {', '.join(names)}",
            severity=self.severity,
            description=(
                f"Accounts {', '.join(names)} all map to UID 0. Any of them has complete "
                "root authority. A second UID-0 account is a classic, durable backdoor — "
                "it survives password changes and rarely shows up in a casual user review. "
                "The benign cause is a deliberately configured alternate root; confirm "
                f"{', '.join(others) or 'each entry'} was created on purpose."
            ),
            facts=root_facts,
            attack_techniques=list(self.attack_techniques),
            metadata={"accounts": names},
        )


@register_fact
class UnexpectedSudoGrantDetection(FactDetection):
    rule_id: ClassVar[str] = "THN-0041"
    title: ClassVar[str] = "Unexpected sudoers grant"
    severity: ClassVar[Severity] = Severity.HIGH
    description: ClassVar[str] = (
        "A sudoers rule grants passwordless or full root access to a non-standard principal."
    )
    attack_techniques: ClassVar[list[str]] = ["T1548.003"]

    def run(self, facts: FactBase, config: Config) -> Iterator[Finding]:
        for subject in facts.of_kind("sudo"):
            who = subject.split(":", 1)[1]
            if who == "Defaults":
                continue

            principal = who[1:] if who.startswith("%") else who
            if config.account_allowed(principal):
                continue

            spec = facts.value(subject, "spec") or ""
            commands = facts.value(subject, "commands") or ""
            nopasswd = facts.value(subject, "nopasswd") == "true"
            grants_all = any(tok == "ALL" for tok in re.split(r"[,\s]+", commands))

            is_expected_admin = who == "root" or (
                who.startswith("%") and config.is_privileged_group(principal)
            )

            reasons: list[str] = []
            if nopasswd:
                reasons.append("passwordless (NOPASSWD)")
            if grants_all and not is_expected_admin:
                reasons.append("full command access to a non-standard principal")
            if not reasons:
                continue

            spec_facts = facts.for_subject(subject)
            yield Finding(
                rule_id=self.rule_id,
                title=f"sudoers grant to '{who}': {', '.join(reasons)}",
                severity=self.severity,
                description=(
                    f"The sudoers rule for '{who}' is {' and '.join(reasons)}:\n    {spec}\n"
                    "Passwordless or wildcard sudo is a common way to keep root access "
                    "quietly. If this is a deployment or automation account, add it to "
                    "service_accounts to silence this."
                ),
                facts=spec_facts,
                attack_techniques=list(self.attack_techniques),
                metadata={"principal": who, "reasons": reasons, "spec": spec},
            )


@register_fact
class SuspiciousAuthorizedKeyDetection(FactDetection):
    rule_id: ClassVar[str] = "THN-0042"
    title: ClassVar[str] = "Suspicious authorised SSH key"
    severity: ClassVar[Severity] = Severity.HIGH
    description: ClassVar[str] = (
        "An authorised SSH key uses a deprecated algorithm or forces execution of an interpreter."
    )
    attack_techniques: ClassVar[list[str]] = ["T1098.004", "T1021.004"]

    def run(self, facts: FactBase, config: Config) -> Iterator[Finding]:
        for subject in facts.of_kind("sshkey"):
            key_facts = facts.for_subject(subject)
            account = facts.value(subject, "account")
            if account and config.account_allowed(account):
                continue

            keytype = facts.value(subject, "type") or "?"
            options = facts.value(subject, "options") or ""
            comment = facts.value(subject, "comment") or ""

            reason = ""
            severity = self.severity
            if _INTERPRETER_RE.search(options):
                reason = "forces execution of an interpreter via a command= option"
                severity = Severity.HIGH
            elif keytype in DEPRECATED_KEY_TYPES:
                reason = f"uses the deprecated {keytype} (DSA) algorithm"
                severity = Severity.MEDIUM
            if not reason:
                continue

            where = f" authorising '{account}'" if account else ""
            label = comment or facts.value(subject, "fingerprint") or "<no comment>"
            yield Finding(
                rule_id=self.rule_id,
                title=f"Authorised key '{label}'{where} {reason}",
                severity=severity,
                description=(
                    f"An authorised SSH key{where} {reason}.\n"
                    f"    type={keytype}  comment={comment or '<none>'}\n"
                    f"    options={options or '<none>'}\n"
                    "A forced-command key that launches a shell is a backdoor; a DSA key is "
                    "weak enough that its presence is itself worth questioning. Verify the "
                    "key belongs to someone who should have access."
                ),
                facts=key_facts,
                attack_techniques=list(self.attack_techniques),
                metadata={"key": label, "type": keytype, "account": account, "reason": reason},
            )


@register_fact
class UnitFromWorldWritableDetection(FactDetection):
    rule_id: ClassVar[str] = "THN-0043"
    title: ClassVar[str] = "systemd unit runs from a world-writable path"
    severity: ClassVar[Severity] = Severity.HIGH
    description: ClassVar[str] = (
        "A systemd unit executes a binary from /tmp, /var/tmp or /dev/shm — a location any "
        "user can overwrite."
    )
    attack_techniques: ClassVar[list[str]] = ["T1543.002"]

    _EXEC_ATTRS = ("exec_start", "exec_start_pre", "exec_start_post", "exec_reload")

    def run(self, facts: FactBase, config: Config) -> Iterator[Finding]:
        for subject in facts.of_kind("unit"):
            unit = subject.split(":", 1)[1]
            hits: list[tuple[str, str, str]] = []  # (attribute, path, directive)

            for attr in self._EXEC_ATTRS:
                for directive in facts.values(subject, attr):
                    path = _exec_path(directive)
                    if _under_world_writable(path):
                        hits.append((attr, path, directive))

            workdir = facts.value(subject, "working_directory")
            if workdir and _under_world_writable(workdir):
                hits.append(("working_directory", workdir, workdir))

            if not hits:
                continue

            attr, path, directive = hits[0]
            unit_facts = facts.for_subject(subject)
            yield Finding(
                rule_id=self.rule_id,
                title=f"Unit '{unit}' runs from world-writable {path}",
                severity=self.severity,
                description=(
                    f"The unit '{unit}' has {attr} pointing into a world-writable "
                    f"directory:\n    {directive}\n"
                    "Any local user can replace the target, so the unit runs whatever they "
                    "put there — with the unit's privileges, on every start. Legitimate "
                    "software installs to /usr or /opt, never /tmp."
                ),
                facts=unit_facts,
                attack_techniques=list(self.attack_techniques),
                metadata={"unit": unit, "path": path, "directive": directive},
            )


@register_fact
class ServiceAccountLoginShellDetection(FactDetection):
    rule_id: ClassVar[str] = "THN-0044"
    title: ClassVar[str] = "Service account has a login shell"
    severity: ClassVar[Severity] = Severity.MEDIUM
    description: ClassVar[str] = (
        "A system account (UID below 1000) has an interactive login shell instead of nologin."
    )
    attack_techniques: ClassVar[list[str]] = ["T1136.001"]

    def run(self, facts: FactBase, config: Config) -> Iterator[Finding]:
        for subject in facts.of_kind("account"):
            name = subject.split(":", 1)[1]
            if name == "root" or config.account_allowed(name):
                continue

            uid = _int(facts.value(subject, "uid"))
            shell = facts.value(subject, "shell") or ""
            if uid is None or not (0 < uid < _SYSTEM_UID_MAX):
                continue

            basename = shell.rsplit("/", 1)[-1]
            if shell in NOLOGIN_SHELLS or basename not in LOGIN_SHELL_NAMES:
                continue

            account_facts = facts.for_subject(subject)
            yield Finding(
                rule_id=self.rule_id,
                title=f"Service account '{name}' (UID {uid}) has shell {shell}",
                severity=self.severity,
                description=(
                    f"'{name}' is a system account (UID {uid}) yet its login shell is "
                    f"{shell}, not nologin. Daemon accounts do not need to log in, and "
                    "giving one a shell is a quiet way to gain a usable, low-profile "
                    "account. Confirm this account is meant to be interactive; if it is a "
                    "known service, add it to service_accounts."
                ),
                facts=account_facts,
                attack_techniques=list(self.attack_techniques),
                metadata={"account": name, "uid": uid, "shell": shell},
            )


__all__ = [
    "DuplicateRootDetection",
    "ServiceAccountLoginShellDetection",
    "SuspiciousAuthorizedKeyDetection",
    "UnexpectedSudoGrantDetection",
    "UnitFromWorldWritableDetection",
]
