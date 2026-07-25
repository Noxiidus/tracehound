"""Parser for ``/etc/sudoers`` and ``/etc/sudoers.d/*``.

The sudoers grammar is large; this parser reads the part that matters for triage — the
user specifications that actually grant privilege — and records the rest verbatim rather
than pretending to fully understand it. A logical line has the shape::

    who   hosts = (runas) TAG: TAG: command_list

Each specification becomes a subject ``sudo:<who>``. The raw rule is always preserved as
``spec``; the fields a detection cares about (the run-as target, whether ``NOPASSWD`` is
set, the command list) are broken out as their own attributes. ``Defaults`` lines and the
various ``*_Alias`` definitions are kept too, under their own subjects, so nothing in the
file is silently dropped.

Line continuations (a trailing ``\\``) are joined before parsing, because a rule split
across two physical lines is still one grant.
"""

from __future__ import annotations

import re
from collections.abc import Iterator
from pathlib import Path
from typing import ClassVar

from ..models import Fact
from .base import FactParser, ParseContext, register_fact

_ALIAS_RE = re.compile(r"^(User_Alias|Runas_Alias|Host_Alias|Cmnd_Alias)\s+(\S+)\s*=\s*(.*)$")
_SPEC_RE = re.compile(r"^(?P<who>\S+)\s+(?P<hosts>[^=]+?)\s*=\s*(?P<rest>.+)$")
_RUNAS_RE = re.compile(r"^\(\s*(?P<runas>[^)]*)\)\s*(?P<rest>.*)$")
_TAG_RE = re.compile(r"^(NOPASSWD|PASSWD|NOEXEC|EXEC|SETENV|NOSETENV|LOG_INPUT|LOG_OUTPUT):\s*")


def _logical_lines(text: str) -> Iterator[str]:
    """Yield sudoers logical lines, joining trailing-backslash continuations."""
    buffer = ""
    for raw in text.splitlines():
        line = raw.rstrip("\n")
        if buffer:
            line = buffer + " " + line.strip()
            buffer = ""
        if line.endswith("\\"):
            buffer = line[:-1].rstrip()
            continue
        yield line


@register_fact
class SudoersParser(FactParser):
    name = "sudoers"
    description = "Sudo privilege policy (/etc/sudoers, sudoers.d)"
    priority: ClassVar[int] = 20

    def sniff(self, path: Path) -> bool:
        if path.name == "sudoers" or path.parent.name == "sudoers.d":
            return True
        try:
            with path.open("r", encoding="utf-8", errors="replace") as fh:
                head = fh.read(4096)
        except (OSError, UnicodeDecodeError):
            return False
        # A file we were not told is sudoers must show the two structures that only
        # sudoers has together: a Defaults line and a host=command specification.
        return "\nDefaults" in f"\n{head}" and bool(
            re.search(r"^\s*\S+\s+\S+\s*=\s*(\(|ALL|NOPASSWD|/)", head, re.MULTILINE)
        )

    def parse(self, path: Path, ctx: ParseContext) -> Iterator[Fact]:
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return

        for line in _logical_lines(text):
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue

            alias = _ALIAS_RE.match(stripped)
            if alias is not None:
                kind, alias_name, members = alias.groups()
                yield Fact(
                    subject=f"sudo_alias:{alias_name}",
                    attribute=kind,
                    value=members.strip(),
                    source=self.name,
                    metadata={"raw": stripped},
                )
                continue

            if stripped.startswith("Defaults"):
                yield Fact(
                    subject="sudo:Defaults",
                    attribute="option",
                    value=stripped[len("Defaults") :].lstrip("@:!").strip(),
                    source=self.name,
                    metadata={"raw": stripped},
                )
                continue

            spec = _SPEC_RE.match(stripped)
            if spec is None:
                continue

            who = spec.group("who")
            hosts = spec.group("hosts").strip()
            rest = spec.group("rest").strip()

            runas = ""
            runas_match = _RUNAS_RE.match(rest)
            if runas_match is not None:
                runas = runas_match.group("runas").strip()
                rest = runas_match.group("rest").strip()

            tags: list[str] = []
            while True:
                tag_match = _TAG_RE.match(rest)
                if tag_match is None:
                    break
                tags.append(tag_match.group(1))
                rest = rest[tag_match.end() :].lstrip()

            commands = rest.strip()
            subject = f"sudo:{who}"
            meta = {"raw": stripped, "hosts": hosts, "tags": tags}

            yield Fact(
                subject=subject, attribute="spec", value=stripped, source=self.name, metadata=meta
            )
            yield Fact(
                subject=subject,
                attribute="commands",
                value=commands,
                source=self.name,
                metadata=meta,
            )
            if runas:
                yield Fact(
                    subject=subject, attribute="runas", value=runas, source=self.name, metadata=meta
                )
            yield Fact(
                subject=subject,
                attribute="nopasswd",
                value="true" if "NOPASSWD" in tags else "false",
                source=self.name,
                metadata=meta,
            )
