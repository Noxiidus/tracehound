"""Parser for systemd unit files (``*.service`` and friends).

Unit files are INI-like: ``[Section]`` headers over ``Key=Value`` lines. Only a handful of
keys decide what a unit actually does, and those are what a triage run wants — most of all
``ExecStart``, which is the command the unit runs, and the identity it runs as. A unit
pointing at ``/tmp`` or running a shell one-liner is a classic persistence mechanism that
leaves no event behind until it fires.

Each unit becomes a subject ``unit:<filename>``. A key that legitimately repeats
(``ExecStartPre``, or several ``ExecStart`` lines) yields one fact per occurrence, so no
directive is lost. Values are kept verbatim, including systemd's ``-``/``@``/``+``/``!``
prefixes, because those prefixes change the meaning and a detection needs to see them.
"""

from __future__ import annotations

import re
from collections.abc import Iterator
from pathlib import Path
from typing import ClassVar

from ..models import Fact
from .base import FactParser, ParseContext, register_fact

UNIT_SUFFIXES = frozenset(
    {".service", ".socket", ".timer", ".mount", ".path", ".target", ".automount"}
)

# The keys worth surfacing, mapped to the fact attribute they become. Everything else in
# the file is ignored on purpose — a unit has dozens of tuning knobs that say nothing about
# what it runs or who it runs as.
_KEYS = {
    "ExecStart": "exec_start",
    "ExecStartPre": "exec_start_pre",
    "ExecStartPost": "exec_start_post",
    "ExecStop": "exec_stop",
    "ExecReload": "exec_reload",
    "User": "user",
    "Group": "group",
    "WorkingDirectory": "working_directory",
    "Type": "type",
    "Restart": "restart",
    "Description": "description",
    "WantedBy": "wanted_by",
    "RequiredBy": "required_by",
    "Environment": "environment",
    "EnvironmentFile": "environment_file",
}

_SECTION_RE = re.compile(r"^\[(?P<name>[^\]]+)\]\s*$")
_KV_RE = re.compile(r"^(?P<key>[A-Za-z][A-Za-z0-9]*)\s*=\s*(?P<value>.*)$")


@register_fact
class SystemdUnitParser(FactParser):
    name = "systemd_unit"
    description = "systemd unit file (*.service and friends)"
    priority: ClassVar[int] = 20

    def sniff(self, path: Path) -> bool:
        if path.suffix in UNIT_SUFFIXES:
            return True
        try:
            with path.open("r", encoding="utf-8", errors="replace") as fh:
                head = fh.read(2048)
        except (OSError, UnicodeDecodeError):
            return False
        # An oddly named unit still declares a systemd section and an ExecStart or Unit
        # header together; a plain INI config would not.
        return bool(re.search(r"^\[(Unit|Service|Install)\]", head, re.MULTILINE)) and (
            "ExecStart=" in head or "\n[Unit]" in f"\n{head}"
        )

    def parse(self, path: Path, ctx: ParseContext) -> Iterator[Fact]:
        subject = f"unit:{path.name}"
        section = ""
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return

        for raw_line in text.splitlines():
            line = raw_line.strip()
            if not line or line.startswith(("#", ";")):
                continue

            header = _SECTION_RE.match(line)
            if header is not None:
                section = header.group("name")
                continue

            kv = _KV_RE.match(line)
            if kv is None:
                continue
            key, value = kv.group("key"), kv.group("value").strip()
            attribute = _KEYS.get(key)
            if attribute is None or not value:
                continue

            yield Fact(
                subject=subject,
                attribute=attribute,
                value=value,
                source=self.name,
                metadata={"section": section, "key": key, "unit": path.name, "raw": line},
            )
