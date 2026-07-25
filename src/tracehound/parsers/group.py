"""Parser for ``/etc/group``.

Four colon-separated fields per line::

    name:password:gid:member1,member2,...

Each group becomes a subject ``group:<name>`` carrying its gid and its member list. The
members matter for privilege review — an unexpected name in ``sudo``, ``wheel`` or
``docker`` is a standing grant of administrative access that no login event records.
"""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path
from typing import ClassVar

from ..models import Fact
from .base import FactParser, ParseContext, register_fact


def _looks_like_group(line: str) -> bool:
    parts = line.split(":")
    return len(parts) == 4 and parts[2].isdigit()


@register_fact
class GroupParser(FactParser):
    name = "group"
    description = "Local group database (/etc/group)"
    priority: ClassVar[int] = 20

    def sniff(self, path: Path) -> bool:
        named = path.name == "group"
        try:
            with path.open("r", encoding="utf-8", errors="replace") as fh:
                checked = 0
                for _ in range(40):
                    line = fh.readline()
                    if not line:
                        break
                    stripped = line.strip()
                    if not stripped or stripped.startswith("#"):
                        continue
                    checked += 1
                    if not _looks_like_group(stripped):
                        return False
                    if named or checked >= 3:
                        return True
        except (OSError, UnicodeDecodeError):
            return False
        return False

    def parse(self, path: Path, ctx: ParseContext) -> Iterator[Fact]:
        with path.open("r", encoding="utf-8", errors="replace") as fh:
            for raw_line in fh:
                line = raw_line.strip()
                if not line or line.startswith("#") or not _looks_like_group(line):
                    continue

                name, _password, gid, member_field = line.split(":")
                members = [m for m in member_field.split(",") if m]
                subject = f"group:{name}"

                yield Fact(
                    subject=subject,
                    attribute="gid",
                    value=gid,
                    source=self.name,
                    metadata={"raw": line},
                )
                yield Fact(
                    subject=subject,
                    attribute="members",
                    value=",".join(members),
                    source=self.name,
                    metadata={"members": members, "raw": line},
                )
