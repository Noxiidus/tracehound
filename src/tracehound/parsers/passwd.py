"""Parser for ``/etc/passwd``.

Seven colon-separated fields per line::

    name:password:uid:gid:gecos:home:shell

The ``password`` field is almost always ``x`` (the real hash lives in ``/etc/shadow``);
anything else is itself worth surfacing, so it is preserved verbatim as a fact rather than
discarded. Each account becomes one subject ``account:<name>`` carrying its uid, gid,
gecos, home and shell as separate attributes — the shape a detection wants when it asks
"which accounts have UID 0" without re-parsing the line.
"""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path
from typing import ClassVar

from ..models import Fact
from .base import FactParser, ParseContext, register_fact


def _looks_like_passwd(line: str) -> bool:
    parts = line.split(":")
    return len(parts) == 7 and parts[2].isdigit() and parts[3].isdigit()


@register_fact
class PasswdParser(FactParser):
    name = "passwd"
    description = "Local account database (/etc/passwd)"
    priority: ClassVar[int] = 20

    def sniff(self, path: Path) -> bool:
        named = path.name == "passwd"
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
                    if not _looks_like_passwd(stripped):
                        return False
                    # A named file needs only one good line; an unnamed one must be
                    # unambiguous, so require a couple before claiming it.
                    if named or checked >= 2:
                        return True
        except (OSError, UnicodeDecodeError):
            return False
        return False

    def parse(self, path: Path, ctx: ParseContext) -> Iterator[Fact]:
        with path.open("r", encoding="utf-8", errors="replace") as fh:
            for raw_line in fh:
                line = raw_line.strip()
                if not line or line.startswith("#") or not _looks_like_passwd(line):
                    continue

                name, password, uid, gid, gecos, home, shell = line.split(":")
                subject = f"account:{name}"
                meta = {"raw": line}
                attributes = [
                    ("uid", uid),
                    ("gid", gid),
                    ("shell", shell),
                    ("home", home),
                    # 'x' points at /etc/shadow and '*'/'!' lock the account; a hash here
                    # instead is a legacy or hand-edited password worth keeping visible.
                    ("password_field", password),
                ]
                if gecos:
                    attributes.append(("gecos", gecos))

                for attribute, value in attributes:
                    yield Fact(
                        subject=subject,
                        attribute=attribute,
                        value=value,
                        source=self.name,
                        metadata=meta,
                    )
