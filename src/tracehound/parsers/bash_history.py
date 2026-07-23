"""Parser for shell history files (``.bash_history``, ``.zsh_history``).

Shell history is one of the most useful artifacts on a compromised host and one of the
worst-structured. Two formats occur:

*Timestamped* — written when ``HISTTIMEFORMAT`` is set. Each command is preceded by a
comment holding a Unix epoch::

    #1709707077
    cat /etc/shadow

*Bare* — the default. Commands only, with no timing information whatsoever::

    cat /etc/shadow

Bare history cannot be placed on a timeline honestly. Rather than silently inventing
times, this parser anchors such entries to the file's modification time, records their
original ordering in ``metadata["sequence"]``, and flags them with
``metadata["timestamp_precision"] = "file_mtime"``. Consumers can then present them as
"ordered but undated" instead of implying a precision that does not exist.
"""

from __future__ import annotations

from collections.abc import Iterator
from datetime import datetime, timezone
from pathlib import Path
from typing import ClassVar

from ..models import Event, EventType
from .base import ParseContext, Parser, register

_NAMES = {".bash_history", "bash_history", ".zsh_history", "zsh_history", ".sh_history"}
_MIN_EPOCH = 946_684_800
_MAX_EPOCH = 4_102_444_800


@register
class ShellHistoryParser(Parser):
    name = "shell_history"
    description = "Shell command history (.bash_history / .zsh_history)"
    priority: ClassVar[int] = 20

    def sniff(self, path: Path) -> bool:
        if path.name not in _NAMES:
            return False
        try:
            return path.stat().st_size > 0
        except OSError:
            return False

    def parse(self, path: Path, ctx: ParseContext) -> Iterator[Event]:
        try:
            mtime = datetime.fromtimestamp(path.stat().st_mtime, tz=timezone.utc)
        except OSError:
            mtime = datetime.now(timezone.utc)

        user = self._owner_from_path(path)
        pending: datetime | None = None
        sequence = 0

        with path.open("r", encoding="utf-8", errors="replace") as fh:
            for raw_line in fh:
                line = raw_line.rstrip("\n")
                if not line.strip():
                    continue

                epoch = self._history_timestamp(line)
                if epoch is not None:
                    pending = epoch
                    continue

                sequence += 1
                dated = pending is not None
                timestamp = pending if pending is not None else mtime
                pending = None

                yield Event(
                    timestamp=timestamp,
                    source=self.name,
                    event_type=EventType.COMMAND_EXECUTED,
                    message=line.strip(),
                    user=user,
                    raw=line,
                    metadata={
                        "command": line.strip(),
                        "sequence": sequence,
                        "timestamp_precision": "exact" if dated else "file_mtime",
                        "history_file": path.name,
                    },
                )

    @staticmethod
    def _history_timestamp(line: str) -> datetime | None:
        """Return the epoch encoded by a ``#1709707077`` history marker, if present."""
        if not line.startswith("#"):
            return None
        candidate = line[1:].strip()
        if not candidate.isdigit():
            return None
        seconds = int(candidate)
        if not _MIN_EPOCH < seconds < _MAX_EPOCH:
            return None
        return datetime.fromtimestamp(seconds, tz=timezone.utc)

    @staticmethod
    def _owner_from_path(path: Path) -> str | None:
        """Infer the account from ``/home/<user>/.bash_history`` or ``/root/...``."""
        parts = [p for p in path.resolve().parts]
        for index, part in enumerate(parts[:-1]):
            if part == "home" and index + 1 < len(parts) - 1:
                return parts[index + 1]
            if part == "root":
                return "root"
        return None
