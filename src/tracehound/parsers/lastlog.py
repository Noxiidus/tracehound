"""Parser for ``/var/log/lastlog``.

Unlike ``wtmp``, lastlog is not a journal — it is a fixed-size array indexed by UID,
holding only the *most recent* login per user::

    offset  size  field
    0       4     ll_time    Unix epoch
    4      32     ll_line    terminal
    36    256     ll_host    remote host

Record N belongs to UID N, so the file is mostly sparse zeroes and its size reflects the
highest UID on the system rather than the number of logins. A zero timestamp means that
UID has never logged in, not that the record is corrupt.
"""

from __future__ import annotations

import struct
from collections.abc import Iterator
from datetime import datetime, timezone
from pathlib import Path
from typing import ClassVar

from ..models import Event, EventType
from .base import ParseContext, Parser, register

RECORD_SIZE = 292

_OFF_TIME = 0
_OFF_LINE = 4
_OFF_HOST = 36
_LEN_LINE = 32
_LEN_HOST = 256

# Sanity bounds for a plausible login epoch: 2000-01-01 .. 2100-01-01.
_MIN_EPOCH = 946_684_800
_MAX_EPOCH = 4_102_444_800


def _cstr(buf: bytes, offset: int, length: int) -> str:
    return buf[offset : offset + length].split(b"\0", 1)[0].decode("utf-8", "replace").strip()


@register
class LastlogParser(Parser):
    name = "lastlog"
    description = "Most recent login per UID (lastlog)"
    priority: ClassVar[int] = 10  # binary format, check before any text parser

    def sniff(self, path: Path) -> bool:
        if path.name != "lastlog":
            # The layout is too generic to identify by content alone — a 292-byte
            # multiple of mostly-zero bytes could be anything. Require the name.
            return False
        try:
            size = path.stat().st_size
        except OSError:
            return False
        return size > 0 and size % RECORD_SIZE == 0

    def parse(self, path: Path, ctx: ParseContext) -> Iterator[Event]:
        with path.open("rb") as fh:
            uid = -1
            while True:
                buf = fh.read(RECORD_SIZE)
                uid += 1
                if len(buf) < RECORD_SIZE:
                    break

                seconds = struct.unpack_from("<I", buf, _OFF_TIME)[0]
                if not _MIN_EPOCH < seconds < _MAX_EPOCH:
                    continue  # never logged in, or an implausible value

                line = _cstr(buf, _OFF_LINE, _LEN_LINE)
                host = _cstr(buf, _OFF_HOST, _LEN_HOST)
                where = f" from {host}" if host else ""

                yield Event(
                    timestamp=datetime.fromtimestamp(seconds, tz=timezone.utc),
                    source=self.name,
                    event_type=EventType.LOGIN_SUCCESS,
                    message=f"Most recent login for UID {uid} on {line or '?'}{where}",
                    user=None,
                    source_ip=host or None,
                    terminal=line or None,
                    raw=f"uid={uid} line={line} host={host}",
                    metadata={"uid": uid, "host": host, "record": "lastlog"},
                )
