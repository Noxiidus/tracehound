"""Parser for the utmp family of binary login databases: ``wtmp``, ``utmp``, ``btmp``.

Record layout (glibc, 64-bit ``struct utmp``, 384 bytes)::

    offset  size  field
    0       4     ut_type
    4       4     ut_pid
    8      32     ut_line      terminal
    40      4     ut_id
    44     32     ut_user
    76    256     ut_host      remote host or kernel version
    332     4     ut_exit
    336     4     ut_session
    340     4     ut_tv.tv_sec
    344     4     ut_tv.tv_usec
    348    16     ut_addr_v6
    364    20     __unused

Timestamps are stored as a 32-bit Unix epoch and are therefore always UTC. Tooling that
renders them with ``localtime`` silently shifts an entire investigation, which is why
this parser converts explicitly and never touches the host timezone.
"""

from __future__ import annotations

import ipaddress
import struct
from collections.abc import Iterator
from datetime import datetime, timezone
from pathlib import Path
from typing import ClassVar

from ..models import Event, EventType
from .base import ParseContext, Parser, register

RECORD_SIZE = 384

_OFF_TYPE = 0
_OFF_PID = 4
_OFF_LINE = 8
_OFF_ID = 40
_OFF_USER = 44
_OFF_HOST = 76
_OFF_SESSION = 336
_OFF_SEC = 340
_OFF_USEC = 344
_OFF_ADDR = 348

_LEN_LINE = 32
_LEN_ID = 4
_LEN_USER = 32
_LEN_HOST = 256

EMPTY = 0
RUN_LVL = 1
BOOT_TIME = 2
NEW_TIME = 3
OLD_TIME = 4
INIT_PROCESS = 5
LOGIN_PROCESS = 6
USER_PROCESS = 7
DEAD_PROCESS = 8
ACCOUNTING = 9

_TYPE_NAMES = {
    EMPTY: "EMPTY",
    RUN_LVL: "RUN_LVL",
    BOOT_TIME: "BOOT_TIME",
    NEW_TIME: "NEW_TIME",
    OLD_TIME: "OLD_TIME",
    INIT_PROCESS: "INIT",
    LOGIN_PROCESS: "LOGIN",
    USER_PROCESS: "USER",
    DEAD_PROCESS: "DEAD",
    ACCOUNTING: "ACCOUNTING",
}


def _cstr(buf: bytes, offset: int, length: int) -> str:
    raw = buf[offset : offset + length]
    return raw.split(b"\0", 1)[0].decode("utf-8", "replace").strip()


def _addr(buf: bytes) -> str | None:
    """Decode ut_addr_v6. Only the first word is set for IPv4; all-zero means unset."""
    words = struct.unpack_from("<4I", buf, _OFF_ADDR)
    if not any(words):
        return None
    if not any(words[1:]):
        return str(ipaddress.IPv4Address(struct.pack("<I", words[0])))
    return str(ipaddress.IPv6Address(struct.pack("<4I", *words)))


@register
class UtmpParser(Parser):
    name = "wtmp"
    description = "Binary login records (wtmp / utmp / btmp)"
    priority: ClassVar[int] = 10  # binary, unambiguous — check before any text parser

    def sniff(self, path: Path) -> bool:
        try:
            size = path.stat().st_size
        except OSError:
            return False
        # A trailing partial record is accepted deliberately: truncation is exactly what
        # log tampering looks like here, and refusing the file would discard the evidence.
        if size < RECORD_SIZE:
            return False

        # A structurally valid record has a known type and a plausible epoch.
        try:
            with path.open("rb") as fh:
                head = fh.read(RECORD_SIZE)
        except OSError:
            return False
        if len(head) < RECORD_SIZE:
            return False

        rec_type = struct.unpack_from("<I", head, _OFF_TYPE)[0]
        seconds = struct.unpack_from("<I", head, _OFF_SEC)[0]
        return rec_type in _TYPE_NAMES and 946_684_800 < seconds < 4_102_444_800

    def parse(self, path: Path, ctx: ParseContext) -> Iterator[Event]:
        is_btmp = path.name.startswith("btmp")
        source = "btmp" if is_btmp else self.name
        last_seen: datetime | None = None

        with path.open("rb") as fh:
            while True:
                buf = fh.read(RECORD_SIZE)
                if len(buf) < RECORD_SIZE:
                    if buf:
                        yield self._truncation_event(path, source, len(buf), last_seen)
                    break

                rec_type = struct.unpack_from("<I", buf, _OFF_TYPE)[0]
                seconds = struct.unpack_from("<I", buf, _OFF_SEC)[0]
                if rec_type == EMPTY or seconds == 0:
                    continue

                micros = struct.unpack_from("<I", buf, _OFF_USEC)[0]
                try:
                    ts = datetime.fromtimestamp(seconds, tz=timezone.utc).replace(
                        microsecond=min(micros, 999_999)
                    )
                except (OverflowError, OSError, ValueError):
                    continue

                user = _cstr(buf, _OFF_USER, _LEN_USER)
                line = _cstr(buf, _OFF_LINE, _LEN_LINE)
                host = _cstr(buf, _OFF_HOST, _LEN_HOST)
                pid = struct.unpack_from("<I", buf, _OFF_PID)[0]
                session = struct.unpack_from("<I", buf, _OFF_SESSION)[0]

                event_type, message = self._classify(rec_type, user, line, host, is_btmp)
                last_seen = ts

                yield Event(
                    timestamp=ts,
                    source=source,
                    event_type=event_type,
                    message=message,
                    user=user or None,
                    source_ip=_addr(buf) or (host if _looks_like_ip(host) else None),
                    pid=pid or None,
                    terminal=line or None,
                    raw=f"{_TYPE_NAMES.get(rec_type, rec_type)} {user} {line} {host}".strip(),
                    metadata={
                        "record_type": _TYPE_NAMES.get(rec_type, str(rec_type)),
                        "id": _cstr(buf, _OFF_ID, _LEN_ID),
                        "session": session,
                        "host": host,
                    },
                )

    def _truncation_event(
        self, path: Path, source: str, trailing: int, last_seen: datetime | None
    ) -> Event:
        """Flag a file that ends mid-record.

        These databases are only ever appended to in whole ``RECORD_SIZE`` units, so a
        partial tail means something rewrote the file rather than the system writing it.
        The event is anchored to the last intact record because that is the latest moment
        the file is known to have been consistent.
        """
        if last_seen is None:
            try:
                last_seen = datetime.fromtimestamp(path.stat().st_mtime, tz=timezone.utc)
            except OSError:
                last_seen = datetime.now(timezone.utc)

        return Event(
            timestamp=last_seen,
            source=source,
            event_type=EventType.OTHER,
            message=f"{path.name} ends mid-record ({trailing} trailing bytes)",
            raw=f"truncated: {trailing} bytes short of a {RECORD_SIZE}-byte record",
            metadata={
                "anomaly": "truncated",
                "trailing_bytes": trailing,
                "record_size": RECORD_SIZE,
                "file": path.name,
            },
        )

    def _classify(
        self, rec_type: int, user: str, line: str, host: str, is_btmp: bool
    ) -> tuple[EventType, str]:
        if is_btmp:
            return EventType.LOGIN_FAILURE, f"Failed login for {user or '<unknown>'} on {line}"
        if rec_type == USER_PROCESS:
            where = f" from {host}" if host else ""
            return EventType.LOGIN_SUCCESS, f"Login for {user or '<unknown>'} on {line}{where}"
        if rec_type == DEAD_PROCESS:
            return EventType.LOGOUT, f"Session ended on {line}"
        if rec_type == BOOT_TIME:
            return EventType.BOOT, f"System boot ({host})" if host else "System boot"
        if rec_type == RUN_LVL:
            kind = user or "runlevel"
            event = EventType.SHUTDOWN if kind.startswith("shutdown") else EventType.SERVICE_EVENT
            return event, f"Runlevel change: {kind}"
        if rec_type in {INIT_PROCESS, LOGIN_PROCESS}:
            return EventType.SERVICE_EVENT, f"{_TYPE_NAMES[rec_type]} process on {line}"
        return EventType.OTHER, f"{_TYPE_NAMES.get(rec_type, rec_type)} record"


def _looks_like_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return False
    return True
