"""Parser for a log2timeline / plaso ``l2tcsv`` super-timeline.

The counterpart to :func:`tracehound.export.render_l2tcsv`. Reading a super-timeline back
in means tracehound's detections can run over a timeline that already fuses filesystem MACB
timestamps, browser history and registry activity with the auth events tracehound parses
itself — a strictly richer timeline than either tool builds alone.

The format is the fixed 17-column CSV log2timeline emits; the parser is keyed off that exact
header, so it never mistakes tracehound's own flat CSV export (a different, seven-column
shape) for a super-timeline. Rows whose timezone is neither UTC nor an explicit numeric
offset are skipped rather than guessed at — a super-timeline is normally exported in UTC,
and inventing a zone would reintroduce exactly the local-time error this project forbids.
"""

from __future__ import annotations

import csv
import re
from collections.abc import Iterator
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import ClassVar

from ..export import L2T_COLUMNS
from ..models import Event, EventType
from .base import ParseContext, Parser, register

_OFFSET_RE = re.compile(r"^(?P<sign>[+-])(?P<hh>\d{2}):?(?P<mm>\d{2})$")
_EXTRA_RE = re.compile(r"\s*;\s*")

_EVENT_TYPES = {e.value for e in EventType}


def _tzinfo(name: str) -> timezone | None:
    """UTC, blank or a numeric offset -> a fixed tz; anything else -> None (skip the row)."""
    cleaned = name.strip()
    if cleaned in {"", "UTC", "Z"}:
        return timezone.utc
    match = _OFFSET_RE.match(cleaned)
    if match is None:
        return None
    delta = timedelta(hours=int(match.group("hh")), minutes=int(match.group("mm")))
    return timezone(-delta if match.group("sign") == "-" else delta)


def _parse_extra(extra: str) -> dict[str, str]:
    pairs: dict[str, str] = {}
    for chunk in _EXTRA_RE.split(extra.strip()):
        key, sep, value = chunk.partition(":")
        if sep and key.strip():
            pairs[key.strip()] = value.strip()
    return pairs


@register
class L2tCsvParser(Parser):
    name = "l2tcsv"
    description = "log2timeline / plaso super-timeline (l2tcsv)"
    priority: ClassVar[int] = 5  # a unique header; check it before any text parser

    def sniff(self, path: Path) -> bool:
        try:
            with path.open("r", encoding="utf-8", errors="replace") as fh:
                first = fh.readline().strip()
        except (OSError, UnicodeDecodeError):
            return False
        return first == ",".join(L2T_COLUMNS)

    def parse(self, path: Path, ctx: ParseContext) -> Iterator[Event]:
        with path.open("r", encoding="utf-8", errors="replace", newline="") as fh:
            reader = csv.reader(fh)
            try:
                header = next(reader)
            except StopIteration:
                return
            if header != L2T_COLUMNS:
                return

            for row in reader:
                if len(row) != len(L2T_COLUMNS):
                    continue
                fields = dict(zip(L2T_COLUMNS, row, strict=True))

                tz = _tzinfo(fields["timezone"])
                if tz is None:
                    continue
                try:
                    naive = datetime.strptime(
                        f"{fields['date']} {fields['time']}", "%m/%d/%Y %H:%M:%S"
                    )
                except ValueError:
                    continue
                ts = naive.replace(tzinfo=tz)

                extra = _parse_extra(fields["extra"])
                raw_type = fields["type"]
                event_type = EventType(raw_type) if raw_type in _EVENT_TYPES else EventType.OTHER
                source = fields["sourcetype"].removeprefix("tracehound ").strip() or (
                    fields["source"] or self.name
                )
                user = fields["user"]
                pid = extra.get("pid")

                # Every extra pair that isn't already a typed field becomes metadata, so a
                # detection that keys on, say, the sudo command or the added group sees the
                # same structured value the original parser emitted.
                typed = {"source_ip", "process", "pid", "terminal"}
                metadata: dict[str, object] = {
                    key: (int(val) if val.isdigit() else val)
                    for key, val in extra.items()
                    if key not in typed
                }
                metadata.update(
                    {
                        "macb": fields["MACB"],
                        "filename": fields["filename"],
                        "l2t_format": fields["format"],
                        "notes": fields["notes"],
                        "origin": "l2tcsv",
                    }
                )

                yield Event(
                    timestamp=ts,
                    source=source or self.name,
                    event_type=event_type,
                    message=fields["desc"] or fields["short"],
                    user=user if user not in {"", "-"} else None,
                    source_ip=extra.get("source_ip"),
                    process=extra.get("process"),
                    pid=int(pid) if pid and pid.isdigit() else None,
                    terminal=extra.get("terminal"),
                    raw=",".join(row),
                    metadata=metadata,
                )
