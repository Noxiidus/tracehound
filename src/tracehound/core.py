"""High-level API — the entry point most callers actually want."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from . import __version__
from .config import Config
from .detections import run_all
from .detections.base import Detection
from .models import Finding
from .parsers import ParseContext, parser_for
from .timeline import Timeline

_HASH_CHUNK = 1024 * 1024


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        while chunk := fh.read(_HASH_CHUNK):
            digest.update(chunk)
    return digest.hexdigest()


@dataclass(slots=True)
class ArtifactRecord:
    """What was done with one input file, and enough detail to prove it.

    A triage report that cannot say exactly which bytes it read is weak evidence.
    Recording the digest alongside the parser and event count makes the run
    reproducible and lets a reviewer confirm the artifact has not changed since.
    """

    path: Path
    size: int
    sha256: str
    parser: str | None = None
    event_count: int = 0
    skipped_reason: str | None = None

    @property
    def parsed(self) -> bool:
        return self.skipped_reason is None

    def to_dict(self) -> dict[str, Any]:
        return {
            "path": str(self.path),
            "size": self.size,
            "sha256": self.sha256,
            "parser": self.parser,
            "event_count": self.event_count,
            "skipped_reason": self.skipped_reason,
        }


@dataclass(slots=True)
class ScanResult:
    timeline: Timeline
    findings: list[Finding]
    artifacts: list[ArtifactRecord] = field(default_factory=list)
    started_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    tool_version: str = __version__

    @property
    def parsed(self) -> list[ArtifactRecord]:
        return [a for a in self.artifacts if a.parsed]

    @property
    def skipped(self) -> list[ArtifactRecord]:
        return [a for a in self.artifacts if not a.parsed]

    def provenance(self) -> dict[str, Any]:
        return {
            "tool": "tracehound",
            "tool_version": self.tool_version,
            "scanned_at": self.started_at.isoformat(),
            "artifacts": [a.to_dict() for a in self.artifacts],
        }


def collect_files(paths: list[Path]) -> list[Path]:
    """Expand directories into their files, preserving caller order and de-duplicating."""
    found: list[Path] = []
    seen: set[Path] = set()

    for path in paths:
        candidates = sorted(p for p in path.rglob("*") if p.is_file()) if path.is_dir() else [path]
        for candidate in candidates:
            resolved = candidate.resolve()
            if resolved not in seen:
                seen.add(resolved)
                found.append(candidate)
    return found


def scan(
    paths: list[Path],
    *,
    year: int | None = None,
    config: Config | None = None,
    extra_detections: list[Detection] | None = None,
) -> ScanResult:
    """Parse every recognised artifact under ``paths`` and run all detections.

    Unrecognised files are recorded rather than raising — a triage tool pointed at
    ``/var/log`` will meet plenty of files it cannot read, and that is not an error
    worth aborting the whole run for. Every file is still hashed and listed, so the
    report can account for what was examined and what was not.
    """
    ctx = ParseContext(default_year=year)
    timeline = Timeline()
    result = ScanResult(timeline=timeline, findings=[])

    for file_path in collect_files(paths):
        try:
            size = file_path.stat().st_size
            digest = sha256_file(file_path)
        except OSError as exc:
            result.artifacts.append(
                ArtifactRecord(
                    path=file_path,
                    size=-1,
                    sha256="",
                    skipped_reason=f"unreadable: {type(exc).__name__}",
                )
            )
            continue

        record = ArtifactRecord(path=file_path, size=size, sha256=digest)

        parser = parser_for(file_path)
        if parser is None:
            record.skipped_reason = "no parser matched"
            result.artifacts.append(record)
            continue

        try:
            events = list(parser.parse(file_path, ctx))
        except (OSError, ValueError) as exc:
            record.skipped_reason = f"{type(exc).__name__}: {exc}"
            result.artifacts.append(record)
            continue

        timeline.add(events)
        record.parser = parser.name
        record.event_count = len(events)
        result.artifacts.append(record)

    timeline.sort()
    result.findings = run_all(timeline, config or Config(), extra_detections)
    return result
