"""High-level API — the entry point most callers actually want."""

from __future__ import annotations

import hashlib
import os
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from . import __version__
from .config import Config
from .detections import order_findings, run_all, run_all_facts
from .detections.base import Detection
from .factbase import FactBase
from .models import Finding
from .parsers import ParseContext, fact_parser_for, parser_for
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
    fact_count: int = 0
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
            "fact_count": self.fact_count,
            "skipped_reason": self.skipped_reason,
        }


@dataclass(slots=True)
class ScanResult:
    timeline: Timeline
    findings: list[Finding]
    factbase: FactBase = field(default_factory=FactBase)
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


def _walk_files(root: Path) -> list[Path]:
    """Every file under ``root``, sorted, without following directory symlinks.

    ``Path.rglob`` follows symlinked directories, so a triage run pointed at ``/var/log`` or
    a mounted image containing a symlink cycle would loop forever generating paths before the
    de-duplication below ever runs. ``os.walk(followlinks=False)`` — its own default — cannot
    loop. Symlinked *files* are still collected; only descending through a symlinked directory
    is refused, which is the safe behaviour for untrusted evidence trees anyway.
    """
    out: list[Path] = []
    for dirpath, _dirs, filenames in os.walk(root, followlinks=False):
        base = Path(dirpath)
        out.extend(base / name for name in filenames)
    out.sort()
    return out


def collect_files(paths: list[Path]) -> list[Path]:
    """Expand directories into their files, preserving caller order and de-duplicating."""
    found: list[Path] = []
    seen: set[Path] = set()

    for path in paths:
        candidates = _walk_files(path) if path.is_dir() else [path]
        for candidate in candidates:
            try:
                resolved = candidate.resolve()
            except OSError:
                resolved = candidate
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
    factbase = FactBase()
    result = ScanResult(timeline=timeline, findings=[], factbase=factbase)

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

        # Event parsers are tried first; only if none claims the file do we offer it to
        # the state parsers. The two never overlap — a state artifact is not valid syslog —
        # so order is a small optimisation, not a correctness question.
        parser = parser_for(file_path)
        if parser is not None:
            try:
                events = list(parser.parse(file_path, ctx))
            except (OSError, ValueError) as exc:
                record.skipped_reason = f"{type(exc).__name__}: {exc}"
                result.artifacts.append(record)
                continue
            record.parser = parser.name
            record.event_count = timeline.add(events)
            result.artifacts.append(record)
            continue

        fact_parser = fact_parser_for(file_path)
        if fact_parser is not None:
            try:
                facts = list(fact_parser.parse(file_path, ctx))
            except (OSError, ValueError) as exc:
                record.skipped_reason = f"{type(exc).__name__}: {exc}"
                result.artifacts.append(record)
                continue
            factbase.add(facts)
            record.parser = fact_parser.name
            record.fact_count = len(facts)
            result.artifacts.append(record)
            continue

        record.skipped_reason = "no parser matched"
        result.artifacts.append(record)

    timeline.sort()
    factbase.sort()

    active = config or Config()
    findings = run_all(timeline, active, extra_detections)
    findings.extend(run_all_facts(factbase, active))
    result.findings = order_findings(findings)
    return result
