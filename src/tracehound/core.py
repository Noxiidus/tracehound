"""High-level API — the entry point most callers actually want."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from .detections import run_all
from .models import Finding
from .parsers import ParseContext, parser_for
from .timeline import Timeline


@dataclass(slots=True)
class ScanResult:
    timeline: Timeline
    findings: list[Finding]
    parsed: dict[Path, str] = field(default_factory=dict)
    skipped: dict[Path, str] = field(default_factory=dict)


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


def scan(paths: list[Path], *, year: int | None = None) -> ScanResult:
    """Parse every recognised artifact under ``paths`` and run all detections.

    Unrecognised files are recorded in ``ScanResult.skipped`` rather than raising —
    a triage tool pointed at ``/var/log`` will meet plenty of files it cannot read,
    and that is not an error worth aborting the whole run for.
    """
    ctx = ParseContext(default_year=year)
    timeline = Timeline()
    result = ScanResult(timeline=timeline, findings=[])

    for file_path in collect_files(paths):
        parser = parser_for(file_path)
        if parser is None:
            result.skipped[file_path] = "no parser matched"
            continue
        try:
            timeline.add(parser.parse(file_path, ctx))
        except (OSError, ValueError) as exc:
            result.skipped[file_path] = f"{type(exc).__name__}: {exc}"
            continue
        result.parsed[file_path] = parser.name

    timeline.sort()
    result.findings = run_all(timeline)
    return result
