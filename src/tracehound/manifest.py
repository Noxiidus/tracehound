"""Collection manifests produced by ``tracehound-collect``.

The manifest closes two gaps that analysis alone cannot.

**Clock offset.** Cross-host ordering depends on knowing how far each machine's clock
drifted, and that is only measurable while the machine is still running. A manifest
carries the measurement taken at collection time, turning hedged orderings into
established ones.

**Integrity across the gap.** tracehound hashes artifacts when it reads them, which
proves nothing about what happened between collection and analysis — the interval where
evidence is copied, emailed and staged. Comparing the two digests closes that window, and
a mismatch is a serious finding in its own right.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from .core import sha256_file


class ManifestError(ValueError):
    """Raised when a manifest is malformed or unreadable."""


@dataclass(slots=True)
class ManifestArtifact:
    path: str
    source: str
    sha256: str
    size: int

    def resolve(self, base: Path) -> Path:
        return base / self.path


@dataclass(slots=True)
class IntegrityIssue:
    """A collected artifact that no longer matches its manifest entry."""

    artifact: ManifestArtifact
    problem: str
    observed_sha256: str | None = None

    def describe(self) -> str:
        if self.observed_sha256:
            return (
                f"{self.artifact.path}: {self.problem}\n"
                f"    manifest: {self.artifact.sha256}\n"
                f"    observed: {self.observed_sha256}"
            )
        return f"{self.artifact.path}: {self.problem}"


@dataclass(slots=True)
class Manifest:
    hostname: str
    base_dir: Path
    collected_by: str = "unknown"
    started_at: datetime | None = None
    finished_at: datetime | None = None
    clock_offset: timedelta | None = None
    clock_note: str = ""
    hash_algorithm: str = "sha256"
    artifacts: list[ManifestArtifact] = field(default_factory=list)
    skipped: list[dict[str, Any]] = field(default_factory=list)

    @property
    def clock_measured(self) -> bool:
        return self.clock_offset is not None

    def artifact_paths(self) -> list[Path]:
        """Existing artifact files, for handing to :func:`tracehound.scan`."""
        return [
            a.resolve(self.base_dir) for a in self.artifacts if a.resolve(self.base_dir).exists()
        ]

    def verify(self) -> list[IntegrityIssue]:
        """Re-hash every artifact and report anything that no longer matches.

        A mismatch means the evidence changed after it left the host. That is either a
        handling error or tampering, and either way it must be surfaced rather than
        quietly analysed as though nothing happened.
        """
        issues: list[IntegrityIssue] = []
        for artifact in self.artifacts:
            path = artifact.resolve(self.base_dir)
            if not path.exists():
                issues.append(IntegrityIssue(artifact, "missing from the collection"))
                continue
            if not artifact.sha256:
                issues.append(IntegrityIssue(artifact, "no digest recorded at collection time"))
                continue
            observed = sha256_file(path)
            if observed.lower() != artifact.sha256.lower():
                issues.append(
                    IntegrityIssue(artifact, "digest does not match the manifest", observed)
                )
        return issues

    @classmethod
    def load(cls, path: Path) -> Manifest:
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except OSError as exc:
            raise ManifestError(f"cannot read {path}: {exc}") from exc
        except json.JSONDecodeError as exc:
            raise ManifestError(f"invalid JSON in {path}: {exc}") from exc

        if not isinstance(data, dict):
            raise ManifestError(f"{path}: top level must be a mapping")

        hostname = str(data.get("hostname", "")).strip()
        if not hostname:
            raise ManifestError(f"{path}: 'hostname' is required")

        clock = data.get("clock") or {}
        if not isinstance(clock, dict):
            raise ManifestError(f"{path}: 'clock' must be a mapping")

        raw_offset = clock.get("offset_seconds")
        offset: timedelta | None = None
        if raw_offset is not None:
            if isinstance(raw_offset, bool) or not isinstance(raw_offset, (int, float)):
                raise ManifestError(f"{path}: clock.offset_seconds must be a number or null")
            offset = timedelta(seconds=float(raw_offset))

        entries = data.get("artifacts", [])
        if not isinstance(entries, list):
            raise ManifestError(f"{path}: 'artifacts' must be a list")

        artifacts: list[ManifestArtifact] = []
        for entry in entries:
            if not isinstance(entry, dict):
                raise ManifestError(f"{path}: each artifact must be a mapping")
            rel = str(entry.get("path", "")).strip()
            if not rel:
                raise ManifestError(f"{path}: an artifact entry has no 'path'")
            artifacts.append(
                ManifestArtifact(
                    path=rel,
                    source=str(entry.get("source", "")),
                    sha256=str(entry.get("sha256", "")),
                    size=int(entry.get("size", 0) or 0),
                )
            )

        skipped = data.get("skipped", [])
        if not isinstance(skipped, list):
            raise ManifestError(f"{path}: 'skipped' must be a list")

        return cls(
            hostname=hostname,
            base_dir=path.parent,
            collected_by=str(data.get("collected_by", "unknown")),
            started_at=_parse_time(data.get("started_at")),
            finished_at=_parse_time(data.get("finished_at")),
            clock_offset=offset,
            clock_note=str(clock.get("note", "")),
            hash_algorithm=str(data.get("hash_algorithm", "sha256")),
            artifacts=artifacts,
            skipped=[s for s in skipped if isinstance(s, dict)],
        )


def _parse_time(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)
