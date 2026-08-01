from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from synth import syslog_line, write_auth_log
from tracehound.case import build_case_from_manifests
from tracehound.cli import main
from tracehound.core import sha256_file
from tracehound.manifest import Manifest, ManifestError

BASE = datetime(2024, 3, 6, 6, 0, 0, tzinfo=timezone.utc)
ATTACKER = "65.2.161.68"


def _brute_force(start: datetime, count: int = 14) -> list[str]:
    return [
        syslog_line(
            start + timedelta(seconds=i),
            "sshd",
            f"Failed password for invalid user admin from {ATTACKER} port {5000 + i} ssh2",
            pid=2000 + i,
        )
        for i in range(count)
    ]


def _collection(
    root: Path,
    hostname: str,
    lines: list[str],
    *,
    offset_seconds: float | None = 0.0,
    corrupt: bool = False,
) -> Path:
    """Write a collection directory that mirrors what tracehound-collect produces."""
    base = root / hostname
    artifacts = base / "artifacts"
    artifacts.mkdir(parents=True)

    log = write_auth_log(artifacts / "auth.log", lines)
    digest = sha256_file(log)
    size = log.stat().st_size

    if corrupt:
        # Simulate the evidence changing after collection but before analysis.
        log.write_text(log.read_text(encoding="utf-8") + "tampered\n", encoding="utf-8")

    manifest = {
        "tool": "tracehound-collect",
        "version": "0.5.0",
        "hostname": hostname,
        "collected_by": "root",
        "started_at": "2024-03-06T07:00:00Z",
        "finished_at": "2024-03-06T07:00:05Z",
        "hash_algorithm": "sha256",
        "clock": {
            "host_utc": "2024-03-06T07:00:00Z",
            "reference_utc": "2024-03-06T07:00:00" if offset_seconds is not None else None,
            "offset_seconds": offset_seconds,
            "note": "measured" if offset_seconds is not None else "no reference supplied",
        },
        "artifacts": [
            {
                "path": "artifacts/auth.log",
                "source": "/var/log/auth.log",
                "sha256": digest,
                "size": size,
            }
        ],
        "skipped": [{"source": "/var/log/btmp", "reason": "not present"}],
    }
    path = base / "manifest.json"
    path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    return path


class TestManifestLoading:
    def test_loads_fields(self, tmp_path: Path) -> None:
        path = _collection(tmp_path, "web01", _brute_force(BASE), offset_seconds=-137)
        manifest = Manifest.load(path)

        assert manifest.hostname == "web01"
        assert manifest.collected_by == "root"
        assert manifest.clock_offset == timedelta(seconds=-137)
        assert manifest.clock_measured
        assert len(manifest.artifacts) == 1
        assert len(manifest.skipped) == 1

    def test_null_offset_means_unmeasured(self, tmp_path: Path) -> None:
        path = _collection(tmp_path, "web01", _brute_force(BASE), offset_seconds=None)
        manifest = Manifest.load(path)

        assert manifest.clock_offset is None
        assert not manifest.clock_measured

    def test_artifact_paths_resolve_relative_to_manifest(self, tmp_path: Path) -> None:
        path = _collection(tmp_path, "web01", _brute_force(BASE))
        manifest = Manifest.load(path)

        (resolved,) = manifest.artifact_paths()
        assert resolved.exists()
        assert resolved.name == "auth.log"

    def test_missing_hostname_rejected(self, tmp_path: Path) -> None:
        path = tmp_path / "manifest.json"
        path.write_text(json.dumps({"artifacts": []}), encoding="utf-8")
        with pytest.raises(ManifestError, match="'hostname' is required"):
            Manifest.load(path)

    def test_bad_json_rejected(self, tmp_path: Path) -> None:
        path = tmp_path / "manifest.json"
        path.write_text("{not json", encoding="utf-8")
        with pytest.raises(ManifestError, match="invalid JSON"):
            Manifest.load(path)

    def test_bad_offset_type_rejected(self, tmp_path: Path) -> None:
        path = tmp_path / "manifest.json"
        path.write_text(
            json.dumps({"hostname": "h", "clock": {"offset_seconds": "soon"}}), encoding="utf-8"
        )
        with pytest.raises(ManifestError, match="must be a number or null"):
            Manifest.load(path)

    def test_non_numeric_size_rejected(self, tmp_path: Path) -> None:
        """A garbage artifact 'size' must raise ManifestError, not a bare ValueError that
        escapes and crashes verify/case."""
        path = tmp_path / "manifest.json"
        path.write_text(
            json.dumps({"hostname": "h", "artifacts": [{"path": "a", "size": "huge"}]}),
            encoding="utf-8",
        )
        with pytest.raises(ManifestError, match="'size' must be a number"):
            Manifest.load(path)

    def test_numeric_string_size_accepted(self, tmp_path: Path) -> None:
        path = tmp_path / "manifest.json"
        path.write_text(
            json.dumps({"hostname": "h", "artifacts": [{"path": "a", "size": "1024"}]}),
            encoding="utf-8",
        )
        assert Manifest.load(path).artifacts[0].size == 1024


class TestIntegrityVerification:
    def test_intact_collection_passes(self, tmp_path: Path) -> None:
        path = _collection(tmp_path, "web01", _brute_force(BASE))
        assert Manifest.load(path).verify() == []

    def test_modified_artifact_is_caught(self, tmp_path: Path) -> None:
        """The window between collection and analysis is exactly what this closes."""
        path = _collection(tmp_path, "web01", _brute_force(BASE), corrupt=True)
        issues = Manifest.load(path).verify()

        assert len(issues) == 1
        assert "does not match" in issues[0].problem
        assert issues[0].observed_sha256 != issues[0].artifact.sha256

    def test_missing_artifact_is_caught(self, tmp_path: Path) -> None:
        path = _collection(tmp_path, "web01", _brute_force(BASE))
        (path.parent / "artifacts" / "auth.log").unlink()

        issues = Manifest.load(path).verify()
        assert len(issues) == 1
        assert "missing" in issues[0].problem

    def test_absent_digest_is_reported(self, tmp_path: Path) -> None:
        path = _collection(tmp_path, "web01", _brute_force(BASE))
        data = json.loads(path.read_text(encoding="utf-8"))
        data["artifacts"][0]["sha256"] = ""
        path.write_text(json.dumps(data), encoding="utf-8")

        issues = Manifest.load(path).verify()
        assert len(issues) == 1
        assert "no digest recorded" in issues[0].problem


class TestCaseFromManifests:
    def test_measured_offsets_establish_ordering(self, tmp_path: Path) -> None:
        """The whole point of the collector: hedged orderings become established ones."""
        web = _collection(
            tmp_path,
            "web01",
            [
                *_brute_force(BASE),
                syslog_line(
                    BASE + timedelta(seconds=20),
                    "sshd",
                    f"Accepted password for root from {ATTACKER} port 1 ssh2",
                    pid=1,
                ),
            ],
            offset_seconds=0,
        )
        db = _collection(
            tmp_path,
            "db01",
            [
                *_brute_force(BASE + timedelta(seconds=40)),
                syslog_line(
                    BASE + timedelta(seconds=60),
                    "sshd",
                    f"Accepted password for root from {ATTACKER} port 2 ssh2",
                    pid=2,
                ),
            ],
            offset_seconds=0,
        )

        case = build_case_from_manifests([Manifest.load(web), Manifest.load(db)], year=2024)

        assert case.all_clocks_verified
        patient_zero = [f for f in case.findings if f.rule_id == "THN-1003"]
        assert len(patient_zero) == 1
        # Only 40 seconds apart — without measured clocks this would be hedged.
        assert patient_zero[0].metadata["ordering_established"] is True
        assert patient_zero[0].metadata["candidate_patient_zero"] == "web01"

    def test_unmeasured_manifest_stays_hedged(self, tmp_path: Path) -> None:
        web = _collection(tmp_path, "web01", _brute_force(BASE), offset_seconds=None)
        db = _collection(
            tmp_path, "db01", _brute_force(BASE + timedelta(seconds=40)), offset_seconds=None
        )
        case = build_case_from_manifests([Manifest.load(web), Manifest.load(db)], year=2024)

        assert not case.all_clocks_verified
        assert any(f.rule_id == "THN-1004" for f in case.findings)

    def test_offset_is_actually_applied(self, tmp_path: Path) -> None:
        web = _collection(tmp_path, "web01", _brute_force(BASE), offset_seconds=600)
        case = build_case_from_manifests([Manifest.load(web)], year=2024)

        host = case.host("web01")
        assert host is not None
        assert host.clock_offset == timedelta(seconds=600)
        first = min(e.timestamp for e in host.adjusted_events())
        assert first == BASE + timedelta(seconds=600)


class TestManifestCli:
    def test_verify_ok(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
        path = _collection(tmp_path, "web01", _brute_force(BASE))
        assert main(["verify", str(path)]) == 0

        out = capsys.readouterr().out
        assert "OK" in out
        assert "web01" in out

    def test_verify_detects_tampering(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        path = _collection(tmp_path, "web01", _brute_force(BASE), corrupt=True)
        assert main(["verify", str(path)]) == 1
        assert "FAILED" in capsys.readouterr().err

    def test_case_from_manifest(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
        web = _collection(tmp_path, "web01", _brute_force(BASE), offset_seconds=0)
        db = _collection(
            tmp_path, "db01", _brute_force(BASE + timedelta(minutes=30)), offset_seconds=0
        )

        code = main(
            [
                "case",
                "--manifest",
                str(web),
                "--manifest",
                str(db),
                "--year",
                "2024",
                "-f",
                "json",
            ]
        )
        assert code == 0

        payload = json.loads(capsys.readouterr().out)
        assert payload["summary"]["all_clocks_verified"] is True
        assert payload["summary"]["host_count"] == 2

    def test_case_refuses_tampered_evidence(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        web = _collection(tmp_path, "web01", _brute_force(BASE), corrupt=True)
        code = main(["case", "--manifest", str(web), "--year", "2024"])

        assert code == 3
        assert "do not match the manifest" in capsys.readouterr().err

    def test_skip_verify_allows_it_through(self, tmp_path: Path) -> None:
        web = _collection(tmp_path, "web01", _brute_force(BASE), corrupt=True)
        code = main(["case", "--manifest", str(web), "--year", "2024", "--skip-verify"])
        assert code == 0

    def test_case_requires_a_source(self, capsys: pytest.CaptureFixture[str]) -> None:
        assert main(["case"]) == 2
        assert "at least one --host or --manifest" in capsys.readouterr().err
