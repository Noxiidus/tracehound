from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from synth import syslog_line, write_auth_log
from tracehound import build_case
from tracehound.case import ClockConfidence
from tracehound.cli import main
from tracehound.config import Config
from tracehound.report import render_case_json, render_case_text

BASE = datetime(2024, 3, 6, 6, 0, 0, tzinfo=timezone.utc)
ATTACKER = "65.2.161.68"


def _brute_force_lines(start: datetime, ip: str, count: int = 14) -> list[str]:
    return [
        syslog_line(
            start + timedelta(seconds=i),
            "sshd",
            f"Failed password for invalid user admin from {ip} port {5000 + i} ssh2",
            pid=2000 + i,
        )
        for i in range(count)
    ]


def _host_dir(tmp_path: Path, name: str, lines: list[str]) -> Path:
    directory = tmp_path / name
    directory.mkdir(parents=True, exist_ok=True)
    write_auth_log(directory / "auth.log", lines)
    return directory


@pytest.fixture
def two_hosts(tmp_path: Path) -> dict[str, list[Path]]:
    """web01 is hit first, then db01 twenty minutes later, by the same address."""
    web = _host_dir(
        tmp_path,
        "web01",
        [
            *_brute_force_lines(BASE, ATTACKER),
            syslog_line(
                BASE + timedelta(seconds=20),
                "sshd",
                f"Accepted password for root from {ATTACKER} port 5100 ssh2",
                pid=2100,
            ),
        ],
    )
    db = _host_dir(
        tmp_path,
        "db01",
        [
            *_brute_force_lines(BASE + timedelta(minutes=20), ATTACKER),
            syslog_line(
                BASE + timedelta(minutes=20, seconds=20),
                "sshd",
                f"Accepted password for root from {ATTACKER} port 5200 ssh2",
                pid=2200,
            ),
        ],
    )
    return {"web01": [web], "db01": [db]}


class TestCaseAssembly:
    def test_builds_all_hosts(self, two_hosts: dict[str, list[Path]]) -> None:
        case = build_case(two_hosts, year=2024)

        assert len(case.hosts) == 2
        assert {h.name for h in case.hosts} == {"web01", "db01"}
        assert all(len(h.result.timeline) > 0 for h in case.hosts)

    def test_merged_timeline_is_ordered(self, two_hosts: dict[str, list[Path]]) -> None:
        merged = build_case(two_hosts, year=2024).merged_timeline()
        stamps = [e.timestamp for e in merged]
        assert stamps == sorted(stamps)

    def test_events_are_tagged_with_host(self, two_hosts: dict[str, list[Path]]) -> None:
        merged = build_case(two_hosts, year=2024).merged_timeline()
        assert {e.metadata["host"] for e in merged} == {"web01", "db01"}

    def test_per_host_findings_survive(self, two_hosts: dict[str, list[Path]]) -> None:
        case = build_case(two_hosts, year=2024)
        for host in case.hosts:
            assert any(f.rule_id == "THN-0001" for f in host.result.findings)


class TestClockOffsets:
    def test_offset_shifts_events(self, two_hosts: dict[str, list[Path]]) -> None:
        plain = build_case(two_hosts, year=2024)
        shifted = build_case(two_hosts, year=2024, offsets={"db01": timedelta(seconds=90)})

        plain_db = plain.host("db01")
        shifted_db = shifted.host("db01")
        assert plain_db is not None and shifted_db is not None

        first_plain = min(e.timestamp for e in plain_db.adjusted_events())
        first_shifted = min(e.timestamp for e in shifted_db.adjusted_events())
        assert first_shifted - first_plain == timedelta(seconds=90)

    def test_declared_offset_marks_clock_verified(self, two_hosts: dict[str, list[Path]]) -> None:
        case = build_case(
            two_hosts,
            year=2024,
            offsets={
                "web01": timedelta(0),
                "db01": timedelta(seconds=5),
            },
        )
        assert case.all_clocks_verified
        assert all(h.clock_confidence == ClockConfidence.DECLARED for h in case.hosts)

    def test_missing_offset_is_assumed_not_verified(self, two_hosts: dict[str, list[Path]]) -> None:
        case = build_case(two_hosts, year=2024, offsets={"web01": timedelta(0)})
        assert not case.all_clocks_verified

        db = case.host("db01")
        assert db is not None
        assert db.clock_confidence == ClockConfidence.ASSUMED
        assert db.clock_offset == timedelta(0)

    def test_offsets_are_never_inferred(self, two_hosts: dict[str, list[Path]]) -> None:
        """Silence about a clock must stay silence — not a guess dressed up as a fact."""
        case = build_case(two_hosts, year=2024)
        assert all(h.clock_offset == timedelta(0) for h in case.hosts)
        assert all(not h.clock_verified for h in case.hosts)


class TestCrossHostDetections:
    def test_detects_shared_attacker(self, two_hosts: dict[str, list[Path]]) -> None:
        case = build_case(two_hosts, year=2024)
        found = [f for f in case.findings if f.rule_id == "THN-1001"]

        assert len(found) == 1
        assert found[0].metadata["source_ip"] == ATTACKER
        assert sorted(found[0].metadata["hosts"]) == ["db01", "web01"]

    def test_identifies_patient_zero_when_margin_is_wide(
        self, two_hosts: dict[str, list[Path]]
    ) -> None:
        case = build_case(two_hosts, year=2024)
        found = [f for f in case.findings if f.rule_id == "THN-1003"]

        assert len(found) == 1
        assert found[0].metadata["candidate_patient_zero"] == "web01"
        assert found[0].metadata["ordering_established"] is True

    def test_hedges_when_hosts_are_seconds_apart(self, tmp_path: Path) -> None:
        """Within drift range and with unverified clocks, ordering must not be asserted."""
        web = _host_dir(
            tmp_path,
            "web01",
            [
                *_brute_force_lines(BASE, ATTACKER),
                syslog_line(
                    BASE + timedelta(seconds=20),
                    "sshd",
                    f"Accepted password for root from {ATTACKER} port 1 ssh2",
                    pid=1,
                ),
            ],
        )
        db = _host_dir(
            tmp_path,
            "db01",
            [
                *_brute_force_lines(BASE + timedelta(seconds=30), ATTACKER),
                syslog_line(
                    BASE + timedelta(seconds=50),
                    "sshd",
                    f"Accepted password for root from {ATTACKER} port 2 ssh2",
                    pid=2,
                ),
            ],
        )
        case = build_case({"web01": [web], "db01": [db]}, year=2024)

        patient_zero = [f for f in case.findings if f.rule_id == "THN-1003"]
        assert len(patient_zero) == 1
        assert patient_zero[0].metadata["ordering_established"] is False
        assert "candidate rather than a conclusion" in patient_zero[0].description

    def test_clock_warning_raised_for_tight_events(self, tmp_path: Path) -> None:
        web = _host_dir(tmp_path, "web01", _brute_force_lines(BASE, ATTACKER))
        db = _host_dir(tmp_path, "db01", _brute_force_lines(BASE + timedelta(seconds=10), ATTACKER))
        case = build_case({"web01": [web], "db01": [db]}, year=2024)

        warnings = [f for f in case.findings if f.rule_id == "THN-1004"]
        assert len(warnings) == 1
        assert sorted(warnings[0].metadata["unverified_hosts"]) == ["db01", "web01"]

    def test_no_clock_warning_when_declared(self, tmp_path: Path) -> None:
        web = _host_dir(tmp_path, "web01", _brute_force_lines(BASE, ATTACKER))
        db = _host_dir(tmp_path, "db01", _brute_force_lines(BASE + timedelta(seconds=10), ATTACKER))
        case = build_case(
            {"web01": [web], "db01": [db]},
            year=2024,
            offsets={"web01": timedelta(0), "db01": timedelta(0)},
        )
        assert all(f.rule_id != "THN-1004" for f in case.findings)

    def test_detects_lateral_movement(self, tmp_path: Path) -> None:
        web = _host_dir(
            tmp_path,
            "web01",
            [
                syslog_line(BASE, "useradd", "new user: name=svcbackup, UID=1099", pid=10),
            ],
        )
        db = _host_dir(
            tmp_path,
            "db01",
            [
                syslog_line(
                    BASE + timedelta(minutes=15),
                    "sshd",
                    f"Accepted password for svcbackup from {ATTACKER} port 9 ssh2",
                    pid=11,
                ),
            ],
        )
        case = build_case({"web01": [web], "db01": [db]}, year=2024)
        found = [f for f in case.findings if f.rule_id == "THN-1002"]

        assert len(found) == 1
        assert found[0].metadata["account"] == "svcbackup"
        assert found[0].metadata["origin_host"] == "web01"
        assert found[0].metadata["target_host"] == "db01"
        assert found[0].metadata["ordering_established"] is True

    def test_lateral_movement_hedges_inside_drift(self, tmp_path: Path) -> None:
        web = _host_dir(
            tmp_path,
            "web01",
            [
                syslog_line(BASE, "useradd", "new user: name=svcbackup, UID=1099", pid=10),
            ],
        )
        db = _host_dir(
            tmp_path,
            "db01",
            [
                syslog_line(
                    BASE + timedelta(seconds=30),
                    "sshd",
                    f"Accepted password for svcbackup from {ATTACKER} port 9 ssh2",
                    pid=11,
                ),
            ],
        )
        case = build_case({"web01": [web], "db01": [db]}, year=2024)
        (found,) = [f for f in case.findings if f.rule_id == "THN-1002"]

        assert found.metadata["ordering_established"] is False
        assert "not established" in found.description

    def test_allowlisted_ip_suppresses_cross_host(self, two_hosts: dict[str, list[Path]]) -> None:
        case = build_case(two_hosts, year=2024, config=Config(known_ips={ATTACKER}))
        assert all(f.rule_id not in {"THN-1001", "THN-1003"} for f in case.findings)

    def test_single_host_yields_no_cross_host_findings(self, tmp_path: Path) -> None:
        web = _host_dir(tmp_path, "web01", _brute_force_lines(BASE, ATTACKER))
        case = build_case({"web01": [web]}, year=2024)
        assert case.findings == []


class TestCaseReports:
    def test_text_report(self, two_hosts: dict[str, list[Path]]) -> None:
        case = build_case(two_hosts, year=2024)
        output = render_case_text(case)

        assert "tracehound case report" in output
        assert "web01" in output and "db01" in output
        assert "NOT all verified" in output
        assert "Per-host findings" in output

    def test_json_report(self, two_hosts: dict[str, list[Path]]) -> None:
        case = build_case(two_hosts, year=2024)
        payload = json.loads(render_case_json(case))

        assert payload["summary"]["host_count"] == 2
        assert payload["summary"]["all_clocks_verified"] is False
        assert len(payload["hosts"]) == 2
        assert all("artifacts" in h for h in payload["hosts"])


class TestCaseCli:
    def test_case_command(
        self, two_hosts: dict[str, list[Path]], capsys: pytest.CaptureFixture[str]
    ) -> None:
        args = ["case", "--year", "2024"]
        for name, paths in two_hosts.items():
            args += ["--host", f"{name}={paths[0]}"]

        assert main(args) == 0
        assert "tracehound case report" in capsys.readouterr().out

    def test_case_json_with_offsets(
        self, two_hosts: dict[str, list[Path]], capsys: pytest.CaptureFixture[str]
    ) -> None:
        args = ["case", "--year", "2024", "-f", "json"]
        for name, paths in two_hosts.items():
            args += ["--host", f"{name}={paths[0]}", "--clock-offset", f"{name}=0"]

        assert main(args) == 0
        payload = json.loads(capsys.readouterr().out)
        assert payload["summary"]["all_clocks_verified"] is True

    def test_malformed_host_arg(self, capsys: pytest.CaptureFixture[str]) -> None:
        assert main(["case", "--host", "nonsense"]) == 2
        assert "NAME=VALUE" in capsys.readouterr().err

    def test_offset_for_unknown_host(
        self, two_hosts: dict[str, list[Path]], capsys: pytest.CaptureFixture[str]
    ) -> None:
        paths = two_hosts["web01"]
        code = main(["case", "--host", f"web01={paths[0]}", "--clock-offset", "ghost=5"])

        assert code == 2
        assert "unknown host" in capsys.readouterr().err

    def test_missing_path(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
        code = main(["case", "--host", f"web01={tmp_path / 'nope'}"])
        assert code == 2
        assert "no such file" in capsys.readouterr().err
