from __future__ import annotations

import json
from pathlib import Path

import pytest

from tracehound import scan
from tracehound.cli import main
from tracehound.report import render_html, render_json, render_text, render_timeline_csv


class TestReports:
    def test_text_report_lists_findings(self, scenario: tuple[Path, Path]) -> None:
        result = scan(list(scenario), year=2024)
        output = render_text(result.timeline, result.findings)

        assert "tracehound report" in output
        assert "CRITICAL" in output
        assert "cyberjunkie" in output

    def test_json_report_is_valid(self, scenario: tuple[Path, Path]) -> None:
        result = scan(list(scenario), year=2024)
        payload = json.loads(render_json(result.timeline, result.findings))

        assert payload["tool"] == "tracehound"
        assert payload["summary"]["finding_count"] == len(result.findings)
        assert all("rule_id" in f for f in payload["findings"])

    def test_json_can_omit_events(self, scenario: tuple[Path, Path]) -> None:
        result = scan(list(scenario), year=2024)
        payload = json.loads(render_json(result.timeline, result.findings, include_events=False))
        assert all("events" not in f for f in payload["findings"])

    def test_csv_has_header_and_rows(self, scenario: tuple[Path, Path]) -> None:
        result = scan(list(scenario), year=2024)
        rows = render_timeline_csv(result.timeline).strip().splitlines()

        assert rows[0].startswith("timestamp_utc,source,event_type")
        assert len(rows) == len(result.timeline) + 1

    def test_html_is_self_contained(self, scenario: tuple[Path, Path]) -> None:
        result = scan(list(scenario), year=2024)
        output = render_html(result.timeline, result.findings)

        assert output.startswith("<!doctype html>")
        assert "<script" not in output.lower()
        assert 'src="http' not in output

    def test_empty_report_is_honest(self, tmp_path: Path) -> None:
        from synth import write_auth_log

        path = write_auth_log(
            tmp_path / "auth.log",
            [
                "Mar  6 06:19:54 host sshd[1]: Accepted password for root from 10.0.0.5 port 1 ssh2",
            ],
        )
        result = scan([path], year=2024)
        output = render_text(result.timeline, result.findings)
        assert "not proof of a clean host" in output


class TestCli:
    def test_scan_text(
        self, scenario: tuple[Path, Path], capsys: pytest.CaptureFixture[str]
    ) -> None:
        code = main(["scan", str(scenario[0]), str(scenario[1]), "--year", "2024"])
        captured = capsys.readouterr()

        assert code == 0
        assert "tracehound report" in captured.out

    def test_scan_json_to_file(self, scenario: tuple[Path, Path], tmp_path: Path) -> None:
        out = tmp_path / "report.json"
        code = main(
            [
                "scan",
                str(scenario[0]),
                "--year",
                "2024",
                "-f",
                "json",
                "-o",
                str(out),
            ]
        )

        assert code == 0
        assert json.loads(out.read_text(encoding="utf-8"))["tool"] == "tracehound"

    def test_min_severity_filters(
        self, scenario: tuple[Path, Path], capsys: pytest.CaptureFixture[str]
    ) -> None:
        main(
            ["scan", str(scenario[0]), "--year", "2024", "-f", "json", "--min-severity", "critical"]
        )
        payload = json.loads(capsys.readouterr().out)

        assert payload["findings"]
        assert all(f["severity"] == "critical" for f in payload["findings"])

    def test_fail_on_findings_exit_code(self, scenario: tuple[Path, Path]) -> None:
        code = main(["scan", str(scenario[0]), "--year", "2024", "--fail-on-findings"])
        assert code == 1

    def test_missing_path_errors(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
        code = main(["scan", str(tmp_path / "nope.log")])
        assert code == 2
        assert "no such file" in capsys.readouterr().err

    def test_parsers_command(self, capsys: pytest.CaptureFixture[str]) -> None:
        assert main(["parsers"]) == 0
        assert "auth.log" in capsys.readouterr().out

    def test_rules_command(self, capsys: pytest.CaptureFixture[str]) -> None:
        assert main(["rules"]) == 0
        assert "THN-0001" in capsys.readouterr().out
