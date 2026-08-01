from __future__ import annotations

import csv
import io
import json
import os
from datetime import datetime, timezone
from pathlib import Path

import pytest

from tracehound import render_l2tcsv, scan
from tracehound.cli import main
from tracehound.core import collect_files
from tracehound.models import Event, EventType
from tracehound.report import render_html, render_json, render_text, render_timeline_csv
from tracehound.timeline import Timeline


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

    def test_html_escapes_user_controlled_fields(self) -> None:
        """A finding whose rule_id/title/description come from a loaded rule (e.g. Sigma)
        must not inject markup into the shared HTML report."""
        from datetime import datetime, timezone

        from tracehound.models import Event, EventType, Finding, Severity
        from tracehound.timeline import Timeline

        event = Event(
            timestamp=datetime(2024, 1, 1, tzinfo=timezone.utc),
            source="s",
            event_type=EventType.OTHER,
            message="<img src=x onerror=alert(1)>",
        )
        finding = Finding(
            rule_id="<script>alert('id')</script>",
            title="<script>alert('title')</script>",
            severity=Severity.HIGH,
            description="<b>desc</b>",
            events=[event],
        )
        timeline = Timeline([event])
        output = render_html(timeline, [finding])

        assert "<script>alert('id')</script>" not in output
        assert "<script>alert('title')</script>" not in output
        assert "<img src=x onerror" not in output
        assert "&lt;script&gt;" in output  # it is present, but escaped

    def test_timeline_csv_neutralises_formula_injection(self) -> None:
        """An attacker-controlled log field beginning with a spreadsheet formula character
        must be defanged in the human CSV so Excel/LibreOffice won't execute it."""
        event = Event(
            timestamp=datetime(2024, 1, 1, tzinfo=timezone.utc),
            source="auth.log",
            event_type=EventType.OTHER,
            message="=cmd|'/c calc'!A1",
            user="@SUM(1+1)",
        )
        rows = list(csv.reader(io.StringIO(render_timeline_csv(Timeline([event])))))
        cells = rows[1]
        assert not any(c[:1] in ("=", "+", "@", "\t", "\r") for c in cells)
        assert "'=cmd|'/c calc'!A1" in cells  # value preserved, just quoted
        assert "'@SUM(1+1)" in cells

    def test_l2tcsv_export_is_not_quote_mangled(self) -> None:
        """l2tcsv feeds plaso/Timesketch, not Excel — it must keep values verbatim."""
        event = Event(
            timestamp=datetime(2024, 1, 1, tzinfo=timezone.utc),
            source="auth.log",
            event_type=EventType.OTHER,
            message="=formula",
        )
        out = render_l2tcsv(Timeline([event]), [])
        assert "=formula" in out
        assert "'=formula" not in out

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


class TestCollectFiles:
    def test_nested_tree_and_dedup(self, tmp_path: Path) -> None:
        (tmp_path / "a" / "b").mkdir(parents=True)
        (tmp_path / "top.log").write_text("x")
        (tmp_path / "a" / "mid.log").write_text("y")
        (tmp_path / "a" / "b" / "deep.log").write_text("z")
        names = sorted(f.name for f in collect_files([tmp_path]))
        assert names == ["deep.log", "mid.log", "top.log"]
        # the same file passed twice is collected once
        assert len(collect_files([tmp_path / "top.log", tmp_path / "top.log"])) == 1

    def test_symlink_loop_does_not_hang(self, tmp_path: Path) -> None:
        """Directory symlink cycles must not send collect_files into an infinite walk."""
        sub = tmp_path / "a"
        sub.mkdir()
        (sub / "real.log").write_text("evidence")
        try:
            os.symlink(tmp_path, sub / "loop", target_is_directory=True)
        except (OSError, NotImplementedError):
            pytest.skip("symlinks not supported on this platform/user")
        files = collect_files([tmp_path])  # would loop forever if symlinks were followed
        assert any(f.name == "real.log" for f in files)


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
