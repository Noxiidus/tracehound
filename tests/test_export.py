"""Tests for the 0.7.0 interoperability formats: l2tcsv, Timesketch JSONL, Sigma, and the
l2tcsv importer that closes the loop."""

from __future__ import annotations

import csv
import io
import json
from pathlib import Path

import pytest
import yaml

from synth import brute_force_scenario, write_passwd
from tracehound import render_l2tcsv, render_sigma, render_timesketch_jsonl, scan
from tracehound.export import L2T_COLUMNS
from tracehound.models import EventType
from tracehound.parsers import ParseContext, parser_for
from tracehound.parsers.l2tcsv import L2tCsvParser

CTX = ParseContext(default_year=2024)


def _scan(tmp_path: Path):
    brute_force_scenario(tmp_path, year=2024)
    return scan([tmp_path], year=2024)


class TestL2tCsvExport:
    def test_header_and_row_shape(self, tmp_path: Path) -> None:
        result = _scan(tmp_path)
        rows = list(
            csv.reader(io.StringIO(render_l2tcsv(result.timeline, result.findings, result)))
        )
        assert rows[0] == L2T_COLUMNS
        assert all(len(row) == len(L2T_COLUMNS) for row in rows[1:])
        assert len(rows) - 1 == len(result.timeline)

    def test_dates_are_utc_mmddyyyy(self, tmp_path: Path) -> None:
        result = _scan(tmp_path)
        rows = list(
            csv.reader(io.StringIO(render_l2tcsv(result.timeline, result.findings, result)))
        )
        first = dict(zip(L2T_COLUMNS, rows[1], strict=True))
        assert first["timezone"] == "UTC"
        assert first["date"].count("/") == 2  # MM/DD/YYYY

    def test_notes_column_carries_finding_rule_ids(self, tmp_path: Path) -> None:
        result = _scan(tmp_path)
        rows = list(
            csv.reader(io.StringIO(render_l2tcsv(result.timeline, result.findings, result)))
        )
        cited = {dict(zip(L2T_COLUMNS, r, strict=True))["notes"] for r in rows[1:]}
        # At least one row is annotated with a THN rule id from a finding that cites it.
        assert any(note.startswith("THN-") for note in cited)


class TestTimesketchExport:
    def test_required_fields_present(self, tmp_path: Path) -> None:
        result = _scan(tmp_path)
        lines = render_timesketch_jsonl(result.timeline, result.findings, result).splitlines()
        assert len(lines) == len(result.timeline)
        for line in lines:
            record = json.loads(line)
            assert "datetime" in record
            assert "timestamp_desc" in record
            assert "message" in record

    def test_finding_reasoning_rides_along(self, tmp_path: Path) -> None:
        result = _scan(tmp_path)
        records = [
            json.loads(line)
            for line in render_timesketch_jsonl(
                result.timeline, result.findings, result
            ).splitlines()
        ]
        tagged = [r for r in records if "tracehound-finding" in r.get("tag", [])]
        assert tagged, "expected at least one event tagged with a finding"
        sample = tagged[0]
        assert any(t.startswith("THN-") for t in sample["tag"])
        assert sample["tracehound_rules"]
        assert sample["tracehound_findings"]

    def test_events_without_findings_have_no_finding_tag(self, tmp_path: Path) -> None:
        result = _scan(tmp_path)
        records = [
            json.loads(line)
            for line in render_timesketch_jsonl(
                result.timeline, result.findings, result
            ).splitlines()
        ]
        untagged = [r for r in records if "tracehound-finding" not in r.get("tag", [])]
        assert untagged  # not every event belongs to a finding


class TestSigmaExport:
    def test_output_is_valid_yaml_documents(self, tmp_path: Path) -> None:
        result = _scan(tmp_path)
        docs = list(yaml.safe_load_all(render_sigma(result.findings, result)))
        docs = [d for d in docs if d]  # drop the trailing empty document
        assert len(docs) == len(result.findings)

    def test_rule_has_required_sigma_fields(self, tmp_path: Path) -> None:
        result = _scan(tmp_path)
        docs = [d for d in yaml.safe_load_all(render_sigma(result.findings, result)) if d]
        for rule in docs:
            assert rule["title"]
            assert rule["id"]
            assert rule["level"] in {"informational", "low", "medium", "high", "critical"}
            assert rule["logsource"]["product"] == "linux"
            assert "selection" in rule["detection"]
            assert rule["detection"]["condition"] == "selection"

    def test_attack_tags_are_lowercased(self, tmp_path: Path) -> None:
        result = _scan(tmp_path)
        docs = [d for d in yaml.safe_load_all(render_sigma(result.findings, result)) if d]
        tags = [t for rule in docs for t in rule.get("tags", [])]
        assert any(t.startswith("attack.t") for t in tags)
        assert all(t == t.lower() for t in tags)

    def test_ids_are_stable_across_exports(self, tmp_path: Path) -> None:
        result = _scan(tmp_path)
        first = [d["id"] for d in yaml.safe_load_all(render_sigma(result.findings, result)) if d]
        second = [d["id"] for d in yaml.safe_load_all(render_sigma(result.findings, result)) if d]
        assert first == second

    def test_em_dash_survives_unmangled(self, tmp_path: Path) -> None:
        """The description scalar must not be corrupted — a mojibake em-dash is a real bug."""
        result = _scan(tmp_path)
        docs = [d for d in yaml.safe_load_all(render_sigma(result.findings, result)) if d]
        assert "�" not in "".join(d["description"] for d in docs)

    def test_state_findings_are_exported_too(self, tmp_path: Path) -> None:
        root = tmp_path / "h"
        root.mkdir()
        write_passwd(root / "passwd", ["root:x:0:0::/root:/bin/bash", "bad:x:0:0::/root:/bin/bash"])
        result = scan([root])
        docs = [d for d in yaml.safe_load_all(render_sigma(result.findings, result)) if d]
        refs = [ref for d in docs for ref in d.get("references", [])]
        assert "tracehound:THN-0040" in refs


class TestL2tCsvImport:
    def test_sniff_matches_only_the_l2t_header(self, tmp_path: Path) -> None:
        good = tmp_path / "super.csv"
        good.write_text(",".join(L2T_COLUMNS) + "\n", encoding="utf-8")
        bad = tmp_path / "other.csv"
        bad.write_text("timestamp_utc,source,event_type\n2024-01-01,auth,login\n", encoding="utf-8")
        assert L2tCsvParser().sniff(good)
        assert not L2tCsvParser().sniff(bad)

    def test_parses_rows_into_events(self, tmp_path: Path) -> None:
        path = tmp_path / "super.csv"
        path.write_text(
            ",".join(L2T_COLUMNS) + "\n"
            "03/06/2024,06:31:31,UTC,,LOG,tracehound auth.log,login_failure,admin,-,"
            "short,Failed password,2,auth.log,-,,tracehound,source_ip: 65.2.161.68; pid: 42\n",
            encoding="utf-8",
        )
        (event,) = list(L2tCsvParser().parse(path, CTX))
        assert event.event_type is EventType.LOGIN_FAILURE
        assert event.source == "auth.log"
        assert event.user == "admin"
        assert event.source_ip == "65.2.161.68"
        assert event.pid == 42
        assert event.timestamp.isoformat() == "2024-03-06T06:31:31+00:00"

    def test_non_utc_named_zone_is_skipped(self, tmp_path: Path) -> None:
        path = tmp_path / "super.csv"
        path.write_text(
            ",".join(L2T_COLUMNS) + "\n"
            "03/06/2024,06:31:31,America/New_York,,LOG,src,login_failure,u,-,s,d,2,f,-,,fmt,\n"
            "03/06/2024,06:31:31,+02:00,,LOG,src,login_failure,u,-,s,d,2,f,-,,fmt,\n",
            encoding="utf-8",
        )
        events = list(L2tCsvParser().parse(path, CTX))
        # The named zone row is dropped; the explicit offset row is kept and converted.
        assert len(events) == 1
        assert events[0].timestamp.isoformat() == "2024-03-06T04:31:31+00:00"

    def test_parser_selection_prefers_l2tcsv_header(self, tmp_path: Path) -> None:
        path = tmp_path / "super.csv"
        path.write_text(",".join(L2T_COLUMNS) + "\n", encoding="utf-8")
        selected = parser_for(path)
        assert selected is not None
        assert selected.name == "l2tcsv"


class TestRoundTrip:
    def test_export_then_reimport_refires_detections(self, tmp_path: Path) -> None:
        """An l2tcsv super-timeline exported by tracehound, read back in, must reproduce the
        same event-based findings — the events survive the format intact."""
        result = _scan(tmp_path)
        l2t = render_l2tcsv(result.timeline, result.findings, result)
        super_path = tmp_path / "exported.csv"
        super_path.write_text(l2t, encoding="utf-8", newline="")

        reimported = scan([super_path], year=2024)
        assert len(reimported.timeline) == len(result.timeline)

        original_event_rules = {f.rule_id for f in result.findings if f.events}
        reimported_rules = {f.rule_id for f in reimported.findings}
        # The brute-force chain (event-based) must survive the round-trip.
        assert "THN-0001" in original_event_rules
        assert original_event_rules <= reimported_rules


@pytest.mark.parametrize("fmt", ["l2tcsv", "timesketch", "sigma"])
def test_cli_formats_produce_output(tmp_path: Path, capsys, fmt: str) -> None:
    from tracehound.cli import main

    brute_force_scenario(tmp_path, year=2024)
    rc = main(["scan", str(tmp_path), "--year", "2024", "-f", fmt])
    out = capsys.readouterr().out
    assert rc == 0
    assert out.strip()
