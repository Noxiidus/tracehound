from __future__ import annotations

import json
import struct
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from synth import syslog_line, utmp_record, write_auth_log, write_wtmp
from tracehound import scan
from tracehound.cli import main
from tracehound.config import Config, ConfigError
from tracehound.core import sha256_file
from tracehound.models import EventType
from tracehound.parsers import ParseContext
from tracehound.parsers.journal import JournalParser
from tracehound.parsers.wtmp import RECORD_SIZE, USER_PROCESS, UtmpParser
from tracehound.report import render_json, render_text
from tracehound.rules import RuleError, load_rules

CTX = ParseContext(default_year=2024)


# --------------------------------------------------------------------------- provenance


class TestProvenance:
    def test_every_file_is_hashed(self, scenario: tuple[Path, Path]) -> None:
        result = scan(list(scenario), year=2024)

        assert len(result.artifacts) == 2
        for record in result.artifacts:
            assert len(record.sha256) == 64
            assert record.sha256 == sha256_file(record.path)
            assert record.size > 0

    def test_unrecognised_file_is_recorded_not_dropped(self, tmp_path: Path) -> None:
        junk = tmp_path / "random.bin"
        junk.write_bytes(b"\x01\x02\x03")
        result = scan([junk])

        assert len(result.parsed) == 0
        assert len(result.skipped) == 1
        assert result.skipped[0].skipped_reason == "no parser matched"
        assert result.skipped[0].sha256  # still hashed — it was examined

    def test_text_report_lists_evidence(self, scenario: tuple[Path, Path]) -> None:
        result = scan(list(scenario), year=2024)
        output = render_text(result.timeline, result.findings, result)

        assert "Evidence examined" in output
        assert "sha256=" in output
        assert "Tool version" in output

    def test_json_report_carries_provenance(self, scenario: tuple[Path, Path]) -> None:
        result = scan(list(scenario), year=2024)
        payload = json.loads(render_json(result.timeline, result.findings, result))

        prov = payload["provenance"]
        assert prov["tool"] == "tracehound"
        assert len(prov["artifacts"]) == 2
        assert all(len(a["sha256"]) == 64 for a in prov["artifacts"])

    def test_provenance_omitted_when_not_supplied(self, scenario: tuple[Path, Path]) -> None:
        result = scan(list(scenario), year=2024)
        payload = json.loads(render_json(result.timeline, result.findings))
        assert "provenance" not in payload


# ------------------------------------------------------------------------------ config


class TestConfig:
    def test_known_ip_suppresses_brute_force(self, scenario: tuple[Path, Path]) -> None:
        config = Config(known_ips={"65.2.161.68"})
        result = scan(list(scenario), year=2024, config=config)

        ids = {f.rule_id for f in result.findings}
        assert "THN-0001" not in ids
        assert "THN-0002" not in ids

    def test_service_account_suppresses_creation(self, scenario: tuple[Path, Path]) -> None:
        config = Config(service_accounts={"cyberjunkie"})
        result = scan(list(scenario), year=2024, config=config)

        ids = {f.rule_id for f in result.findings}
        assert "THN-0010" not in ids
        assert "THN-0012" not in ids

    def test_disabled_rule_does_not_run(self, scenario: tuple[Path, Path]) -> None:
        config = Config(disabled_rules={"THN-0001"})
        result = scan(list(scenario), year=2024, config=config)
        assert all(f.rule_id != "THN-0001" for f in result.findings)

    def test_threshold_raises_the_bar(self, scenario: tuple[Path, Path]) -> None:
        config = Config(brute_force_threshold=1000)
        result = scan(list(scenario), year=2024, config=config)
        assert all(f.rule_id not in {"THN-0001", "THN-0002"} for f in result.findings)

    def test_expected_cron_glob_suppresses(self, tmp_path: Path) -> None:
        path = tmp_path / "cron"
        path.write_text(
            "Mar  6 06:25:01 h CROND[1]: (root) CMD (/tmp/deploy/run.sh)\n"
            "Mar  6 06:26:01 h CROND[2]: (root) CMD (/usr/bin/true)\n",
            encoding="utf-8",
        )
        loud = scan([path], year=2024)
        assert any(f.rule_id == "THN-0021" for f in loud.findings)

        quiet = scan([path], year=2024, config=Config(expected_cron=["/tmp/deploy/*"]))
        assert all(f.rule_id != "THN-0021" for f in quiet.findings)

    def test_load_json(self, tmp_path: Path) -> None:
        path = tmp_path / "cfg.json"
        path.write_text(
            json.dumps({"known_ips": ["10.0.0.1"], "brute_force_threshold": 25}),
            encoding="utf-8",
        )
        config = Config.load(path)
        assert config.known_ips == {"10.0.0.1"}
        assert config.brute_force_threshold == 25

    def test_unknown_key_is_rejected(self, tmp_path: Path) -> None:
        path = tmp_path / "cfg.json"
        path.write_text(json.dumps({"nope": 1}), encoding="utf-8")
        with pytest.raises(ConfigError, match="unknown configuration key"):
            Config.load(path)

    def test_bad_type_is_rejected(self, tmp_path: Path) -> None:
        path = tmp_path / "cfg.json"
        path.write_text(json.dumps({"known_ips": "10.0.0.1"}), encoding="utf-8")
        with pytest.raises(ConfigError, match="must be a list"):
            Config.load(path)


# ---------------------------------------------------------------------------- tampering


class TestTamperingDetections:
    def test_detects_log_gap(self, tmp_path: Path) -> None:
        base = datetime(2024, 3, 6, 6, 0, 0, tzinfo=timezone.utc)
        lines = [
            syslog_line(base + timedelta(seconds=i * 10), "sshd", f"routine message {i}")
            for i in range(40)
        ]
        # A two-hour hole after a steady ten-second cadence.
        lines += [
            syslog_line(base + timedelta(hours=2, seconds=i * 10), "sshd", f"after {i}")
            for i in range(40)
        ]
        path = write_auth_log(tmp_path / "auth.log", lines)

        result = scan([path], year=2024)
        gaps = [f for f in result.findings if f.rule_id == "THN-0030"]

        assert len(gaps) == 1
        assert gaps[0].metadata["gap_seconds"] > 3600

    def test_no_gap_reported_for_sparse_log(self, tmp_path: Path) -> None:
        """A log with too few events has no baseline, so silence proves nothing."""
        base = datetime(2024, 3, 6, 6, 0, 0, tzinfo=timezone.utc)
        path = write_auth_log(
            tmp_path / "auth.log",
            [
                syslog_line(base, "sshd", "one"),
                syslog_line(base + timedelta(hours=5), "sshd", "two"),
            ],
        )
        result = scan([path], year=2024)
        assert all(f.rule_id != "THN-0030" for f in result.findings)

    def test_detects_truncated_wtmp(self, tmp_path: Path) -> None:
        ts = datetime(2024, 3, 6, 6, 32, 45, tzinfo=timezone.utc)
        path = tmp_path / "wtmp"
        path.write_bytes(
            utmp_record(rec_type=USER_PROCESS, ts=ts, user="root", line="pts/1")
            + b"\x00" * 100  # a partial record
        )
        result = scan([path], year=2024)
        found = [f for f in result.findings if f.rule_id == "THN-0031"]

        assert len(found) == 1
        assert found[0].metadata["trailing_bytes"] == 100

    def test_intact_wtmp_is_not_flagged(self, tmp_path: Path) -> None:
        ts = datetime(2024, 3, 6, 6, 32, 45, tzinfo=timezone.utc)
        path = write_wtmp(
            tmp_path / "wtmp",
            [
                utmp_record(rec_type=USER_PROCESS, ts=ts, user="root", line="pts/1"),
            ],
        )
        result = scan([path], year=2024)
        assert all(f.rule_id != "THN-0031" for f in result.findings)

    def test_truncated_file_still_yields_its_intact_records(self, tmp_path: Path) -> None:
        """Truncation must not cost us the evidence that survived."""
        ts = datetime(2024, 3, 6, 6, 32, 45, tzinfo=timezone.utc)
        path = tmp_path / "wtmp"
        path.write_bytes(
            utmp_record(rec_type=USER_PROCESS, ts=ts, user="root", line="pts/1") + b"\x00" * 50
        )
        events = list(UtmpParser().parse(path, CTX))
        assert any(e.event_type is EventType.LOGIN_SUCCESS for e in events)
        assert any(e.metadata.get("anomaly") == "truncated" for e in events)

    def test_cleared_history_needs_history_elsewhere(self, tmp_path: Path) -> None:
        """With no history collected at all, silence is a collection gap, not tampering."""
        path = write_auth_log(
            tmp_path / "auth.log",
            [
                "Mar  6 06:37:57 h sudo: alice : TTY=pts/1 ; PWD=/ ; USER=root ; COMMAND=/bin/ls",
            ],
        )
        result = scan([path], year=2024)
        assert all(f.rule_id != "THN-0032" for f in result.findings)

    def test_detects_cleared_history(self, tmp_path: Path) -> None:
        write_auth_log(
            tmp_path / "auth.log",
            [
                "Mar  6 06:37:57 h sudo: alice : TTY=pts/1 ; PWD=/ ; USER=root ; COMMAND=/bin/ls",
                "Mar  6 06:38:57 h sudo: bob : TTY=pts/2 ; PWD=/ ; USER=root ; COMMAND=/bin/ls",
            ],
        )
        home = tmp_path / "home" / "bob"
        home.mkdir(parents=True)
        (home / ".bash_history").write_text("ls\n", encoding="utf-8")

        result = scan([tmp_path], year=2024)
        found = [f for f in result.findings if f.rule_id == "THN-0032"]

        assert [f.metadata["account"] for f in found] == ["alice"]


# ------------------------------------------------------------------------------ journal


class TestJournalParser:
    @staticmethod
    def _entry(micros: int, message: str, **extra: object) -> str:
        payload = {"__REALTIME_TIMESTAMP": str(micros), "MESSAGE": message, **extra}
        return json.dumps(payload)

    def test_parses_jsonl(self, tmp_path: Path) -> None:
        micros = int(datetime(2024, 3, 6, 6, 31, 40, tzinfo=timezone.utc).timestamp() * 1_000_000)
        path = tmp_path / "journal.json"
        path.write_text(
            self._entry(
                micros,
                "Accepted password for root from 65.2.161.68 port 34782 ssh2",
                SYSLOG_IDENTIFIER="sshd",
                _PID="2411",
            )
            + "\n",
            encoding="utf-8",
        )
        (event,) = list(JournalParser().parse(path, CTX))

        assert event.event_type is EventType.LOGIN_SUCCESS
        assert event.user == "root"
        assert event.source_ip == "65.2.161.68"
        assert event.pid == 2411
        assert event.process == "sshd"  # extracted from SYSLOG_IDENTIFIER
        assert event.timestamp == datetime(2024, 3, 6, 6, 31, 40, tzinfo=timezone.utc)

    def test_parses_json_array(self, tmp_path: Path) -> None:
        micros = int(datetime(2024, 3, 6, 6, 0, 0, tzinfo=timezone.utc).timestamp() * 1_000_000)
        path = tmp_path / "journal.json"
        path.write_text(
            json.dumps(
                [
                    {
                        "__REALTIME_TIMESTAMP": str(micros),
                        "MESSAGE": "new user: name=eve, UID=1005",
                    },
                ]
            ),
            encoding="utf-8",
        )
        (event,) = list(JournalParser().parse(path, CTX))
        assert event.event_type is EventType.ACCOUNT_CREATED
        assert event.user == "eve"

    def test_decodes_binary_message_arrays(self, tmp_path: Path) -> None:
        """journalctl emits non-UTF8 fields as byte arrays rather than strings."""
        micros = int(datetime(2024, 3, 6, 6, 0, 0, tzinfo=timezone.utc).timestamp() * 1_000_000)
        path = tmp_path / "journal.json"
        path.write_text(
            json.dumps({"__REALTIME_TIMESTAMP": str(micros), "MESSAGE": list(b"hello")}) + "\n",
            encoding="utf-8",
        )
        (event,) = list(JournalParser().parse(path, CTX))
        assert event.message == "hello"

    def test_truncated_final_line_is_skipped(self, tmp_path: Path) -> None:
        micros = int(datetime(2024, 3, 6, 6, 0, 0, tzinfo=timezone.utc).timestamp() * 1_000_000)
        path = tmp_path / "journal.json"
        path.write_text(
            self._entry(micros, "fine") + "\n" + '{"__REALTIME_TIMESTAMP": "17', encoding="utf-8"
        )
        events = list(JournalParser().parse(path, CTX))
        assert len(events) == 1

    def test_end_to_end_detection_from_journal(self, tmp_path: Path) -> None:
        base = datetime(2024, 3, 6, 6, 31, 31, tzinfo=timezone.utc)
        lines = []
        for i in range(15):
            micros = int((base + timedelta(seconds=i)).timestamp() * 1_000_000)
            lines.append(
                self._entry(
                    micros,
                    f"Failed password for invalid user admin from 9.9.9.9 port {5000 + i} ssh2",
                    SYSLOG_IDENTIFIER="sshd",
                    _PID=str(3000 + i),
                )
            )
        path = tmp_path / "journal.json"
        path.write_text("\n".join(lines) + "\n", encoding="utf-8")

        result = scan([path], year=2024)
        assert any(f.rule_id == "THN-0001" for f in result.findings)


# -------------------------------------------------------------------------------- rules


class TestDeclarativeRules:
    def test_simple_match(self, tmp_path: Path) -> None:
        rules = tmp_path / "rules.json"
        rules.write_text(
            json.dumps(
                {
                    "rules": [
                        {
                            "id": "LOCAL-0001",
                            "title": "Shadow file touched",
                            "severity": "critical",
                            "description": "Someone read the shadow file.",
                            "attack": ["T1003.008"],
                            "match": {
                                "event_type": "privilege_escalation",
                                "command": "/etc/shadow",
                            },
                        }
                    ]
                }
            ),
            encoding="utf-8",
        )

        log = write_auth_log(
            tmp_path / "auth.log",
            [
                "Mar  6 06:37:57 h sudo: eve : TTY=pts/1 ; PWD=/ ; USER=root ; "
                "COMMAND=/usr/bin/cat /etc/shadow",
            ],
        )
        result = scan([log], year=2024, extra_detections=load_rules(rules))
        found = [f for f in result.findings if f.rule_id == "LOCAL-0001"]

        assert len(found) == 1
        assert found[0].severity.value == "critical"
        assert found[0].attack_techniques == ["T1003.008"]

    def test_threshold_and_grouping(self, tmp_path: Path) -> None:
        rules = tmp_path / "rules.json"
        rules.write_text(
            json.dumps(
                {
                    "rules": [
                        {
                            "id": "LOCAL-0002",
                            "title": "Repeated failures",
                            "severity": "medium",
                            "match": {"event_type": "login_failure"},
                            "threshold": {
                                "count": 5,
                                "window_seconds": 300,
                                "group_by": "source_ip",
                            },
                        }
                    ]
                }
            ),
            encoding="utf-8",
        )

        base = datetime(2024, 3, 6, 6, 0, 0, tzinfo=timezone.utc)
        lines = [
            syslog_line(
                base + timedelta(seconds=i),
                "sshd",
                f"Failed password for bob from 7.7.7.7 port {i} ssh2",
                pid=100 + i,
            )
            for i in range(6)
        ]
        lines.append(
            syslog_line(base, "sshd", "Failed password for bob from 8.8.8.8 port 1 ssh2", pid=999)
        )
        log = write_auth_log(tmp_path / "auth.log", lines)

        result = scan([log], year=2024, extra_detections=load_rules(rules))
        found = [f for f in result.findings if f.rule_id == "LOCAL-0002"]

        assert len(found) == 1  # only 7.7.7.7 crosses the threshold
        assert "7.7.7.7" in found[0].title

    def test_rules_are_not_globally_registered(self, tmp_path: Path) -> None:
        """Loading a rule file must not leak into unrelated scans."""
        rules = tmp_path / "rules.json"
        rules.write_text(
            json.dumps(
                {
                    "rules": [
                        {
                            "id": "LOCAL-0003",
                            "title": "Anything",
                            "match": {},
                        }
                    ]
                }
            ),
            encoding="utf-8",
        )
        load_rules(rules)

        log = write_auth_log(
            tmp_path / "auth.log",
            [
                "Mar  6 06:19:54 h sshd[1]: Accepted password for root from 10.0.0.5 port 1 ssh2",
            ],
        )
        result = scan([log], year=2024)
        assert all(f.rule_id != "LOCAL-0003" for f in result.findings)

    def test_missing_id_rejected(self, tmp_path: Path) -> None:
        rules = tmp_path / "rules.json"
        rules.write_text(json.dumps({"rules": [{"title": "x"}]}), encoding="utf-8")
        with pytest.raises(RuleError, match="needs an 'id'"):
            load_rules(rules)

    def test_bad_event_type_rejected(self, tmp_path: Path) -> None:
        rules = tmp_path / "rules.json"
        rules.write_text(
            json.dumps(
                {
                    "rules": [
                        {
                            "id": "X",
                            "title": "x",
                            "match": {"event_type": "nope"},
                        }
                    ]
                }
            ),
            encoding="utf-8",
        )
        with pytest.raises(RuleError, match="unknown event_type"):
            load_rules(rules)

    def test_bad_regex_rejected(self, tmp_path: Path) -> None:
        rules = tmp_path / "rules.json"
        rules.write_text(
            json.dumps(
                {
                    "rules": [
                        {
                            "id": "X",
                            "title": "x",
                            "match": {"command": "([unclosed"},
                        }
                    ]
                }
            ),
            encoding="utf-8",
        )
        with pytest.raises(RuleError, match="invalid regex"):
            load_rules(rules)

    def test_duplicate_ids_rejected(self, tmp_path: Path) -> None:
        rules = tmp_path / "rules.json"
        rules.write_text(
            json.dumps(
                {
                    "rules": [
                        {"id": "X", "title": "a", "match": {}},
                        {"id": "X", "title": "b", "match": {}},
                    ]
                }
            ),
            encoding="utf-8",
        )
        with pytest.raises(RuleError, match="duplicate rule id"):
            load_rules(rules)

    def test_bad_group_by_rejected(self, tmp_path: Path) -> None:
        rules = tmp_path / "rules.json"
        rules.write_text(
            json.dumps(
                {
                    "rules": [
                        {
                            "id": "X",
                            "title": "x",
                            "match": {},
                            "threshold": {"count": 2, "group_by": "nonsense"},
                        }
                    ]
                }
            ),
            encoding="utf-8",
        )
        with pytest.raises(RuleError, match="cannot group by"):
            load_rules(rules)

    def test_bad_window_seconds_rejected(self, tmp_path: Path) -> None:
        """A non-integer threshold.window_seconds must raise RuleError, not a bare
        ValueError that escapes the loader and crashes the scan."""
        rules = tmp_path / "rules.json"
        rules.write_text(
            json.dumps(
                {
                    "rules": [
                        {
                            "id": "X",
                            "title": "x",
                            "match": {"user": "root"},
                            "threshold": {"count": 5, "window_seconds": "soon"},
                        }
                    ]
                }
            ),
            encoding="utf-8",
        )
        with pytest.raises(RuleError, match="window_seconds must be a positive integer"):
            load_rules(rules)


# ---------------------------------------------------------------------------------- cli


class TestCliIntegration:
    def test_config_flag(
        self, scenario: tuple[Path, Path], tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        cfg = tmp_path / "cfg.json"
        cfg.write_text(json.dumps({"known_ips": ["65.2.161.68"]}), encoding="utf-8")

        main(["scan", str(scenario[0]), "--year", "2024", "-f", "json", "-c", str(cfg)])
        payload = json.loads(capsys.readouterr().out)
        assert all(f["rule_id"] != "THN-0001" for f in payload["findings"])

    def test_rules_flag(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
        rules = tmp_path / "rules.json"
        rules.write_text(
            json.dumps(
                {
                    "rules": [
                        {
                            "id": "LOCAL-9",
                            "title": "Any login",
                            "match": {"event_type": "login_success"},
                        }
                    ]
                }
            ),
            encoding="utf-8",
        )
        log = write_auth_log(
            tmp_path / "auth.log",
            [
                "Mar  6 06:19:54 h sshd[1]: Accepted password for root from 10.0.0.5 port 1 ssh2",
            ],
        )

        main(["scan", str(log), "--year", "2024", "-f", "json", "-r", str(rules)])
        payload = json.loads(capsys.readouterr().out)
        assert any(f["rule_id"] == "LOCAL-9" for f in payload["findings"])

    def test_bad_config_exits_2(
        self, scenario: tuple[Path, Path], tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        cfg = tmp_path / "cfg.json"
        cfg.write_text("{not json", encoding="utf-8")
        code = main(["scan", str(scenario[0]), "-c", str(cfg)])

        assert code == 2
        assert "error:" in capsys.readouterr().err

    def test_json_output_includes_provenance(
        self, scenario: tuple[Path, Path], capsys: pytest.CaptureFixture[str]
    ) -> None:
        main(["scan", str(scenario[0]), "--year", "2024", "-f", "json"])
        payload = json.loads(capsys.readouterr().out)
        assert "provenance" in payload
        assert payload["provenance"]["artifacts"][0]["sha256"]


def test_record_size_constant_is_sane() -> None:
    assert RECORD_SIZE == 384
    assert struct.calcsize("<I") == 4
