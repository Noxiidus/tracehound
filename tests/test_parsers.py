from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

import pytest

from synth import syslog_line, utmp_record, write_auth_log, write_wtmp
from tracehound.models import EventType
from tracehound.parsers import ParseContext, parser_for
from tracehound.parsers.authlog import AuthLogParser
from tracehound.parsers.wtmp import BOOT_TIME, USER_PROCESS, UtmpParser

CTX = ParseContext(default_year=2024)


class TestAuthLogParser:
    def test_sniffs_syslog_format(self, tmp_path: Path) -> None:
        path = write_auth_log(tmp_path / "auth.log", ["Mar  6 06:18:01 host sshd[1]: hello"])
        assert AuthLogParser().sniff(path)

    def test_rejects_random_text(self, tmp_path: Path) -> None:
        path = tmp_path / "notes.txt"
        path.write_text("just some notes\nnothing structured here\n", encoding="utf-8")
        assert not AuthLogParser().sniff(path)

    def test_parses_accepted_password(self, tmp_path: Path) -> None:
        line = "Mar  6 06:19:54 host sshd[1465]: Accepted password for root from 1.2.3.4 port 42825 ssh2"
        path = write_auth_log(tmp_path / "auth.log", [line])
        (event,) = list(AuthLogParser().parse(path, CTX))

        assert event.event_type is EventType.LOGIN_SUCCESS
        assert event.user == "root"
        assert event.source_ip == "1.2.3.4"
        assert event.pid == 1465
        assert event.process == "sshd"
        assert event.timestamp == datetime(2024, 3, 6, 6, 19, 54, tzinfo=timezone.utc)

    def test_parses_invalid_user_failure(self, tmp_path: Path) -> None:
        line = "Mar  6 06:31:33 host sshd[2327]: Failed password for invalid user admin from 9.9.9.9 port 46392 ssh2"
        path = write_auth_log(tmp_path / "auth.log", [line])
        (event,) = list(AuthLogParser().parse(path, CTX))

        assert event.event_type is EventType.LOGIN_FAILURE
        assert event.user == "admin"
        assert event.source_ip == "9.9.9.9"

    def test_parses_sudo_command(self, tmp_path: Path) -> None:
        line = (
            "Mar  6 06:37:57 host sudo: cyberjunkie : TTY=pts/1 ; PWD=/home/cyberjunkie ; "
            "USER=root ; COMMAND=/usr/bin/cat /etc/shadow"
        )
        path = write_auth_log(tmp_path / "auth.log", [line])
        (event,) = list(AuthLogParser().parse(path, CTX))

        assert event.event_type is EventType.PRIVILEGE_ESCALATION
        assert event.user == "cyberjunkie"
        assert event.metadata["command"] == "/usr/bin/cat /etc/shadow"
        assert event.metadata["target"] == "root"
        assert event.terminal == "pts/1"

    def test_parses_account_creation(self, tmp_path: Path) -> None:
        line = "Mar  6 06:34:18 host useradd[2592]: new user: name=cyberjunkie, UID=1002, GID=1002"
        path = write_auth_log(tmp_path / "auth.log", [line])
        (event,) = list(AuthLogParser().parse(path, CTX))

        assert event.event_type is EventType.ACCOUNT_CREATED
        assert event.user == "cyberjunkie"

    def test_parses_group_addition(self, tmp_path: Path) -> None:
        line = "Mar  6 06:35:15 host usermod[2628]: add 'cyberjunkie' to group 'sudo'"
        path = write_auth_log(tmp_path / "auth.log", [line])
        (event,) = list(AuthLogParser().parse(path, CTX))

        assert event.event_type is EventType.GROUP_MEMBER_ADDED
        assert event.user == "cyberjunkie"
        assert event.metadata["group"] == "sudo"

    def test_parses_iso_timestamps(self, tmp_path: Path) -> None:
        line = "2024-03-06T06:19:54.123456+00:00 host sshd[1465]: Accepted password for root from 1.2.3.4 port 1 ssh2"
        path = write_auth_log(tmp_path / "auth.log", [line])
        (event,) = list(AuthLogParser().parse(path, CTX))

        assert event.timestamp.year == 2024
        assert event.user == "root"

    def test_year_rollover_increments(self, tmp_path: Path) -> None:
        """December followed by January means the log crossed into the next year."""
        path = write_auth_log(
            tmp_path / "auth.log",
            [
                "Dec 31 23:59:59 host sshd[1]: Accepted password for a from 1.1.1.1 port 1 ssh2",
                "Jan  1 00:00:01 host sshd[2]: Accepted password for b from 1.1.1.1 port 2 ssh2",
            ],
        )
        first, second = list(AuthLogParser().parse(path, ParseContext(default_year=2023)))

        assert first.timestamp.year == 2023
        assert second.timestamp.year == 2024

    def test_all_timestamps_are_utc_aware(self, tmp_path: Path) -> None:
        path = write_auth_log(
            tmp_path / "auth.log",
            [
                syslog_line(datetime(2024, 3, 6, 6, 19, 54, tzinfo=timezone.utc), "sshd", "test"),
            ],
        )
        for event in AuthLogParser().parse(path, CTX):
            assert event.timestamp.tzinfo is not None
            assert event.timestamp.utcoffset().total_seconds() == 0  # type: ignore[union-attr]

    def test_malformed_lines_are_skipped_not_fatal(self, tmp_path: Path) -> None:
        path = write_auth_log(
            tmp_path / "auth.log",
            [
                "this is not a syslog line",
                "",
                "Mar  6 06:19:54 host sshd[1]: Accepted password for root from 1.2.3.4 port 1 ssh2",
                "Xyz 99 99:99:99 host sshd[2]: nonsense",
            ],
        )
        events = list(AuthLogParser().parse(path, CTX))
        assert len(events) == 1


class TestUtmpParser:
    def test_round_trip(self, tmp_path: Path) -> None:
        """The writer and parser must agree on the 384-byte layout."""
        ts = datetime(2024, 3, 6, 6, 32, 45, tzinfo=timezone.utc)
        path = write_wtmp(
            tmp_path / "wtmp",
            [
                utmp_record(
                    rec_type=USER_PROCESS,
                    ts=ts,
                    user="root",
                    line="pts/1",
                    host="65.2.161.68",
                    pid=2549,
                ),
            ],
        )
        (event,) = list(UtmpParser().parse(path, CTX))

        assert event.timestamp == ts
        assert event.user == "root"
        assert event.terminal == "pts/1"
        assert event.source_ip == "65.2.161.68"
        assert event.pid == 2549
        assert event.event_type is EventType.LOGIN_SUCCESS

    def test_boot_record(self, tmp_path: Path) -> None:
        ts = datetime(2024, 3, 6, 6, 17, 15, tzinfo=timezone.utc)
        path = write_wtmp(
            tmp_path / "wtmp",
            [
                utmp_record(rec_type=BOOT_TIME, ts=ts, user="reboot", line="~", host="6.2.0-aws"),
            ],
        )
        (event,) = list(UtmpParser().parse(path, CTX))
        assert event.event_type is EventType.BOOT

    def test_sniff_rejects_wrong_size(self, tmp_path: Path) -> None:
        path = tmp_path / "wtmp"
        path.write_bytes(b"\x00" * 100)
        assert not UtmpParser().sniff(path)

    def test_sniff_rejects_empty(self, tmp_path: Path) -> None:
        path = tmp_path / "wtmp"
        path.write_bytes(b"")
        assert not UtmpParser().sniff(path)

    def test_timestamps_are_utc_not_local(self, tmp_path: Path) -> None:
        """Regression guard: utmp epochs must never be rendered in host local time."""
        ts = datetime(2024, 3, 6, 6, 32, 45, tzinfo=timezone.utc)
        path = write_wtmp(
            tmp_path / "wtmp",
            [
                utmp_record(rec_type=USER_PROCESS, ts=ts, user="root", line="pts/1"),
            ],
        )
        (event,) = list(UtmpParser().parse(path, CTX))
        assert event.timestamp.strftime("%Y-%m-%d %H:%M:%S") == "2024-03-06 06:32:45"


class TestParserSelection:
    def test_binary_not_mistaken_for_log(self, tmp_path: Path) -> None:
        path = write_wtmp(
            tmp_path / "wtmp",
            [
                utmp_record(
                    rec_type=USER_PROCESS, ts=datetime(2024, 3, 6, tzinfo=timezone.utc), user="root"
                ),
            ],
        )
        selected = parser_for(path)
        assert selected is not None
        assert selected.name == "wtmp"

    def test_log_selects_authlog(self, tmp_path: Path) -> None:
        path = write_auth_log(
            tmp_path / "auth.log",
            [
                "Mar  6 06:19:54 host sshd[1]: Accepted password for root from 1.2.3.4 port 1 ssh2",
            ],
        )
        selected = parser_for(path)
        assert selected is not None
        assert selected.name == "auth.log"

    def test_unknown_file_selects_nothing(self, tmp_path: Path) -> None:
        path = tmp_path / "random.bin"
        path.write_bytes(b"\x01\x02\x03")
        assert parser_for(path) is None


def test_naive_timestamp_rejected() -> None:
    from tracehound.models import Event

    with pytest.raises(ValueError, match="naive timestamp"):
        Event(
            timestamp=datetime(2024, 3, 6, 6, 0, 0),
            source="test",
            event_type=EventType.OTHER,
            message="x",
        )
