"""Timeline backend contract (0.9.0).

Both the in-memory :class:`Timeline` and the on-disk :class:`SqliteTimeline` are held to the
same :class:`TimelineLike` contract here, and proven to produce identical results on identical
input — that equivalence is what lets a detection run against either without knowing which.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from tracehound.models import Event, EventType
from tracehound.sqlite_timeline import SqliteTimeline
from tracehound.timeline import Timeline, TimelineLike


def _ev(sec: int, **kw: object) -> Event:
    base = {
        "timestamp": datetime(2024, 3, 6, 6, 0, 0, tzinfo=timezone.utc) + timedelta(seconds=sec),
        "source": "auth.log",
        "event_type": EventType.OTHER,
        "message": f"m{sec}",
    }
    base.update(kw)
    return Event(**base)  # type: ignore[arg-type]


@pytest.fixture(params=["memory", "sqlite"])
def backend(request: pytest.FixtureRequest) -> TimelineLike:
    return Timeline() if request.param == "memory" else SqliteTimeline()


class TestBackendContract:
    def test_both_satisfy_the_protocol(self, backend: TimelineLike) -> None:
        assert isinstance(backend, TimelineLike)

    def test_add_returns_count_and_accepts_an_iterator(self, backend: TimelineLike) -> None:
        assert backend.add(_ev(i) for i in range(3)) == 3  # a lazy generator, not a list
        assert backend.add([_ev(9)]) == 1
        assert len(backend) == 4

    def test_query_surface(self, backend: TimelineLike) -> None:
        backend.add(
            [
                _ev(0, event_type=EventType.LOGIN_FAILURE, source_ip="1.2.3.4", user="root"),
                _ev(5, event_type=EventType.LOGIN_SUCCESS, source_ip="1.2.3.4", user="root"),
                _ev(10, event_type=EventType.LOGIN_FAILURE, source_ip="9.9.9.9", user="admin"),
            ]
        )
        backend.sort()
        assert len(backend.of_type(EventType.LOGIN_FAILURE)) == 2
        assert len(backend.by_ip("1.2.3.4")) == 2
        assert len(backend.by_user("admin")) == 1
        assert backend.start == _ev(0).timestamp
        assert backend.end == _ev(10).timestamp
        assert backend.sources() == {"auth.log": 3}
        anchor = list(backend)[1]
        assert len(backend.window(anchor, timedelta(seconds=6), timedelta(seconds=6))) == 3

    def test_deterministic_order_by_time_source_message(self, backend: TimelineLike) -> None:
        backend.add([_ev(5, source="b"), _ev(5, source="a"), _ev(1)])
        backend.sort()
        assert [(e.timestamp, e.source) for e in backend] == [
            (_ev(1).timestamp, "auth.log"),
            (_ev(5).timestamp, "a"),
            (_ev(5).timestamp, "b"),
        ]

    def test_empty_backend(self, backend: TimelineLike) -> None:
        assert len(backend) == 0
        assert backend.start is None
        assert backend.end is None
        assert backend.sources() == {}
        assert list(backend) == []
        assert backend.of_type(EventType.OTHER) == []


class TestSqliteFidelity:
    def test_round_trips_every_field_including_microseconds(self) -> None:
        original = Event(
            timestamp=datetime(2024, 3, 6, 6, 31, 31, 123456, tzinfo=timezone.utc),
            source="auth.log",
            event_type=EventType.PRIVILEGE_ESCALATION,
            message="cyberjunkie : COMMAND=/usr/bin/cat /etc/shadow",
            user="cyberjunkie",
            source_ip="65.2.161.68",
            process="sudo",
            pid=2603,
            terminal="pts/1",
            raw="raw line",
            metadata={"command": "/usr/bin/cat /etc/shadow", "target": "root", "count": 3},
        )
        tl = SqliteTimeline()
        tl.add([original])
        (restored,) = list(tl)
        assert restored.timestamp == original.timestamp
        assert restored.to_dict() == original.to_dict()

    def test_none_fields_survive(self) -> None:
        tl = SqliteTimeline()
        tl.add([_ev(0)])  # user/source_ip/process/pid/terminal all None
        (e,) = list(tl)
        assert e.user is None and e.source_ip is None and e.pid is None

    def test_exotic_metadata_does_not_crash(self) -> None:
        """Metadata JSON can't hold bytes or a set; the backend must degrade to a string,
        not abort the whole scan (every built-in parser emits only JSON-native metadata)."""
        tl = SqliteTimeline()
        tl.add([_ev(0, metadata={"blob": b"\x00raw", "seen": {1, 2}, "n": 5})])
        (e,) = list(tl)
        assert e.metadata["n"] == 5  # JSON-native value round-trips exactly
        assert isinstance(e.metadata["blob"], str)  # bytes stringified, no crash

    def test_reset_clears_existing_rows_by_default(self, tmp_path: Path) -> None:
        db = tmp_path / "t.db"
        first = SqliteTimeline(db)
        first.add([_ev(0), _ev(1)])
        first.close()

        assert len(SqliteTimeline(db, reset=False)) == 2  # reopen preserving
        assert len(SqliteTimeline(db)) == 0  # default reset empties it


class TestCrossBackendEquivalence:
    def test_identical_input_gives_identical_output(self) -> None:
        events = [
            _ev(10, event_type=EventType.LOGIN_FAILURE, source_ip="1.2.3.4", user="root"),
            _ev(
                2,
                event_type=EventType.LOGIN_SUCCESS,
                source_ip="9.9.9.9",
                user="admin",
                source="wtmp",
            ),
            _ev(2, event_type=EventType.INVALID_USER, source_ip="1.2.3.4", user="root"),
            _ev(30, event_type=EventType.CRON_JOB, process="CROND"),
        ]
        mem, sql = Timeline(), SqliteTimeline()
        mem.add(events)
        mem.sort()
        sql.add(events)

        def snapshot(tl: TimelineLike) -> tuple[object, ...]:
            return (
                len(tl),
                [(e.timestamp, e.source, e.message) for e in tl],
                [e.message for e in tl.of_type(EventType.LOGIN_FAILURE, EventType.INVALID_USER)],
                [e.message for e in tl.by_ip("1.2.3.4")],
                [e.message for e in tl.by_user("root")],
                tl.start,
                tl.end,
                tl.sources(),
            )

        assert snapshot(mem) == snapshot(sql)

    def test_scan_findings_identical_on_disk(self, tmp_path: Path) -> None:
        """The whole pipeline — parse, detect, report — must yield the same findings whether
        the timeline is in memory or on disk."""
        from synth import backdoor_state_scenario, brute_force_scenario
        from tracehound import scan

        brute_force_scenario(tmp_path, year=2024)
        backdoor_state_scenario(tmp_path)
        db = tmp_path / "timeline.db"

        mem = scan([tmp_path], year=2024)
        disk = scan([tmp_path], year=2024, on_disk=db)

        assert db.exists() and db.stat().st_size > 0
        assert type(disk.timeline).__name__ == "SqliteTimeline"
        assert sorted((f.rule_id, f.title) for f in mem.findings) == sorted(
            (f.rule_id, f.title) for f in disk.findings
        )

    def test_rescan_to_same_file_does_not_accumulate(self, tmp_path: Path) -> None:
        """Re-running a scan to the same --sqlite path must represent that scan, not add to
        the previous one — otherwise the timeline and findings silently double."""
        from synth import brute_force_scenario
        from tracehound import scan

        brute_force_scenario(tmp_path, year=2024)
        db = tmp_path / "tl.db"
        first = scan([tmp_path], year=2024, on_disk=db)
        second = scan([tmp_path], year=2024, on_disk=db)
        assert len(second.timeline) == len(first.timeline)
        assert len(second.findings) == len(first.findings)


class TestIncrementalScan:
    def test_requires_on_disk(self, tmp_path: Path) -> None:
        from tracehound import scan

        with pytest.raises(ValueError, match="incremental scanning requires"):
            scan([tmp_path], year=2024, incremental=True)

    def test_unchanged_files_are_reused_not_reparsed(self, tmp_path: Path) -> None:
        from synth import brute_force_scenario
        from tracehound import scan

        brute_force_scenario(tmp_path, year=2024)
        db = tmp_path / "tl.db"

        first = scan([tmp_path], year=2024, on_disk=db, incremental=True)
        assert not any(a.reused for a in first.artifacts)  # nothing to reuse on the first run

        second = scan([tmp_path], year=2024, on_disk=db, incremental=True)
        reused = [a for a in second.artifacts if a.reused]
        assert reused, "expected unchanged event files to be reused"
        # Reused files keep their event count and the timeline does not grow or double.
        assert len(second.timeline) == len(first.timeline)
        assert sorted(f.rule_id for f in second.findings) == sorted(
            f.rule_id for f in first.findings
        )

    def test_changed_file_is_reparsed_and_matches_a_full_scan(self, tmp_path: Path) -> None:
        from datetime import datetime, timezone

        from synth import brute_force_scenario, syslog_line
        from tracehound import scan

        brute_force_scenario(tmp_path, year=2024)
        db = tmp_path / "tl.db"
        scan([tmp_path], year=2024, on_disk=db, incremental=True)

        # Append a fresh brute-force burst to auth.log, then re-scan incrementally.
        auth = tmp_path / "auth.log"
        base = datetime(2024, 3, 6, 7, 0, 0, tzinfo=timezone.utc)
        with auth.open("a", encoding="utf-8") as fh:
            for i in range(15):
                fh.write(
                    syslog_line(
                        base,
                        "sshd",
                        f"Failed password for invalid user bob from 9.9.9.9 port {i} ssh2",
                        pid=5000 + i,
                    )
                    + "\n"
                )

        incr = scan([tmp_path], year=2024, on_disk=db, incremental=True)
        auth_record = next(a for a in incr.artifacts if a.path.name == "auth.log")
        assert auth_record.reused is False  # the grown file was re-parsed

        # The incremental result must match a fresh full scan of the current evidence.
        full = scan([tmp_path], year=2024)
        assert sorted((f.rule_id, f.title) for f in incr.findings) == sorted(
            (f.rule_id, f.title) for f in full.findings
        )

    def test_changed_file_no_longer_an_event_source_is_not_orphaned(self, tmp_path: Path) -> None:
        """If an event file becomes unparseable (or a different kind of artifact) between
        incremental runs, its old events must be dropped, not left orphaned in the DB."""
        from synth import brute_force_scenario
        from tracehound import scan

        evidence = tmp_path / "evidence"
        evidence.mkdir()
        brute_force_scenario(evidence, year=2024)
        db = tmp_path / "tl.db"
        scan([evidence], year=2024, on_disk=db, incremental=True)

        # auth.log is replaced with content no parser recognises.
        (evidence / "auth.log").write_text("!!! not a log anymore !!!\njunk\n", encoding="utf-8")
        incr = scan([evidence], year=2024, on_disk=db, incremental=True)
        full = scan([evidence], year=2024)
        assert len(incr.timeline) == len(full.timeline)  # no orphaned auth.log events
        assert sorted((f.rule_id, f.title) for f in incr.findings) == sorted(
            (f.rule_id, f.title) for f in full.findings
        )

    def test_deleted_file_is_pruned_from_the_timeline(self, tmp_path: Path) -> None:
        """A file that was an event source last run but is gone now must have its events
        pruned, so an incremental scan equals a full scan of the current evidence."""
        from synth import brute_force_scenario
        from tracehound import scan

        evidence = tmp_path / "evidence"
        evidence.mkdir()
        brute_force_scenario(evidence, year=2024)  # auth.log + wtmp
        db = tmp_path / "tl.db"
        scan([evidence], year=2024, on_disk=db, incremental=True)

        (evidence / "wtmp").unlink()  # delete one event source
        incr = scan([evidence], year=2024, on_disk=db, incremental=True)
        full = scan([evidence], year=2024)
        assert len(incr.timeline) == len(full.timeline)
        assert not any(e.source == "wtmp" for e in incr.timeline)

    def test_backend_bookkeeping(self, tmp_path: Path) -> None:
        db = tmp_path / "b.db"
        tl = SqliteTimeline(db, reset=False)
        tl.add([_ev(0), _ev(1)], source_path="/x/auth.log")
        tl.record_ingested("/x/auth.log", size=100, mtime=123.0, sha256="abc", event_count=2)

        assert tl.unchanged("/x/auth.log", 100, 123.0, "abc")
        assert not tl.unchanged("/x/auth.log", 200, 123.0, "abc")  # size differs
        assert tl.reused_count("/x/auth.log") == 2

        tl.forget("/x/auth.log")
        assert len(tl) == 0
        assert not tl.unchanged("/x/auth.log", 100, 123.0, "abc")
