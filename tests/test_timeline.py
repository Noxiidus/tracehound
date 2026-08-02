"""Timeline backend contract (0.9.0).

Both the in-memory :class:`Timeline` and the on-disk :class:`SqliteTimeline` are held to the
same :class:`TimelineLike` contract here, and proven to produce identical results on identical
input — that equivalence is what lets a detection run against either without knowing which.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

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
