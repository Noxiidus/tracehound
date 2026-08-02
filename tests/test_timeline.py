"""Timeline backend contract (0.9.0 groundwork).

These lock the query surface that detections rely on, so the on-disk backend can be checked
against exactly the same behaviour.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from tracehound.models import Event, EventType
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


class TestTimelineContract:
    def test_timeline_satisfies_the_protocol(self) -> None:
        assert isinstance(Timeline(), TimelineLike)

    def test_add_returns_count_and_accepts_an_iterator(self) -> None:
        tl = Timeline()
        assert tl.add(_ev(i) for i in range(3)) == 3  # a lazy generator, not a list
        assert tl.add([_ev(9)]) == 1
        assert len(tl) == 4

    def test_query_surface(self) -> None:
        tl = Timeline()
        tl.add(
            [
                _ev(0, event_type=EventType.LOGIN_FAILURE, source_ip="1.2.3.4", user="root"),
                _ev(5, event_type=EventType.LOGIN_SUCCESS, source_ip="1.2.3.4", user="root"),
                _ev(10, event_type=EventType.LOGIN_FAILURE, source_ip="9.9.9.9", user="admin"),
            ]
        )
        tl.sort()
        assert [e.event_type for e in tl.of_type(EventType.LOGIN_FAILURE)] == [
            EventType.LOGIN_FAILURE,
            EventType.LOGIN_FAILURE,
        ]
        assert len(tl.by_ip("1.2.3.4")) == 2
        assert len(tl.by_user("admin")) == 1
        assert tl.start == _ev(0).timestamp
        assert tl.end == _ev(10).timestamp
        assert tl.sources() == {"auth.log": 3}
        window = tl.window(tl.events[1], timedelta(seconds=6), timedelta(seconds=6))
        assert len(window) == 3

    def test_sort_is_deterministic_by_time_source_message(self) -> None:
        tl = Timeline()
        tl.add([_ev(5, source="b"), _ev(5, source="a"), _ev(1)])
        tl.sort()
        assert [(e.timestamp, e.source) for e in tl] == [
            (_ev(1).timestamp, "auth.log"),
            (_ev(5).timestamp, "a"),
            (_ev(5).timestamp, "b"),
        ]
