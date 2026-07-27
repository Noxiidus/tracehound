"""Tests for the Sigma rule loader (tracehound.sigma)."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

import pytest

from tracehound import scan
from tracehound.models import Event, EventType
from tracehound.sigma import SigmaError, build_rule, load_sigma_rules


def _event(message: str, **kwargs: object) -> Event:
    base = {
        "timestamp": datetime(2024, 3, 6, 6, 31, 31, tzinfo=timezone.utc),
        "source": "auth.log",
        "event_type": EventType.OTHER,
        "message": message,
    }
    base.update(kwargs)
    return Event(**base)  # type: ignore[arg-type]


def _rule(**detection: object) -> object:
    doc = {
        "title": "T",
        "id": "00000000-0000-0000-0000-000000000000",
        "detection": detection,
    }
    return build_rule(doc)


class TestFieldMatching:
    def test_equals_is_case_insensitive(self) -> None:
        rule = _rule(sel={"User": "ROOT"}, condition="sel")
        assert rule.matches(_event("x", user="root"))
        assert not rule.matches(_event("x", user="admin"))

    def test_wildcard_value(self) -> None:
        rule = _rule(sel={"CommandLine": "*/etc/shadow*"}, condition="sel")
        assert rule.matches(_event("cat /etc/shadow", event_type=EventType.COMMAND_EXECUTED))
        assert not rule.matches(_event("cat /etc/passwd", event_type=EventType.COMMAND_EXECUTED))

    def test_list_value_is_or(self) -> None:
        rule = _rule(sel={"User": ["alice", "bob"]}, condition="sel")
        assert rule.matches(_event("x", user="bob"))
        assert not rule.matches(_event("x", user="carol"))

    def test_contains_startswith_endswith(self) -> None:
        assert _rule(sel={"message|contains": "shadow"}, condition="sel").matches(
            _event("cat shadow")
        )
        assert _rule(sel={"message|startswith": "cat"}, condition="sel").matches(_event("cat x"))
        assert _rule(sel={"message|endswith": "shadow"}, condition="sel").matches(
            _event("cat shadow")
        )

    def test_all_modifier_requires_every_value(self) -> None:
        rule = _rule(sel={"message|contains|all": ["curl", "sh"]}, condition="sel")
        assert rule.matches(_event("curl x | sh"))
        assert not rule.matches(_event("curl x"))

    def test_re_modifier(self) -> None:
        rule = _rule(sel={"message|re": r"\d{1,3}(\.\d{1,3}){3}"}, condition="sel")
        assert rule.matches(_event("from 10.0.0.1 port 22"))
        assert not rule.matches(_event("no address here"))

    def test_cidr_modifier(self) -> None:
        rule = _rule(sel={"SourceIp|cidr": "10.0.0.0/8"}, condition="sel")
        assert rule.matches(_event("x", source_ip="10.5.5.5"))
        assert not rule.matches(_event("x", source_ip="192.168.1.1"))
        assert not rule.matches(_event("x", source_ip=None))

    def test_null_matches_absent_field(self) -> None:
        rule = _rule(sel={"SourceIp": None}, condition="sel")
        assert rule.matches(_event("x", source_ip=None))
        assert not rule.matches(_event("x", source_ip="1.2.3.4"))

    def test_keyword_list_searches_everything(self) -> None:
        rule = _rule(keywords=["beacon"], condition="keywords")
        assert rule.matches(_event("started /tmp/beacon --daemon"))
        assert rule.matches(_event("clean", metadata={"command": "run beacon"}))
        assert not rule.matches(_event("nothing here"))

    def test_list_of_maps_is_or(self) -> None:
        rule = _rule(sel=[{"user": "root"}, {"user": "admin"}], condition="sel")
        assert rule.matches(_event("x", user="admin"))
        assert not rule.matches(_event("x", user="eve"))

    def test_metadata_fallback(self) -> None:
        rule = _rule(sel={"group": "sudo"}, condition="sel")
        assert rule.matches(_event("x", metadata={"group": "sudo"}))
        assert not rule.matches(_event("x", metadata={"group": "users"}))


class TestConditionGrammar:
    def _two(self, condition: str):
        return _rule(
            a={"user": "root"},
            b={"source_ip": "1.2.3.4"},
            condition=condition,
        )

    def test_and(self) -> None:
        rule = self._two("a and b")
        assert rule.matches(_event("x", user="root", source_ip="1.2.3.4"))
        assert not rule.matches(_event("x", user="root", source_ip="9.9.9.9"))

    def test_or(self) -> None:
        rule = self._two("a or b")
        assert rule.matches(_event("x", user="root", source_ip="9.9.9.9"))
        assert rule.matches(_event("x", user="nobody", source_ip="1.2.3.4"))
        assert not rule.matches(_event("x", user="nobody", source_ip="9.9.9.9"))

    def test_not(self) -> None:
        rule = self._two("a and not b")
        assert rule.matches(_event("x", user="root", source_ip="9.9.9.9"))
        assert not rule.matches(_event("x", user="root", source_ip="1.2.3.4"))

    def test_parentheses(self) -> None:
        rule = self._two("not (a or b)")
        assert rule.matches(_event("x", user="nobody", source_ip="9.9.9.9"))
        assert not rule.matches(_event("x", user="root", source_ip="9.9.9.9"))

    def test_one_of_them(self) -> None:
        rule = self._two("1 of them")
        assert rule.matches(_event("x", user="root", source_ip="9.9.9.9"))
        assert not rule.matches(_event("x", user="nobody", source_ip="9.9.9.9"))

    def test_all_of_them(self) -> None:
        rule = self._two("all of them")
        assert rule.matches(_event("x", user="root", source_ip="1.2.3.4"))
        assert not rule.matches(_event("x", user="root", source_ip="9.9.9.9"))

    def test_one_of_pattern(self) -> None:
        rule = build_rule(
            {
                "title": "T",
                "detection": {
                    "sel_a": {"user": "root"},
                    "sel_b": {"user": "admin"},
                    "other": {"user": "eve"},
                    "condition": "1 of sel_*",
                },
            }
        )
        assert rule.matches(_event("x", user="admin"))
        assert not rule.matches(_event("x", user="eve"))  # 'other' is excluded by the glob

    def test_condition_list_is_or(self) -> None:
        rule = self._two(["a", "b"])  # type: ignore[arg-type]
        assert rule.matches(_event("x", user="root", source_ip="9.9.9.9"))
        assert rule.matches(_event("x", user="nobody", source_ip="1.2.3.4"))


class TestMetadataMapping:
    def test_level_maps_to_severity(self) -> None:
        for level, sev in [("informational", "info"), ("low", "low"), ("critical", "critical")]:
            rule = build_rule(
                {"title": "T", "level": level, "detection": {"s": {"user": "x"}, "condition": "s"}}
            )
            assert rule.severity.value == sev

    def test_missing_level_defaults_medium(self) -> None:
        rule = build_rule({"title": "T", "detection": {"s": {"user": "x"}, "condition": "s"}})
        assert rule.severity.value == "medium"

    def test_attack_tags_become_techniques(self) -> None:
        rule = build_rule(
            {
                "title": "T",
                "tags": ["attack.t1110.001", "attack.credential_access", "attack.t1078"],
                "detection": {"s": {"user": "x"}, "condition": "s"},
            }
        )
        assert rule.attack_techniques == ["T1110.001", "T1078"]

    def test_id_becomes_rule_id_else_title(self) -> None:
        with_id = build_rule(
            {"title": "T", "id": "abc-123", "detection": {"s": {"user": "x"}, "condition": "s"}}
        )
        assert with_id.rule_id == "abc-123"
        without = build_rule(
            {"title": "MyTitle", "detection": {"s": {"user": "x"}, "condition": "s"}}
        )
        assert without.rule_id == "MyTitle"


class TestLogsourceNarrowing:
    def test_service_sudo_only_sees_privilege_escalation(self) -> None:
        rule = build_rule(
            {
                "title": "T",
                "logsource": {"product": "linux", "service": "sudo"},
                "detection": {"s": {"user": "root"}, "condition": "s"},
            }
        )
        assert rule.matches(_event("x", user="root", event_type=EventType.PRIVILEGE_ESCALATION))
        # Same fields, wrong event type for this logsource — must not match.
        assert not rule.matches(_event("x", user="root", event_type=EventType.LOGIN_SUCCESS))

    def test_unknown_logsource_sees_everything(self) -> None:
        rule = build_rule(
            {
                "title": "T",
                "logsource": {"product": "linux", "service": "exotic"},
                "detection": {"s": {"user": "root"}, "condition": "s"},
            }
        )
        assert rule.event_types is None
        assert rule.matches(_event("x", user="root", event_type=EventType.LOGIN_SUCCESS))

    def test_malformed_logsource_is_ignored_not_fatal(self) -> None:
        """A non-mapping logsource (advisory only) must not crash the loader."""
        for bad in ("linux", ["a"], 3):
            rule = build_rule(
                {
                    "title": "T",
                    "logsource": bad,
                    "detection": {"s": {"user": "x"}, "condition": "s"},
                }
            )
            assert rule.event_types is None
            assert rule.logsource == {}


class TestErrors:
    @pytest.mark.parametrize(
        "doc, fragment",
        [
            ({"detection": {"s": {"a": "b"}, "condition": "s"}}, "title"),
            ({"title": "T"}, "detection"),
            ({"title": "T", "detection": {"condition": "s"}}, "no selections"),
            ({"title": "T", "detection": {"s": {"a": "b"}}}, "condition"),
            ({"title": "T", "detection": {"s": {"a|base64": "b"}, "condition": "s"}}, "modifier"),
            (
                {"title": "T", "detection": {"s": {"a": "b"}, "condition": "s | count() > 3"}},
                "aggregation",
            ),
            (
                {"title": "T", "detection": {"s": {"a": "b"}, "timeframe": "5m", "condition": "s"}},
                "timeframe",
            ),
            ({"title": "T", "detection": {"s": {"a": "b"}, "condition": "unknown"}}, "unknown"),
            (
                {"title": "T", "detection": {"s": {"a": "b"}, "condition": "1 of zzz*"}},
                "no selection",
            ),
            (
                {"title": "T", "level": "bogus", "detection": {"s": {"a": "b"}, "condition": "s"}},
                "level",
            ),
            (
                {"title": "T", "detection": {"s": {"a": "b"}, "condition": "0 of them"}},
                "at least 1",
            ),
            ({"title": "T", "detection": {"s": {}, "condition": "s"}}, "empty"),
        ],
    )
    def test_clear_errors(self, doc: dict, fragment: str) -> None:
        with pytest.raises(SigmaError) as exc:
            build_rule(doc)
        assert fragment in str(exc.value)


class TestLoading:
    _RULE = """
title: Shadow read via sudo
id: 11111111-1111-1111-1111-111111111111
logsource:
  product: linux
  service: sudo
detection:
  selection:
    CommandLine|contains: /etc/shadow
  condition: selection
level: high
tags:
  - attack.t1003.008
"""

    def test_load_single_file(self, tmp_path: Path) -> None:
        path = tmp_path / "rule.yml"
        path.write_text(self._RULE, encoding="utf-8")
        detections = load_sigma_rules(path)
        assert len(detections) == 1
        assert detections[0].rule_id == "11111111-1111-1111-1111-111111111111"

    def test_load_multidocument_file(self, tmp_path: Path) -> None:
        path = tmp_path / "rules.yml"
        second = self._RULE.replace("11111111-1111-1111-1111-111111111111", "22222222")
        second = second.replace("Shadow read via sudo", "Second rule")
        path.write_text(self._RULE + "\n---\n" + second, encoding="utf-8")
        assert len(load_sigma_rules(path)) == 2

    def test_load_directory(self, tmp_path: Path) -> None:
        (tmp_path / "a.yml").write_text(self._RULE, encoding="utf-8")
        b = self._RULE.replace("11111111-1111-1111-1111-111111111111", "33333333")
        (tmp_path / "b.yaml").write_text(b, encoding="utf-8")
        (tmp_path / "ignore.txt").write_text("not a rule", encoding="utf-8")
        assert len(load_sigma_rules(tmp_path)) == 2

    def test_duplicate_id_is_rejected(self, tmp_path: Path) -> None:
        path = tmp_path / "dup.yml"
        path.write_text(self._RULE + "\n---\n" + self._RULE, encoding="utf-8")
        with pytest.raises(SigmaError, match="duplicate rule id"):
            load_sigma_rules(path)

    def test_end_to_end_scan(self, tmp_path: Path) -> None:
        from synth import brute_force_scenario

        rules_path = tmp_path / "rule.yml"
        rules_path.write_text(self._RULE, encoding="utf-8")
        evidence = tmp_path / "ev"
        evidence.mkdir()
        brute_force_scenario(evidence, year=2024)

        detections = load_sigma_rules(rules_path)
        result = scan([evidence], year=2024, extra_detections=detections)
        hits = [f for f in result.findings if f.rule_id == "11111111-1111-1111-1111-111111111111"]
        assert hits
        assert hits[0].severity.value == "high"
        assert hits[0].attack_techniques == ["T1003.008"]
        assert hits[0].metadata["sigma"] is True
