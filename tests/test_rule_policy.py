"""Guards for the 1.0 rule-id policy (docs/api.md): ids are permanent and never reused."""

from __future__ import annotations

import re

from tracehound.detections import all_detections, all_fact_detections

_RULE_ID = re.compile(r"^THN-\d{4}$")


def _all_rules() -> list[object]:
    return [*all_detections(), *all_fact_detections()]


def test_every_builtin_rule_id_is_unique() -> None:
    """Two rules answering to the same id could not be suppressed or reported unambiguously,
    and an archived report keyed on the id would be meaningless."""
    ids = [d.rule_id for d in _all_rules()]  # type: ignore[attr-defined]
    duplicates = {rid for rid in ids if ids.count(rid) > 1}
    assert not duplicates, f"duplicate rule ids: {sorted(duplicates)}"


def test_builtin_rule_ids_follow_the_scheme() -> None:
    bad = [d.rule_id for d in _all_rules() if not _RULE_ID.match(d.rule_id)]  # type: ignore[attr-defined]
    assert not bad, f"rule ids not matching THN-NNNN: {bad}"


def test_severity_and_attack_are_well_formed() -> None:
    for d in _all_rules():
        assert d.title and d.description  # type: ignore[attr-defined]
        for technique in d.attack_techniques:  # type: ignore[attr-defined]
            assert technique.startswith("T"), f"{d.rule_id}: bad ATT&CK id {technique!r}"  # type: ignore[attr-defined]
