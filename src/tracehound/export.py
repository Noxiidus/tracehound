"""Interoperability exports: log2timeline CSV, Timesketch JSONL, and Sigma.

tracehound produces its own timeline in its own formats, but a triage tool that cannot
feed the platforms a DFIR shop already runs stays a curiosity. These renderers put a scan
into three standard shapes:

- **l2tcsv** — the log2timeline / plaso super-timeline CSV, so tracehound events drop into
  Timesketch alongside filesystem and browser timelines.
- **Timesketch JSONL** — the same events as newline-delimited JSON, with each finding's
  reasoning carried onto the events it implicates as tags and fields, so the *why* survives
  the export rather than just the *what*.
- **Sigma** — each finding rendered as a Sigma rule, so the conclusion can be forwarded to
  a SIEM and made to fire elsewhere.

The reverse direction — reading an l2tcsv super-timeline back in — lives in
:mod:`tracehound.parsers.l2tcsv`, so filesystem MACB timestamps can sit in the same
timeline the detections run over.
"""

from __future__ import annotations

import csv
import io
import json
import re
import uuid
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any

from .models import Event, Finding, Severity
from .timeline import TimelineLike

if TYPE_CHECKING:
    from .core import ScanResult

#: The canonical 17-column log2timeline CSV header, in order. Both the exporter here and
#: the importer in :mod:`tracehound.parsers.l2tcsv` are keyed off this exact sequence.
L2T_COLUMNS = [
    "date", "time", "timezone", "MACB", "source", "sourcetype", "type", "user", "host",
    "short", "desc", "version", "filename", "inode", "notes", "format", "extra",
]  # fmt: skip

L2T_HEADER = ",".join(L2T_COLUMNS)

# Sigma uses its own five-level vocabulary; map our severities onto it.
_SIGMA_LEVEL = {
    Severity.INFO: "informational",
    Severity.LOW: "low",
    Severity.MEDIUM: "medium",
    Severity.HIGH: "high",
    Severity.CRITICAL: "critical",
}

# A fixed namespace so a given finding always renders to the same Sigma rule id. Rules with
# a churning id look like different rules to a SIEM on every export.
_SIGMA_NS = uuid.UUID("6f9b1d2e-7a3c-5e4f-8b0a-1c2d3e4f5a6b")


def _findings_by_event(findings: list[Finding]) -> dict[int, list[Finding]]:
    """Map each event to the findings that cite it, keyed by object identity.

    Events in a finding are the same objects held in the timeline, so ``id()`` matches.
    They are not hashable by value (the dataclass is mutable), which is why identity is the
    right key here rather than the event itself.
    """
    index: dict[int, list[Finding]] = {}
    for finding in findings:
        for event in finding.events:
            index.setdefault(id(event), []).append(finding)
    return index


# Metadata keys that would either bloat or corrupt the extra column: the verbatim source
# line, and internal bookkeeping. Everything else scalar is carried so a re-import can
# reconstruct enough for the metadata-keyed detections to fire again.
_EXTRA_SKIP_KEYS = frozenset({"raw", "host"})


def _extra_pairs(event: Event) -> str:
    """The salient fields as ``key: value; ...``, plaso's ``extra`` convention.

    Carries the typed event fields plus any scalar metadata, so an exported super-timeline
    is not just a wall of messages — and so reading it back in gives the detections the same
    structured fields the original parser produced. A value containing the ``; `` separator
    is dropped rather than emitted, because a corrupt pair is worse than a missing one.
    """
    pairs: list[str] = []
    seen: set[str] = set()
    for key, value in (
        ("source_ip", event.source_ip),
        ("process", event.process),
        ("pid", event.pid),
        ("terminal", event.terminal),
    ):
        if value not in (None, ""):
            pairs.append(f"{key}: {value}")
            seen.add(key)
    for key, value in event.metadata.items():
        if key in _EXTRA_SKIP_KEYS or key in seen:
            continue
        if not isinstance(value, (str, int, bool)) or value in (None, ""):
            continue
        text = str(value)
        if "; " in text or "\n" in text:
            continue
        pairs.append(f"{key}: {text}")
    return "; ".join(pairs)


def render_l2tcsv(
    timeline: TimelineLike,
    findings: list[Finding],
    result: ScanResult | None = None,
) -> str:
    """Render the timeline as a log2timeline (l2tcsv) super-timeline.

    One row per event. The ``notes`` column carries the rule ids of any findings that cite
    the event, so an analyst scrolling the merged timeline in Timesketch can see which
    entries tracehound flagged without a second lookup.
    """
    by_event = _findings_by_event(findings)
    out = io.StringIO()
    writer = csv.writer(out, lineterminator="\n")
    writer.writerow(L2T_COLUMNS)

    for event in timeline:
        ts = event.timestamp
        notes = " ".join(sorted({f.rule_id for f in by_event.get(id(event), [])}))
        writer.writerow(
            [
                ts.strftime("%m/%d/%Y"),
                ts.strftime("%H:%M:%S"),
                "UTC",
                "",  # MACB — log events carry no filesystem timestamp flags
                "LOG",
                f"tracehound {event.source}",
                event.event_type.value,
                event.user or "-",
                str(event.metadata.get("host") or "-"),
                event.message[:80],
                event.message,
                "2",
                event.source,
                "-",
                notes,
                "tracehound",
                _extra_pairs(event),
            ]
        )
    return out.getvalue()


def render_timesketch_jsonl(
    timeline: TimelineLike,
    findings: list[Finding],
    result: ScanResult | None = None,
) -> str:
    """Render the timeline as Timesketch newline-delimited JSON.

    Each line is one event with the three fields Timesketch requires — ``datetime``,
    ``timestamp_desc``, ``message`` — plus tracehound's own fields. Where an event backs a
    finding, that finding's rule id, severity and ATT&CK techniques become ``tag`` entries
    and dedicated fields, so the reasoning rides along with the timeline.

    Fact-only findings have no event and therefore no place in a timeline; they are not
    emitted here. Nothing is invented to give them one — use the Sigma or JSON export to
    carry them.
    """
    by_event = _findings_by_event(findings)
    lines: list[str] = []

    for event in timeline:
        record: dict[str, Any] = {
            "datetime": event.timestamp.isoformat(),
            "timestamp_desc": event.event_type.value,
            "message": event.message,
            "data_type": f"tracehound:{event.source}",
            "source_short": "LOG",
        }
        if event.user:
            record["username"] = event.user
        if event.source_ip:
            record["source_ip"] = event.source_ip
        if event.process:
            record["process"] = event.process
        if event.pid is not None:
            record["pid"] = event.pid
        if event.terminal:
            record["terminal"] = event.terminal

        tags: list[str] = []
        cited = by_event.get(id(event), [])
        if cited:
            techniques: list[str] = []
            for finding in cited:
                tags.append(finding.rule_id)
                techniques.extend(finding.attack_techniques)
            tags.append("tracehound-finding")
            tags.append(f"severity-{max(cited, key=lambda f: f.severity.rank).severity.value}")
            record["tracehound_findings"] = [f.title for f in cited]
            record["tracehound_rules"] = sorted({f.rule_id for f in cited})
            if techniques:
                record["attack_techniques"] = sorted(set(techniques))
        if tags:
            record["tag"] = sorted(set(tags))

        lines.append(json.dumps(record))

    return "\n".join(lines) + ("\n" if lines else "")


# A conservatively "plain-safe" YAML scalar: starts alphanumeric, contains only characters
# that carry no structural meaning in block context, and does not trail whitespace. Anything
# else — a colon anywhere, a quote, a bracket, a leading dash — is single-quoted instead of
# reasoned about case by case, because a description ending in ':' is enough to break a plain
# scalar and there are too many such characters to enumerate safely.
_SAFE_PLAIN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 _./+@-]*$")
_YAML_RESERVED = frozenset({"true", "false", "null", "yes", "no", "on", "off", "~"})


def _sigma_scalar(value: Any) -> str:
    """Serialise one scalar as a valid single-line YAML value."""
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int):
        return str(value)
    # Newlines cannot appear in a single-line scalar; fold them to spaces before quoting.
    text = str(value).replace("\r", " ").replace("\n", " ")
    if text == "":
        return "''"
    if _SAFE_PLAIN.match(text) and text == text.rstrip() and text.lower() not in _YAML_RESERVED:
        return text
    return "'" + text.replace("'", "''") + "'"


def _sigma_yaml(node: Any, indent: int = 0) -> list[str]:
    """A minimal YAML emitter for the controlled shapes a Sigma rule is built from."""
    pad = "  " * indent
    lines: list[str] = []
    if isinstance(node, dict):
        for key, value in node.items():
            if isinstance(value, dict):
                lines.append(f"{pad}{key}:")
                lines.extend(_sigma_yaml(value, indent + 1))
            elif isinstance(value, list):
                lines.append(f"{pad}{key}:")
                for item in value:
                    lines.append(f"{pad}  - {_sigma_scalar(item)}")
            else:
                lines.append(f"{pad}{key}: {_sigma_scalar(value)}")
    return lines


def _sigma_tags(techniques: list[str]) -> list[str]:
    """MITRE technique ids to Sigma tags: ``T1110.001`` -> ``attack.t1110.001``."""
    return [f"attack.{t.lower()}" for t in techniques]


def _sigma_selection(finding: Finding) -> dict[str, Any]:
    """Build a detection selection from the metadata the rule actually keyed on.

    This is a faithful record of what tripped the rule, not a portable query — field names
    are tracehound's, and a SIEM engineer will map them to their schema. Emitting the true
    trigger is more honest than inventing a backend-specific one.
    """
    selection: dict[str, Any] = {}
    for key, value in finding.metadata.items():
        scalar = isinstance(value, (str, int, bool)) and value not in (None, "")
        homogeneous_list = (
            isinstance(value, list)
            and bool(value)
            and all(isinstance(v, (str, int)) for v in value)
        )
        if scalar or homogeneous_list:
            selection[key] = value
    return selection or {"rule_id": finding.rule_id}


def _sigma_rule(finding: Finding, generated: str) -> dict[str, Any]:
    service = ""
    if finding.facts:
        service = finding.facts[0].source
    elif finding.events:
        service = finding.events[0].source

    logsource: dict[str, Any] = {"product": "linux"}
    if service:
        logsource["service"] = service

    rule: dict[str, Any] = {
        "title": finding.title,
        "id": str(uuid.uuid5(_SIGMA_NS, f"{finding.rule_id}:{finding.title}")),
        "status": "experimental",
        "description": finding.description.splitlines()[0]
        if finding.description
        else finding.title,
        "references": [f"tracehound:{finding.rule_id}"],
        "author": "tracehound",
        "date": generated,
        "logsource": logsource,
        "detection": {"selection": _sigma_selection(finding), "condition": "selection"},
        "level": _SIGMA_LEVEL[finding.severity],
    }
    if finding.attack_techniques:
        rule["tags"] = _sigma_tags(finding.attack_techniques)
    return rule


def render_sigma(
    findings: list[Finding],
    result: ScanResult | None = None,
) -> str:
    """Render every finding as a Sigma rule, one YAML document per finding.

    Both event and fact findings are included — a Sigma rule needs no timestamp — so a
    state finding such as a duplicate UID-0 account is exported alongside the timeline ones.
    """
    generated = (result.started_at if result else datetime.now(timezone.utc)).strftime("%Y/%m/%d")
    documents: list[str] = []
    for finding in findings:
        body = "\n".join(_sigma_yaml(_sigma_rule(finding, generated)))
        documents.append(body)
    return "---\n" + "\n---\n".join(documents) + "\n" if documents else ""
