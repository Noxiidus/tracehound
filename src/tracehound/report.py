"""Report rendering: text, JSON, CSV and standalone HTML."""

from __future__ import annotations

import csv
import html
import io
import json
from datetime import datetime, timezone
from typing import TYPE_CHECKING

from . import attack
from .models import Finding, Severity
from .timeline import Timeline

if TYPE_CHECKING:
    from .case import Case
    from .core import ScanResult

_SEVERITY_COLOUR = {
    Severity.CRITICAL: "#b31d28",
    Severity.HIGH: "#d1541f",
    Severity.MEDIUM: "#b08800",
    Severity.LOW: "#2c6fbb",
    Severity.INFO: "#6a737d",
}


def _fmt(dt: datetime | None) -> str:
    return dt.strftime("%Y-%m-%d %H:%M:%S") if dt else "—"


def _html_facts_row(result: ScanResult | None) -> str:
    if result is None or not result.factbase.facts:
        return ""
    fb = result.factbase
    return f"<dt>State facts</dt><dd>{len(fb)} across {len(fb.subjects())} subjects</dd>"


def render_text(
    timeline: Timeline,
    findings: list[Finding],
    result: ScanResult | None = None,
) -> str:
    out = io.StringIO()
    out.write("tracehound report\n")
    out.write("=" * 70 + "\n\n")

    out.write(f"Events parsed : {len(timeline)}\n")
    out.write(f"Time range    : {_fmt(timeline.start)} .. {_fmt(timeline.end)} UTC\n")
    sources = ", ".join(f"{name} ({count})" for name, count in sorted(timeline.sources().items()))
    out.write(f"Sources       : {sources or '—'}\n")
    if result is not None and result.factbase.facts:
        fb = result.factbase
        state_sources = ", ".join(f"{n} ({c})" for n, c in sorted(fb.sources().items()))
        out.write(f"State facts   : {len(fb)} across {len(fb.subjects())} subjects\n")
        out.write(f"State sources : {state_sources}\n")
    out.write(f"Findings      : {len(findings)}\n")

    if result is not None:
        out.write(f"Tool version  : tracehound {result.tool_version}\n")
        out.write(f"Scanned at    : {result.started_at.strftime('%Y-%m-%d %H:%M:%S')} UTC\n")
        out.write("\nEvidence examined\n")
        out.write("-" * 70 + "\n")
        for record in result.artifacts:
            status = record.parser if record.parsed else f"SKIPPED — {record.skipped_reason}"
            yielded = (
                f"{record.fact_count} facts"
                if record.fact_count
                else f"{record.event_count} events"
            )
            out.write(f"  {record.path}\n")
            out.write(
                f"      sha256={record.sha256 or '—'}  {record.size} bytes  [{status}, {yielded}]\n"
            )
    out.write("\n")

    if not findings:
        out.write("No findings. This is not proof of a clean host — only that no rule matched.\n")
        return out.getvalue()

    for index, finding in enumerate(findings, start=1):
        out.write("-" * 70 + "\n")
        out.write(f"[{index}] {finding.severity.value.upper()}  {finding.title}\n")
        out.write(f"    rule    : {finding.rule_id}\n")
        out.write(f"    window  : {_fmt(finding.first_seen)} .. {_fmt(finding.last_seen)} UTC\n")
        if finding.attack_techniques:
            out.write("    ATT&CK  : \n")
            for technique in finding.attack_techniques:
                out.write(f"              {attack.describe(technique)}\n")
        out.write("\n")
        for line in finding.description.splitlines():
            out.write(f"    {line}\n")
        if finding.facts:
            out.write(f"\n    Supporting facts ({len(finding.facts)}):\n")
            for fact in finding.facts[:6]:
                out.write(f"      {fact.subject}  {fact.attribute}={fact.value[:70]}\n")
            if len(finding.facts) > 6:
                out.write(f"      ... and {len(finding.facts) - 6} more\n")
        else:
            out.write(f"\n    Supporting events ({len(finding.events)}):\n")
            for event in finding.events[:5]:
                out.write(f"      {_fmt(event.timestamp)}  {event.message[:80]}\n")
            if len(finding.events) > 5:
                out.write(f"      ... and {len(finding.events) - 5} more\n")
        out.write("\n")

    return out.getvalue()


def render_json(
    timeline: Timeline,
    findings: list[Finding],
    result: ScanResult | None = None,
    *,
    include_events: bool = True,
) -> str:
    summary: dict[str, object] = {
        "event_count": len(timeline),
        "start": timeline.start.isoformat() if timeline.start else None,
        "end": timeline.end.isoformat() if timeline.end else None,
        "sources": timeline.sources(),
        "finding_count": len(findings),
    }
    if result is not None and result.factbase.facts:
        summary["fact_count"] = len(result.factbase)
        summary["fact_subjects"] = len(result.factbase.subjects())
        summary["fact_sources"] = result.factbase.sources()
    payload: dict[str, object] = {
        "tool": "tracehound",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "summary": summary,
        "findings": [f.to_dict(include_events=include_events) for f in findings],
    }
    if result is not None:
        payload["provenance"] = result.provenance()
    return json.dumps(payload, indent=2)


def render_case_text(case: Case) -> str:
    """Render a multi-host investigation."""
    out = io.StringIO()
    out.write("tracehound case report\n")
    out.write("=" * 70 + "\n\n")

    merged = case.merged_timeline()
    out.write(f"Hosts         : {len(case.hosts)}\n")
    out.write(f"Events (all)  : {len(merged)}\n")
    out.write(f"Time range    : {_fmt(merged.start)} .. {_fmt(merged.end)} UTC\n")
    out.write(f"Cross-host    : {len(case.findings)} finding(s)\n")
    out.write(
        "Clocks        : "
        + ("all verified\n" if case.all_clocks_verified else "NOT all verified\n")
    )

    out.write("\nHosts\n")
    out.write("-" * 70 + "\n")
    for host in case.hosts:
        offset = int(host.clock_offset.total_seconds())
        out.write(
            f"  {host.name:20} {len(host.result.timeline):5} events  "
            f"{len(host.result.findings):3} findings  "
            f"clock {offset:+d}s ({host.clock_confidence})\n"
        )

    if not case.findings:
        out.write("\nNo cross-host findings. Single-host findings are reported per host.\n")
    else:
        out.write("\nCross-host findings\n")
        for index, finding in enumerate(case.findings, start=1):
            out.write("-" * 70 + "\n")
            out.write(f"[{index}] {finding.severity.value.upper()}  {finding.title}\n")
            out.write(f"    rule    : {finding.rule_id}\n")
            out.write(
                f"    window  : {_fmt(finding.first_seen)} .. {_fmt(finding.last_seen)} UTC\n"
            )
            if finding.attack_techniques:
                out.write("    ATT&CK  : \n")
                for technique in finding.attack_techniques:
                    out.write(f"              {attack.describe(technique)}\n")
            out.write("\n")
            for line in finding.description.splitlines():
                out.write(f"    {line}\n")
            out.write("\n")

    out.write("\nPer-host findings\n")
    out.write("=" * 70 + "\n")
    for host in case.hosts:
        out.write(f"\n### {host.name}\n\n")
        if not host.result.findings:
            out.write("  (none)\n")
            continue
        for finding in host.result.findings:
            out.write(
                f"  [{finding.severity.value.upper():8}] {finding.rule_id}  {finding.title}\n"
            )

    return out.getvalue()


def render_case_json(case: Case) -> str:
    merged = case.merged_timeline()
    payload = {
        "tool": "tracehound",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "summary": {
            "host_count": len(case.hosts),
            "event_count": len(merged),
            "start": merged.start.isoformat() if merged.start else None,
            "end": merged.end.isoformat() if merged.end else None,
            "cross_host_finding_count": len(case.findings),
            "all_clocks_verified": case.all_clocks_verified,
        },
        "cross_host_findings": [f.to_dict() for f in case.findings],
        "hosts": [
            {
                **host.to_dict(),
                "findings": [f.to_dict(include_events=False) for f in host.result.findings],
            }
            for host in case.hosts
        ],
    }
    return json.dumps(payload, indent=2)


def render_timeline_csv(timeline: Timeline) -> str:
    out = io.StringIO()
    writer = csv.writer(out, lineterminator="\n")
    writer.writerow(
        ["timestamp_utc", "source", "event_type", "user", "source_ip", "process", "message"]
    )
    for event in timeline:
        writer.writerow(
            [
                event.timestamp.strftime("%Y-%m-%d %H:%M:%S"),
                event.source,
                event.event_type.value,
                event.user or "",
                event.source_ip or "",
                event.process or "",
                event.message,
            ]
        )
    return out.getvalue()


def render_html(
    timeline: Timeline,
    findings: list[Finding],
    result: ScanResult | None = None,
) -> str:
    rows = []
    for finding in findings:
        techniques = "".join(
            f'<li><a href="{attack.lookup(t).url}" target="_blank" rel="noopener">'  # type: ignore[union-attr]
            f"{html.escape(attack.describe(t))}</a></li>"
            if attack.lookup(t)
            else f"<li>{html.escape(t)}</li>"
            for t in finding.attack_techniques
        )
        if finding.facts:
            evidence_meta = f"{len(finding.facts)} fact(s)"
            body_rows = "".join(
                f"<tr><td>{html.escape(f.subject)}</td><td>{html.escape(f.attribute)}</td>"
                f"<td>{html.escape(f.value[:120])}</td></tr>"
                for f in finding.facts[:12]
            )
            table = (
                "<table><thead><tr><th>Subject</th><th>Attribute</th><th>Value</th></tr>"
                f"</thead><tbody>{body_rows}</tbody></table>"
            )
        else:
            evidence_meta = f"{len(finding.events)} event(s)"
            body_rows = "".join(
                f"<tr><td>{_fmt(e.timestamp)}</td><td>{html.escape(e.source)}</td>"
                f"<td>{html.escape(e.message[:120])}</td></tr>"
                for e in finding.events[:10]
            )
            table = (
                "<table><thead><tr><th>Time (UTC)</th><th>Source</th><th>Event</th></tr>"
                f"</thead><tbody>{body_rows}</tbody></table>"
            )
        rows.append(f"""
        <article class="finding">
          <header style="border-left-color:{_SEVERITY_COLOUR[finding.severity]}">
            <span class="sev" style="background:{_SEVERITY_COLOUR[finding.severity]}">
              {finding.severity.value.upper()}</span>
            <h2>{html.escape(finding.title)}</h2>
            <p class="meta">{html.escape(finding.rule_id)} &middot;
               {_fmt(finding.first_seen)} .. {_fmt(finding.last_seen)} UTC &middot;
               {evidence_meta}</p>
          </header>
          <p class="desc">{html.escape(finding.description)}</p>
          {f"<ul class='attack'>{techniques}</ul>" if techniques else ""}
          {table}
        </article>""")

    sources = ", ".join(f"{n} ({c})" for n, c in sorted(timeline.sources().items()))
    body = "".join(rows) or "<p class='empty'>No findings matched.</p>"

    evidence = ""
    if result is not None:
        entries = "".join(
            f"<tr><td>{html.escape(str(r.path))}</td>"
            f"<td class='mono'>{html.escape(r.sha256[:16] or '—')}…</td>"
            f"<td>{r.size}</td>"
            f"<td>{html.escape(r.parser or 'skipped: ' + (r.skipped_reason or ''))}</td>"
            f"<td>{r.fact_count or r.event_count}</td></tr>"
            for r in result.artifacts
        )
        evidence = f"""
        <details class="evidence"><summary>Evidence examined
          ({len(result.parsed)} parsed, {len(result.skipped)} skipped)</summary>
          <table><thead><tr><th>File</th><th>SHA-256</th><th>Bytes</th>
          <th>Parser</th><th>Records</th></tr></thead><tbody>{entries}</tbody></table>
          <p class="meta">tracehound {html.escape(result.tool_version)} &middot; scanned
          {_fmt(result.started_at)} UTC</p>
        </details>"""

    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>tracehound report</title>
<style>
  :root {{ color-scheme: light dark; }}
  body {{ font: 15px/1.6 system-ui, sans-serif; margin: 0; padding: 2rem;
         max-width: 1000px; margin-inline: auto; }}
  h1 {{ margin: 0 0 .25rem; font-size: 1.6rem; }}
  .summary {{ border: 1px solid #8884; border-radius: 8px; padding: 1rem;
              margin-bottom: 2rem; }}
  .summary dl {{ display: grid; grid-template-columns: max-content 1fr;
                 gap: .35rem 1rem; margin: 0; }}
  .summary dt {{ font-weight: 600; opacity: .75; }}
  .summary dd {{ margin: 0; }}
  .finding {{ border: 1px solid #8884; border-radius: 8px; margin-bottom: 1.5rem;
              overflow: hidden; }}
  .finding header {{ border-left: 5px solid; padding: 1rem 1rem .5rem; }}
  .finding h2 {{ font-size: 1.1rem; margin: .5rem 0 .25rem; }}
  .sev {{ color: #fff; font-size: .72rem; font-weight: 700; letter-spacing: .04em;
          padding: .15rem .5rem; border-radius: 3px; }}
  .meta {{ font-size: .82rem; opacity: .7; margin: 0; }}
  .desc {{ padding: 0 1rem; white-space: pre-wrap; }}
  .attack {{ padding: 0 1rem 0 2.2rem; font-size: .88rem; }}
  table {{ width: 100%; border-collapse: collapse; font-size: .84rem; }}
  th, td {{ text-align: left; padding: .4rem .6rem; border-top: 1px solid #8883; }}
  th {{ opacity: .7; font-weight: 600; }}
  td:first-child {{ white-space: nowrap; font-variant-numeric: tabular-nums; }}
  .empty {{ opacity: .7; }}
  .evidence {{ border: 1px solid #8884; border-radius: 8px; padding: .75rem 1rem;
               margin-bottom: 1.5rem; }}
  .evidence summary {{ cursor: pointer; font-weight: 600; }}
  .mono {{ font-family: ui-monospace, monospace; font-size: .78rem; }}
  footer {{ margin-top: 2rem; font-size: .8rem; opacity: .6; }}
</style></head><body>
<h1>tracehound report</h1>
<div class="summary"><dl>
  <dt>Events</dt><dd>{len(timeline)}</dd>
  <dt>Range</dt><dd>{_fmt(timeline.start)} .. {_fmt(timeline.end)} UTC</dd>
  <dt>Sources</dt><dd>{html.escape(sources) or "&mdash;"}</dd>
  {_html_facts_row(result)}
  <dt>Findings</dt><dd>{len(findings)}</dd>
</dl></div>
{evidence}
{body}
<footer>All timestamps are UTC. Absence of findings is not evidence of a clean host.</footer>
</body></html>"""
