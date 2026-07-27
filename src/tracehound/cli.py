"""Command-line interface."""

from __future__ import annotations

import argparse
import sys
from datetime import timedelta
from pathlib import Path

from . import __version__, export, report
from .case import build_case
from .config import Config, ConfigError
from .core import scan
from .detections import all_detections, all_fact_detections
from .detections.base import Detection
from .manifest import Manifest, ManifestError
from .models import Severity
from .parsers import all_fact_parsers, all_parsers
from .rules import RuleError, load_rules
from .sigma import SigmaError, load_sigma_rules

_SEVERITY_ORDER = [Severity.INFO, Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="tracehound",
        description="Linux DFIR triage — build a timeline from host artifacts and "
        "surface attacker behaviour.",
    )
    parser.add_argument("--version", action="version", version=f"tracehound {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    scan_cmd = sub.add_parser("scan", help="parse artifacts and report findings")
    scan_cmd.add_argument("paths", nargs="+", type=Path, help="files or directories to scan")
    scan_cmd.add_argument(
        "--year",
        type=int,
        help="year to assume for syslog timestamps, which omit it "
        "(defaults to the current year — pass this for historic evidence)",
    )
    scan_cmd.add_argument(
        "-f",
        "--format",
        choices=["text", "json", "csv", "html", "l2tcsv", "timesketch", "sigma"],
        default="text",
        help="output format. text/json/html report findings; csv and l2tcsv emit the whole "
        "timeline (l2tcsv is the log2timeline/plaso super-timeline for Timesketch); "
        "timesketch emits Timesketch JSONL; sigma emits one Sigma rule per finding",
    )
    scan_cmd.add_argument("-o", "--output", type=Path, help="write to a file instead of stdout")
    scan_cmd.add_argument(
        "-c",
        "--config",
        type=Path,
        help="tuning config (JSON, or YAML with the [yaml] extra): allowlisted IPs and "
        "accounts, expected cron jobs, thresholds, disabled rules",
    )
    scan_cmd.add_argument(
        "-r",
        "--rules",
        type=Path,
        action="append",
        help="declarative rule file (JSON, or YAML with the [yaml] extra); repeatable",
    )
    scan_cmd.add_argument(
        "--sigma",
        type=Path,
        action="append",
        help="Sigma rule file or directory of rules (needs the [yaml] extra); a practical "
        "subset of the spec is supported. Repeatable",
    )
    scan_cmd.add_argument(
        "--min-severity",
        choices=[s.value for s in _SEVERITY_ORDER],
        default="info",
        help="suppress findings below this severity",
    )
    scan_cmd.add_argument(
        "--fail-on-findings",
        action="store_true",
        help="exit 1 if any finding survives filtering (useful in CI)",
    )

    case_cmd = sub.add_parser(
        "case",
        help="correlate several hosts as one investigation",
        description="Scan multiple hosts and report findings that only appear when their "
        "evidence is considered together: shared attacker infrastructure, accounts reused "
        "across machines, and which host was reached first.",
    )
    case_cmd.add_argument(
        "--host",
        action="append",
        default=[],
        metavar="NAME=PATH",
        help="a host's evidence directory or file; repeat for each host",
    )
    case_cmd.add_argument(
        "--manifest",
        action="append",
        default=[],
        type=Path,
        metavar="MANIFEST",
        help="a manifest.json from tracehound-collect; supplies the host name and its "
        "measured clock offset automatically. Repeatable, and combinable with --host",
    )
    case_cmd.add_argument(
        "--skip-verify",
        action="store_true",
        help="do not re-hash manifest artifacts before analysis",
    )
    case_cmd.add_argument(
        "--clock-offset",
        action="append",
        default=[],
        metavar="NAME=SECONDS",
        help="measured clock correction for a host, in seconds (positive if its clock "
        "ran slow). Hosts without one are treated as unverified and cross-host ordering "
        "is hedged accordingly",
    )
    case_cmd.add_argument("--year", type=int, help="year to assume for syslog timestamps")
    case_cmd.add_argument("-c", "--config", type=Path, help="tuning config")
    case_cmd.add_argument(
        "-f", "--format", choices=["text", "json"], default="text", help="output format"
    )
    case_cmd.add_argument("-o", "--output", type=Path, help="write to a file instead of stdout")

    verify_cmd = sub.add_parser(
        "verify",
        help="check collected evidence against its manifest",
        description="Re-hash every artifact listed in a collection manifest and compare "
        "against the digest recorded at collection time. A mismatch means the evidence "
        "changed after it left the host.",
    )
    verify_cmd.add_argument("manifest", type=Path, help="manifest.json from tracehound-collect")

    sub.add_parser("parsers", help="list available artifact parsers")
    sub.add_parser("rules", help="list available detection rules")
    return parser


def _cmd_verify(args: argparse.Namespace) -> int:
    try:
        manifest = Manifest.load(args.manifest)
    except ManifestError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    print(f"host      : {manifest.hostname} (collected by {manifest.collected_by})")
    print(f"collected : {manifest.started_at} .. {manifest.finished_at}")
    if manifest.clock_measured:
        offset = int(manifest.clock_offset.total_seconds())  # type: ignore[union-attr]
        print(f"clock     : {offset:+d}s — {manifest.clock_note}")
    else:
        print(f"clock     : not measured — {manifest.clock_note}")
    print(f"artifacts : {len(manifest.artifacts)} collected, {len(manifest.skipped)} skipped")

    issues = manifest.verify()
    if not issues:
        print(f"\nOK — all {len(manifest.artifacts)} artifact(s) match the manifest.")
        return 0

    print(f"\nFAILED — {len(issues)} artifact(s) do not match:", file=sys.stderr)
    for issue in issues:
        print(f"  {issue.describe()}", file=sys.stderr)
    return 1


def _parse_pairs(values: list[str], what: str) -> dict[str, str] | None:
    pairs: dict[str, str] = {}
    for item in values:
        name, sep, value = item.partition("=")
        if not sep or not name.strip() or not value.strip():
            print(f"error: --{what} expects NAME=VALUE, got {item!r}", file=sys.stderr)
            return None
        pairs[name.strip()] = value.strip()
    return pairs


def _cmd_case(args: argparse.Namespace) -> int:
    if not args.host and not args.manifest:
        print("error: give at least one --host or --manifest", file=sys.stderr)
        return 2

    hosts = _parse_pairs(args.host, "host")
    if hosts is None:
        return 2

    sources: dict[str, list[Path]] = {}
    offsets: dict[str, timedelta] = {}

    for manifest_path in args.manifest:
        try:
            manifest = Manifest.load(manifest_path)
        except ManifestError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2

        if not args.skip_verify:
            issues = manifest.verify()
            if issues:
                print(
                    f"error: {manifest.hostname}: {len(issues)} artifact(s) do not match "
                    f"the manifest recorded at collection time:",
                    file=sys.stderr,
                )
                for issue in issues:
                    print(f"  {issue.describe()}", file=sys.stderr)
                print(
                    "The evidence changed after it left the host. Investigate the "
                    "handling chain, or pass --skip-verify to proceed anyway.",
                    file=sys.stderr,
                )
                return 3

        sources.setdefault(manifest.hostname, []).extend(manifest.artifact_paths())
        if manifest.clock_offset is not None:
            offsets[manifest.hostname] = manifest.clock_offset

    for name, raw_path in hosts.items():
        path = Path(raw_path)
        if not path.exists():
            print(f"error: no such file or directory: {path}", file=sys.stderr)
            return 2
        sources.setdefault(name, []).append(path)

    raw_offsets = _parse_pairs(args.clock_offset, "clock-offset")
    if raw_offsets is None:
        return 2

    for name, seconds in raw_offsets.items():
        if name not in sources:
            print(f"error: --clock-offset names unknown host {name!r}", file=sys.stderr)
            return 2
        try:
            offsets[name] = timedelta(seconds=float(seconds))
        except ValueError:
            print(f"error: clock offset for {name!r} must be a number", file=sys.stderr)
            return 2

    config = Config()
    if args.config:
        try:
            config = Config.load(args.config)
        except ConfigError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2

    case = build_case(sources, year=args.year, config=config, offsets=offsets)

    output = (
        report.render_case_json(case) if args.format == "json" else report.render_case_text(case)
    )

    if args.output:
        args.output.write_text(output, encoding="utf-8")
        print(f"wrote {args.output}", file=sys.stderr)
    else:
        print(output)
    return 0


def _cmd_scan(args: argparse.Namespace) -> int:
    missing = [p for p in args.paths if not p.exists()]
    if missing:
        for path in missing:
            print(f"error: no such file or directory: {path}", file=sys.stderr)
        return 2

    config = Config()
    if args.config:
        try:
            config = Config.load(args.config)
        except ConfigError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2

    extra: list[Detection] = []
    for rule_file in args.rules or []:
        try:
            extra.extend(load_rules(rule_file))
        except RuleError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2

    for sigma_path in args.sigma or []:
        try:
            extra.extend(load_sigma_rules(sigma_path))
        except SigmaError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2

    result = scan(args.paths, year=args.year, config=config, extra_detections=extra)

    threshold = Severity(args.min_severity).rank
    findings = [f for f in result.findings if f.severity.rank >= threshold]

    if args.format == "json":
        output = report.render_json(result.timeline, findings, result)
    elif args.format == "csv":
        output = report.render_timeline_csv(result.timeline)
    elif args.format == "html":
        output = report.render_html(result.timeline, findings, result)
    elif args.format == "l2tcsv":
        output = export.render_l2tcsv(result.timeline, findings, result)
    elif args.format == "timesketch":
        output = export.render_timesketch_jsonl(result.timeline, findings, result)
    elif args.format == "sigma":
        output = export.render_sigma(findings, result)
    else:
        output = report.render_text(result.timeline, findings, result)

    if args.output:
        args.output.write_text(output, encoding="utf-8")
        print(f"wrote {args.output}", file=sys.stderr)
    else:
        print(output)

    if not result.parsed:
        print("warning: no artifacts were recognised", file=sys.stderr)

    return 1 if (args.fail_on_findings and findings) else 0


def _cmd_parsers() -> int:
    print("Event parsers (build the timeline):")
    for parser in all_parsers():
        print(f"  {parser.name:16} {parser.description}")
    print("\nState parsers (build the fact base):")
    for fact_parser in all_fact_parsers():
        print(f"  {fact_parser.name:16} {fact_parser.description}")
    return 0


def _cmd_rules() -> int:
    rules = [
        (d.rule_id, d.severity.value, d.title, d.description, d.attack_techniques)
        for d in all_detections()
    ] + [
        (d.rule_id, d.severity.value, d.title, d.description, d.attack_techniques)
        for d in all_fact_detections()
    ]
    for rule_id, severity, title, description, attack_techniques in sorted(rules):
        techniques = ", ".join(attack_techniques) or "—"
        print(f"{rule_id}  {severity:8}  {title}")
        print(f"{'':10}{description}")
        print(f"{'':10}ATT&CK: {techniques}\n")
    return 0


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command == "scan":
        return _cmd_scan(args)
    if args.command == "case":
        return _cmd_case(args)
    if args.command == "verify":
        return _cmd_verify(args)
    if args.command == "parsers":
        return _cmd_parsers()
    if args.command == "rules":
        return _cmd_rules()
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
