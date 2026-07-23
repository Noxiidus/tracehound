"""Command-line interface."""

from __future__ import annotations

import argparse
import sys
from datetime import timedelta
from pathlib import Path

from . import __version__, report
from .case import build_case
from .config import Config, ConfigError
from .core import scan
from .detections import all_detections
from .detections.base import Detection
from .models import Severity
from .parsers import all_parsers
from .rules import RuleError, load_rules

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
        choices=["text", "json", "csv", "html"],
        default="text",
        help="output format; csv emits the full timeline rather than findings",
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
        required=True,
        metavar="NAME=PATH",
        help="a host's evidence directory or file; repeat for each host",
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

    sub.add_parser("parsers", help="list available artifact parsers")
    sub.add_parser("rules", help="list available detection rules")
    return parser


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
    hosts = _parse_pairs(args.host, "host")
    if hosts is None:
        return 2

    sources: dict[str, list[Path]] = {}
    for name, raw_path in hosts.items():
        path = Path(raw_path)
        if not path.exists():
            print(f"error: no such file or directory: {path}", file=sys.stderr)
            return 2
        sources.setdefault(name, []).append(path)

    raw_offsets = _parse_pairs(args.clock_offset, "clock-offset")
    if raw_offsets is None:
        return 2

    offsets: dict[str, timedelta] = {}
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

    result = scan(args.paths, year=args.year, config=config, extra_detections=extra)

    threshold = Severity(args.min_severity).rank
    findings = [f for f in result.findings if f.severity.rank >= threshold]

    if args.format == "json":
        output = report.render_json(result.timeline, findings, result)
    elif args.format == "csv":
        output = report.render_timeline_csv(result.timeline)
    elif args.format == "html":
        output = report.render_html(result.timeline, findings, result)
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
    for parser in all_parsers():
        print(f"{parser.name:12} {parser.description}")
    return 0


def _cmd_rules() -> int:
    for detection in all_detections():
        techniques = ", ".join(detection.attack_techniques) or "—"
        print(f"{detection.rule_id}  {detection.severity.value:8}  {detection.title}")
        print(f"{'':10}{detection.description}")
        print(f"{'':10}ATT&CK: {techniques}\n")
    return 0


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command == "scan":
        return _cmd_scan(args)
    if args.command == "case":
        return _cmd_case(args)
    if args.command == "parsers":
        return _cmd_parsers()
    if args.command == "rules":
        return _cmd_rules()
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
