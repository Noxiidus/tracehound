"""Command-line interface."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from . import __version__, report
from .core import scan
from .detections import all_detections
from .models import Severity
from .parsers import all_parsers

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

    sub.add_parser("parsers", help="list available artifact parsers")
    sub.add_parser("rules", help="list available detection rules")
    return parser


def _cmd_scan(args: argparse.Namespace) -> int:
    missing = [p for p in args.paths if not p.exists()]
    if missing:
        for path in missing:
            print(f"error: no such file or directory: {path}", file=sys.stderr)
        return 2

    result = scan(args.paths, year=args.year)

    threshold = Severity(args.min_severity).rank
    findings = [f for f in result.findings if f.severity.rank >= threshold]

    if args.format == "json":
        output = report.render_json(result.timeline, findings)
    elif args.format == "csv":
        output = report.render_timeline_csv(result.timeline)
    elif args.format == "html":
        output = report.render_html(result.timeline, findings)
    else:
        output = report.render_text(result.timeline, findings)

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
    if args.command == "parsers":
        return _cmd_parsers()
    if args.command == "rules":
        return _cmd_rules()
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
