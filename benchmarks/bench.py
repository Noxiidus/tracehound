#!/usr/bin/env python3
"""Throughput benchmark for the two timeline backends.

Generates a synthetic ``auth.log`` of N credential-attack lines, then times a full
``scan`` — parse, build the timeline, run every detection — against both the in-memory and
the on-disk SQLite backend, and prints events/second for each.

    python benchmarks/bench.py [N]        # default 100000

This is a profiling aid, not a pass/fail gate — the CI regression guard lives in
``tests/test_benchmarks.py`` with a generous ceiling. Numbers here are only comparable
against other runs on the same machine.
"""

from __future__ import annotations

import sys
import tempfile
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

from tracehound import scan

_MONTHS = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"]
_IPS = ["65.2.161.68", "10.0.0.9", "203.0.113.5", "198.51.100.22"]


def generate(path: Path, n: int) -> None:
    base = datetime(2024, 3, 6, 6, 0, 0, tzinfo=timezone.utc)
    with path.open("w", encoding="utf-8") as fh:
        for i in range(n):
            ts = base + timedelta(seconds=i)
            stamp = f"{_MONTHS[ts.month - 1]} {ts.day:2d} {ts:%H:%M:%S}"
            ip = _IPS[i % len(_IPS)]
            fh.write(
                f"{stamp} host sshd[{1000 + i}]: Failed password for invalid user "
                f"u{i % 50} from {ip} port {2000 + i % 500} ssh2\n"
            )


def _time_scan(evidence: Path, **kwargs: object) -> tuple[float, int, int]:
    start = time.perf_counter()
    result = scan([evidence], year=2024, **kwargs)  # type: ignore[arg-type]
    elapsed = time.perf_counter() - start
    return elapsed, len(result.timeline), len(result.findings)


def main(argv: list[str]) -> int:
    n = int(argv[0]) if argv else 100_000
    workdir = Path(tempfile.mkdtemp(prefix="tracehound-bench-"))
    evidence = workdir / "auth.log"
    print(f"generating {n:,} auth.log lines ...")
    generate(evidence, n)
    print(f"  {evidence.stat().st_size / 1e6:.1f} MB\n")

    mem_t, mem_events, mem_findings = _time_scan(evidence)
    sql_t, sql_events, sql_findings = _time_scan(evidence, on_disk=str(workdir / "tl.db"))

    print(f"{'backend':<12}{'seconds':>10}{'events/s':>14}{'events':>10}{'findings':>10}")
    print("-" * 56)
    for name, secs, events, findings in (
        ("in-memory", mem_t, mem_events, mem_findings),
        ("sqlite", sql_t, sql_events, sql_findings),
    ):
        rate = events / secs if secs else 0.0
        print(f"{name:<12}{secs:>10.3f}{rate:>14,.0f}{events:>10,}{findings:>10}")

    if (mem_events, mem_findings) != (sql_events, sql_findings):
        print("\nWARNING: backends disagree on event/finding counts", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
