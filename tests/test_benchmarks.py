"""A throughput regression guard (0.9.x Scale).

Not a micro-benchmark — CI runners are shared and wall-clock is noisy — but a catastrophe
detector: 20k events must scan on either backend well inside a generous ceiling, so an
accidental O(n^2) or a per-event commit slipping in is caught rather than discovered on a
real, million-line host. It also asserts the two backends agree at scale.
"""

from __future__ import annotations

import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

from synth import syslog_line
from tracehound import scan

_N = 20_000
_IN_MEMORY_CEILING_S = 15.0
_SQLITE_CEILING_S = 30.0


def _big_auth_log(path: Path, n: int) -> Path:
    base = datetime(2024, 3, 6, 6, 0, 0, tzinfo=timezone.utc)
    ips = ["65.2.161.68", "10.0.0.9", "203.0.113.5"]
    with path.open("w", encoding="utf-8") as fh:
        for i in range(n):
            fh.write(
                syslog_line(
                    base + timedelta(seconds=i),
                    "sshd",
                    f"Failed password for invalid user u{i % 50} from {ips[i % 3]} "
                    f"port {2000 + i % 500} ssh2",
                    pid=1000 + i,
                )
                + "\n"
            )
    return path


def test_throughput_and_scale_equivalence(tmp_path: Path) -> None:
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    _big_auth_log(evidence / "auth.log", _N)

    start = time.perf_counter()
    mem = scan([evidence], year=2024)
    mem_elapsed = time.perf_counter() - start

    start = time.perf_counter()
    disk = scan([evidence], year=2024, on_disk=tmp_path / "tl.db")
    disk_elapsed = time.perf_counter() - start

    # Correctness at scale: every line parsed, both backends agree.
    assert len(mem.timeline) == _N
    assert len(disk.timeline) == _N
    assert sorted((f.rule_id, f.title) for f in mem.findings) == sorted(
        (f.rule_id, f.title) for f in disk.findings
    )

    # Catastrophe guard, not a micro-benchmark — the ceilings are ~100x local runtime.
    assert mem_elapsed < _IN_MEMORY_CEILING_S, f"in-memory scan took {mem_elapsed:.1f}s"
    assert disk_elapsed < _SQLITE_CEILING_S, f"sqlite scan took {disk_elapsed:.1f}s"
