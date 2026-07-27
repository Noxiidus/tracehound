"""tracehound — Linux DFIR triage.

Parses host artifacts into a single UTC-normalised timeline and applies detection
rules that surface attacker behaviour, with MITRE ATT&CK mappings.

Typical use::

    from pathlib import Path
    from tracehound import scan

    result = scan([Path("/var/log/auth.log"), Path("/var/log/wtmp")], year=2024)
    for finding in result.findings:
        print(finding.severity.value, finding.title)
"""

from __future__ import annotations

__version__ = "0.8.3"

from .case import Case, Host, build_case
from .config import Config
from .core import ScanResult, scan
from .export import render_l2tcsv, render_sigma, render_timesketch_jsonl
from .factbase import FactBase
from .models import Event, EventType, Fact, Finding, Severity
from .sigma import load_sigma_rules
from .timeline import Timeline

__all__ = [
    "Case",
    "Config",
    "Event",
    "EventType",
    "Fact",
    "FactBase",
    "Finding",
    "Host",
    "ScanResult",
    "Severity",
    "Timeline",
    "__version__",
    "build_case",
    "load_sigma_rules",
    "render_l2tcsv",
    "render_sigma",
    "render_timesketch_jsonl",
    "scan",
]
