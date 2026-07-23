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

__version__ = "0.5.0"

from .case import Case, Host, build_case
from .config import Config
from .core import ScanResult, scan
from .models import Event, EventType, Finding, Severity
from .timeline import Timeline

__all__ = [
    "Case",
    "Config",
    "Event",
    "EventType",
    "Finding",
    "Host",
    "ScanResult",
    "Severity",
    "Timeline",
    "__version__",
    "build_case",
    "scan",
]
