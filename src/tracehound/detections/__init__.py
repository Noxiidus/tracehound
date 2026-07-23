"""Detection rules.

Importing this package registers every built-in detection.
"""

from __future__ import annotations

from .base import Detection, all_detections, register, run_all
from .bruteforce import (
    BruteForceDetection,
    PasswordSprayDetection,
    SuccessfulBruteForceDetection,
)
from .execution import (
    CronPersistenceDetection,
    SuspiciousShellCommandDetection,
)
from .persistence import (
    AccountCreationDetection,
    BackdoorAccountDetection,
    PrivilegedGroupDetection,
    SensitiveSudoDetection,
)
from .tampering import (
    ClearedHistoryDetection,
    LogGapDetection,
    TruncatedRecordDetection,
)

__all__ = [
    "AccountCreationDetection",
    "BackdoorAccountDetection",
    "BruteForceDetection",
    "ClearedHistoryDetection",
    "CronPersistenceDetection",
    "Detection",
    "LogGapDetection",
    "PasswordSprayDetection",
    "PrivilegedGroupDetection",
    "SensitiveSudoDetection",
    "SuccessfulBruteForceDetection",
    "SuspiciousShellCommandDetection",
    "TruncatedRecordDetection",
    "all_detections",
    "register",
    "run_all",
]
