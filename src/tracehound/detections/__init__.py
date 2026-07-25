"""Detection rules.

Importing this package registers every built-in detection.
"""

from __future__ import annotations

from .base import (
    Detection,
    FactDetection,
    all_detections,
    all_fact_detections,
    order_findings,
    register,
    register_fact,
    run_all,
    run_all_facts,
)
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
from .state import (
    DuplicateRootDetection,
    ServiceAccountLoginShellDetection,
    SuspiciousAuthorizedKeyDetection,
    UnexpectedSudoGrantDetection,
    UnitFromWorldWritableDetection,
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
    "DuplicateRootDetection",
    "FactDetection",
    "LogGapDetection",
    "PasswordSprayDetection",
    "PrivilegedGroupDetection",
    "SensitiveSudoDetection",
    "ServiceAccountLoginShellDetection",
    "SuccessfulBruteForceDetection",
    "SuspiciousAuthorizedKeyDetection",
    "SuspiciousShellCommandDetection",
    "TruncatedRecordDetection",
    "UnexpectedSudoGrantDetection",
    "UnitFromWorldWritableDetection",
    "all_detections",
    "all_fact_detections",
    "order_findings",
    "register",
    "register_fact",
    "run_all",
    "run_all_facts",
]
