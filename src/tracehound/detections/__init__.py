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
from .persistence import (
    AccountCreationDetection,
    BackdoorAccountDetection,
    PrivilegedGroupDetection,
    SensitiveSudoDetection,
)

__all__ = [
    "AccountCreationDetection",
    "BackdoorAccountDetection",
    "BruteForceDetection",
    "Detection",
    "PasswordSprayDetection",
    "PrivilegedGroupDetection",
    "SensitiveSudoDetection",
    "SuccessfulBruteForceDetection",
    "all_detections",
    "register",
    "run_all",
]
