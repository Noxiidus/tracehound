"""Artifact parsers.

Importing this package registers every built-in parser. Selection order is governed by
each parser's ``priority``, not by import order — see :class:`~.base.Parser`.
"""

from __future__ import annotations

from .authlog import AuthLogParser, classify_message
from .authorized_keys import AuthorizedKeysParser
from .base import (
    FactParser,
    ParseContext,
    Parser,
    all_fact_parsers,
    all_parsers,
    by_name,
    fact_by_name,
    fact_parser_for,
    parser_for,
    register,
    register_fact,
)
from .bash_history import ShellHistoryParser
from .cron import CronLogParser
from .group import GroupParser
from .journal import JournalParser
from .l2tcsv import L2tCsvParser
from .lastlog import LastlogParser
from .passwd import PasswdParser
from .sudoers import SudoersParser
from .systemd_unit import SystemdUnitParser
from .wtmp import UtmpParser

__all__ = [
    "AuthLogParser",
    "AuthorizedKeysParser",
    "CronLogParser",
    "FactParser",
    "GroupParser",
    "JournalParser",
    "L2tCsvParser",
    "LastlogParser",
    "ParseContext",
    "Parser",
    "PasswdParser",
    "ShellHistoryParser",
    "SudoersParser",
    "SystemdUnitParser",
    "UtmpParser",
    "all_fact_parsers",
    "all_parsers",
    "by_name",
    "classify_message",
    "fact_by_name",
    "fact_parser_for",
    "parser_for",
    "register",
    "register_fact",
]
