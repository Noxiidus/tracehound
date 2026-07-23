"""Artifact parsers.

Importing this package registers every built-in parser. Selection order is governed by
each parser's ``priority``, not by import order — see :class:`~.base.Parser`.
"""

from __future__ import annotations

from .authlog import AuthLogParser, classify_message
from .base import ParseContext, Parser, all_parsers, by_name, parser_for, register
from .bash_history import ShellHistoryParser
from .cron import CronLogParser
from .journal import JournalParser
from .lastlog import LastlogParser
from .wtmp import UtmpParser

__all__ = [
    "AuthLogParser",
    "CronLogParser",
    "JournalParser",
    "LastlogParser",
    "ParseContext",
    "Parser",
    "ShellHistoryParser",
    "UtmpParser",
    "all_parsers",
    "by_name",
    "classify_message",
    "parser_for",
    "register",
]
