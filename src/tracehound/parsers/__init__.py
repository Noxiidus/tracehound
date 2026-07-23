"""Artifact parsers.

Importing this package registers every built-in parser. Order matters: the binary
sniffers run before the text ones so a ``wtmp`` file is never mistaken for a log.
"""

from __future__ import annotations

from .authlog import AuthLogParser
from .base import ParseContext, Parser, all_parsers, by_name, parser_for, register
from .wtmp import UtmpParser

__all__ = [
    "AuthLogParser",
    "ParseContext",
    "Parser",
    "UtmpParser",
    "all_parsers",
    "by_name",
    "parser_for",
    "register",
]
