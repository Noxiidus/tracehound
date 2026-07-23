"""Parser interface and registry."""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import ClassVar

from ..models import Event


@dataclass(slots=True)
class ParseContext:
    """Settings a parser may need that cannot be recovered from the artifact itself.

    ``default_year`` exists because syslog-style timestamps omit the year. Without a
    hint the only options are to guess "this year" or to refuse — and a silent wrong
    guess is the more dangerous of the two, so callers are encouraged to pass it.
    """

    default_year: int | None = None
    hostname: str | None = None


class Parser(ABC):
    """Base class for artifact parsers.

    A parser converts one artifact into normalised :class:`Event` objects. It must not
    interpret behaviour — deciding that five failures are a brute-force attack is a
    detection's job, not a parser's.
    """

    name: ClassVar[str]
    description: ClassVar[str]

    #: Lower runs first during sniffing. Specific formats must outrank general ones —
    #: a cron log is also valid syslog, so it has to be offered the file before the
    #: catch-all auth.log parser claims it. Ordering must not depend on import order,
    #: which formatters are free to rearrange.
    priority: ClassVar[int] = 50

    @abstractmethod
    def sniff(self, path: Path) -> bool:
        """Return True if this parser recognises the file at ``path``."""

    @abstractmethod
    def parse(self, path: Path, ctx: ParseContext) -> Iterator[Event]:
        """Yield events from ``path``. Malformed records are skipped, not fatal."""


_REGISTRY: list[Parser] = []


def register(cls: type[Parser]) -> type[Parser]:
    """Class decorator: instantiate the parser once and add it to the registry."""
    _REGISTRY.append(cls())
    return cls


def all_parsers() -> list[Parser]:
    return sorted(_REGISTRY, key=lambda p: (p.priority, p.name))


def parser_for(path: Path) -> Parser | None:
    """Return the highest-priority registered parser that recognises ``path``."""
    for parser in all_parsers():
        try:
            if parser.sniff(path):
                return parser
        except OSError:
            continue
    return None


def by_name(name: str) -> Parser | None:
    for parser in _REGISTRY:
        if parser.name == name:
            return parser
    return None
