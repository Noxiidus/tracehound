"""Sigma rule support — running the community's rules, not only tracehound's own.

The declarative format in :mod:`tracehound.rules` works, but it is tracehound's. The
industry standardised on `Sigma <https://sigmahq.io/>`_, and there is a large body of
public Linux detection rules that a triage tool ought to be able to run.

This module loads a *practical subset* of the Sigma specification and maps it onto the
existing :class:`~tracehound.detections.base.Detection` interface — the same interface the
built-in and declarative rules use, so a Sigma rule is a first-class detection once loaded.

**Supported:** ``logsource`` (used to narrow which events a rule sees, when the category or
service is one tracehound understands), ``detection`` with named selections, field
modifiers (``contains``, ``startswith``, ``endswith``, ``re``, ``cidr``, ``all``), ``*``/``?``
wildcards in plain values, keyword lists, lists of maps, and a ``condition`` mini-language
(``and`` / ``or`` / ``not``, parentheses, ``1 of them``, ``all of them``, ``N of pattern*``).
``level`` maps to severity and ``attack.*`` ``tags`` map to ATT&CK techniques.

**Not supported, and rejected with a clear error rather than silently mishandled:**
aggregation and correlation (``| count() > N``, ``timeframe``) — tracehound's own format has
threshold clustering for that — and modifiers outside the set above. The point of erroring
is that a rule which cannot be represented faithfully must not appear to run and quietly
match nothing.

Field names are resolved against tracehound's event model: ``CommandLine``/``Image``/``User``
and the common aliases map onto the event's fields, and an unrecognised field falls back to
event metadata. This is necessarily a mapping, not an identity — Sigma's field vocabulary is
open — so a rule written for a different pipeline may need its field names adjusted.
"""

from __future__ import annotations

import fnmatch
import ipaddress
import re
from abc import ABC, abstractmethod
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any, ClassVar

from .config import Config
from .detections.base import Detection
from .models import Event, EventType, Finding, Severity
from .timeline import Timeline


class SigmaError(ValueError):
    """Raised when a Sigma rule is malformed or uses an unsupported construct."""


# --- field resolution ---------------------------------------------------------------

# Sigma field names, lower-cased, mapped to how tracehound's event model represents them.
# ``@command`` / ``@message`` / ``@event_type`` are computed rather than plain attributes.
_FIELD_ALIASES: dict[str, str] = {
    "user": "user",
    "username": "user",
    "targetusername": "user",
    "targetuser": "user",
    "sourceip": "source_ip",
    "srcip": "source_ip",
    "src_ip": "source_ip",
    "source_ip": "source_ip",
    "sourceaddress": "source_ip",
    "ip": "source_ip",
    "image": "process",
    "processname": "process",
    "process": "process",
    "comm": "process",
    "exe": "process",
    "parentimage": "process",
    "commandline": "@command",
    "command": "@command",
    "cmd": "@command",
    "pid": "pid",
    "processid": "pid",
    "tty": "terminal",
    "terminal": "terminal",
    "message": "@message",
    "msg": "@message",
    "eventtype": "@event_type",
    "event_type": "@event_type",
}


def _resolve(event: Event, field: str) -> str | None:
    """Return the event's value for a Sigma field name, or None if it has none."""
    key = field.lower()
    target = _FIELD_ALIASES.get(key)
    if target == "@command":
        command = event.metadata.get("command")
        return str(command) if command not in (None, "") else event.message
    if target == "@message":
        return event.message
    if target == "@event_type":
        return event.event_type.value
    if target == "pid":
        return str(event.pid) if event.pid is not None else None
    if target in {"user", "source_ip", "process", "terminal"}:
        value = getattr(event, target)
        return str(value) if value is not None else None
    # Unmapped field: fall back to metadata, matched case-insensitively.
    for meta_key, meta_value in event.metadata.items():
        if meta_key.lower() == key:
            return None if meta_value is None else str(meta_value)
    return None


def _haystack(event: Event) -> str:
    """Everything a keyword search looks through, lower-cased once."""
    parts = [event.message, event.raw or ""]
    parts.extend(str(v) for v in event.metadata.values() if v is not None)
    return " ".join(parts).lower()


# --- value matching -----------------------------------------------------------------

_SUPPORTED_OPS = {"contains", "startswith", "endswith", "re", "cidr"}
_SUPPORTED_MODIFIERS = _SUPPORTED_OPS | {"all"}
_WILDCARD_RE = re.compile(r"(?<!\\)[*?]")

ValuePredicate = Callable[[str | None], bool]


def _glob_to_regex(pattern: str) -> re.Pattern[str]:
    out: list[str] = []
    i, n = 0, len(pattern)
    while i < n:
        char = pattern[i]
        if char == "\\" and i + 1 < n:
            out.append(re.escape(pattern[i + 1]))
            i += 2
            continue
        if char == "*":
            out.append(".*")
        elif char == "?":
            out.append(".")
        else:
            out.append(re.escape(char))
        i += 1
    return re.compile("".join(out), re.IGNORECASE | re.DOTALL)


def _compile_value(op: str, value: Any, where: str) -> ValuePredicate:
    if value is None:
        return lambda actual: actual is None

    if op == "equals":
        text = str(value)
        if isinstance(value, str) and _WILDCARD_RE.search(value):
            regex = _glob_to_regex(value)
            return lambda a: a is not None and regex.fullmatch(a) is not None
        lowered = text.lower()
        return lambda a: a is not None and a.lower() == lowered

    if op == "contains":
        needle = str(value).lower()
        return lambda a: a is not None and needle in a.lower()
    if op == "startswith":
        prefix = str(value).lower()
        return lambda a: a is not None and a.lower().startswith(prefix)
    if op == "endswith":
        suffix = str(value).lower()
        return lambda a: a is not None and a.lower().endswith(suffix)
    if op == "re":
        try:
            regex = re.compile(str(value))
        except re.error as exc:
            raise SigmaError(f"invalid regex in '{where}': {exc}") from exc
        return lambda a: a is not None and regex.search(a) is not None
    if op == "cidr":
        try:
            network = ipaddress.ip_network(str(value), strict=False)
        except ValueError as exc:
            raise SigmaError(f"invalid CIDR in '{where}': {exc}") from exc

        def in_cidr(a: str | None) -> bool:
            if a is None:
                return False
            try:
                return ipaddress.ip_address(a) in network
            except ValueError:
                return False

        return in_cidr

    raise SigmaError(f"unsupported operator '{op}' on '{where}'")  # pragma: no cover


@dataclass(slots=True)
class _FieldMatcher:
    field: str
    combine_all: bool
    predicates: list[ValuePredicate]

    def matches(self, event: Event) -> bool:
        actual = _resolve(event, self.field)
        if self.combine_all:
            return all(pred(actual) for pred in self.predicates)
        return any(pred(actual) for pred in self.predicates)


def _build_field_matcher(key: str, raw_value: Any) -> _FieldMatcher:
    parts = key.split("|")
    field = parts[0]
    modifiers = [m.lower() for m in parts[1:]]

    unknown = [m for m in modifiers if m not in _SUPPORTED_MODIFIERS]
    if unknown:
        raise SigmaError(f"unsupported field modifier(s) {unknown} on '{key}'")

    combine_all = "all" in modifiers
    ops = [m for m in modifiers if m in _SUPPORTED_OPS]
    if len(ops) > 1:
        raise SigmaError(f"only one value operator is allowed, got {ops} on '{key}'")
    op = ops[0] if ops else "equals"

    values = raw_value if isinstance(raw_value, list) else [raw_value]
    predicates = [_compile_value(op, value, key) for value in values]
    return _FieldMatcher(field=field, combine_all=combine_all, predicates=predicates)


# --- selections ---------------------------------------------------------------------


class _Selection(ABC):
    @abstractmethod
    def matches(self, event: Event) -> bool: ...


@dataclass(slots=True)
class _MapSelection(_Selection):
    """A map of field:value pairs — every field must match the same event."""

    matchers: list[_FieldMatcher]

    def matches(self, event: Event) -> bool:
        return all(matcher.matches(event) for matcher in self.matchers)


@dataclass(slots=True)
class _KeywordSelection(_Selection):
    """A bare list of strings — any appearing anywhere in the event matches."""

    keywords: list[str]

    def matches(self, event: Event) -> bool:
        hay = _haystack(event)
        return any(keyword.lower() in hay for keyword in self.keywords)


@dataclass(slots=True)
class _OrSelection(_Selection):
    """A list of maps — matches if any of them matches."""

    options: list[_Selection]

    def matches(self, event: Event) -> bool:
        return any(option.matches(event) for option in self.options)


def _compile_selection(value: Any, where: str) -> _Selection:
    if isinstance(value, dict):
        return _MapSelection([_build_field_matcher(k, v) for k, v in value.items()])
    if isinstance(value, list):
        if value and all(isinstance(item, dict) for item in value):
            return _OrSelection([_compile_selection(item, where) for item in value])
        if all(not isinstance(item, (dict, list)) for item in value):
            return _KeywordSelection([str(item) for item in value])
        raise SigmaError(f"selection '{where}' must be all maps or all plain values")
    raise SigmaError(f"selection '{where}' must be a map or list, got {type(value).__name__}")


# --- condition mini-language --------------------------------------------------------


class _Node(ABC):
    @abstractmethod
    def eval(self, results: dict[str, bool]) -> bool: ...


@dataclass(slots=True)
class _Ident(_Node):
    name: str

    def eval(self, results: dict[str, bool]) -> bool:
        return results.get(self.name, False)


@dataclass(slots=True)
class _Not(_Node):
    child: _Node

    def eval(self, results: dict[str, bool]) -> bool:
        return not self.child.eval(results)


@dataclass(slots=True)
class _And(_Node):
    left: _Node
    right: _Node

    def eval(self, results: dict[str, bool]) -> bool:
        return self.left.eval(results) and self.right.eval(results)


@dataclass(slots=True)
class _Or(_Node):
    left: _Node
    right: _Node

    def eval(self, results: dict[str, bool]) -> bool:
        return self.left.eval(results) or self.right.eval(results)


@dataclass(slots=True)
class _Quantifier(_Node):
    names: list[str]
    need: int

    def eval(self, results: dict[str, bool]) -> bool:
        return sum(1 for name in self.names if results.get(name, False)) >= self.need


class _ConditionParser:
    """Recursive-descent parser for the supported condition grammar."""

    def __init__(self, tokens: list[str], names: set[str]) -> None:
        self._tokens = tokens
        self._pos = 0
        self._names = names

    def _peek(self) -> str | None:
        return self._tokens[self._pos] if self._pos < len(self._tokens) else None

    def _advance(self) -> str | None:
        token = self._peek()
        self._pos += 1
        return token

    def parse(self) -> _Node:
        node = self._parse_or()
        if self._pos != len(self._tokens):
            raise SigmaError(f"unexpected token {self._peek()!r} in condition")
        return node

    def _parse_or(self) -> _Node:
        node = self._parse_and()
        while (self._peek() or "").lower() == "or":
            self._advance()
            node = _Or(node, self._parse_and())
        return node

    def _parse_and(self) -> _Node:
        node = self._parse_not()
        while (self._peek() or "").lower() == "and":
            self._advance()
            node = _And(node, self._parse_not())
        return node

    def _parse_not(self) -> _Node:
        if (self._peek() or "").lower() == "not":
            self._advance()
            return _Not(self._parse_not())
        return self._parse_primary()

    def _parse_primary(self) -> _Node:
        token = self._peek()
        if token is None:
            raise SigmaError("unexpected end of condition")
        if token == "(":
            self._advance()
            node = self._parse_or()
            if self._peek() != ")":
                raise SigmaError("missing ')' in condition")
            self._advance()
            return node
        low = token.lower()
        if low in {"all", "any"} or low.isdigit():
            return self._parse_quantifier()
        self._advance()
        if token not in self._names:
            raise SigmaError(f"condition references unknown selection '{token}'")
        return _Ident(token)

    def _parse_quantifier(self) -> _Node:
        count_token = (self._advance() or "").lower()
        if (self._peek() or "").lower() != "of":
            raise SigmaError(f"expected 'of' after '{count_token}' in condition")
        self._advance()
        target = self._advance()
        if target is None:
            raise SigmaError("expected 'them' or a pattern after 'of'")

        if target.lower() == "them":
            matched = sorted(self._names)
        else:
            matched = sorted(n for n in self._names if fnmatch.fnmatchcase(n, target))
        if not matched:
            raise SigmaError(f"'{count_token} of {target}' matches no selection")

        if count_token == "all":
            need = len(matched)
        elif count_token in {"any", "1"}:
            need = 1
        else:
            need = int(count_token)
        return _Quantifier(matched, min(need, len(matched)))


def _parse_condition(condition: Any, names: set[str]) -> _Node:
    if isinstance(condition, list):
        # A list of conditions is an OR across them.
        nodes = [_parse_condition(item, names) for item in condition]
        if not nodes:
            raise SigmaError("empty condition list")
        node = nodes[0]
        for extra in nodes[1:]:
            node = _Or(node, extra)
        return node
    if not isinstance(condition, str):
        raise SigmaError("'condition' must be a string or list of strings")
    if "|" in condition:
        raise SigmaError("aggregation/correlation conditions ('|', count, etc.) are not supported")
    tokens = condition.replace("(", " ( ").replace(")", " ) ").split()
    if not tokens:
        raise SigmaError("empty condition")
    return _ConditionParser(tokens, names).parse()


# --- logsource narrowing ------------------------------------------------------------

_CATEGORY_TYPES: dict[str, set[EventType]] = {
    "process_creation": {
        EventType.COMMAND_EXECUTED,
        EventType.CRON_JOB,
        EventType.PRIVILEGE_ESCALATION,
    },
}
_SERVICE_TYPES: dict[str, set[EventType]] = {
    "sudo": {EventType.PRIVILEGE_ESCALATION},
    "auth": {
        EventType.LOGIN_SUCCESS,
        EventType.LOGIN_FAILURE,
        EventType.INVALID_USER,
        EventType.SESSION_OPEN,
        EventType.SESSION_CLOSE,
        EventType.LOGOUT,
    },
    "sshd": {
        EventType.LOGIN_SUCCESS,
        EventType.LOGIN_FAILURE,
        EventType.INVALID_USER,
        EventType.SESSION_OPEN,
        EventType.SESSION_CLOSE,
    },
    "cron": {EventType.CRON_JOB},
}


def _logsource_types(logsource: Any) -> set[EventType] | None:
    """Event types a rule should see, or None to see all.

    Narrowing is deliberately conservative: only categories/services tracehound can map
    are restricted, and everything else runs against the whole timeline. A wrong guess
    here would silently drop matches, which is worse than running a rule too broadly.
    """
    if not isinstance(logsource, dict):
        return None
    category = str(logsource.get("category", "")).lower()
    if category in _CATEGORY_TYPES:
        return _CATEGORY_TYPES[category]
    service = str(logsource.get("service", "")).lower()
    if service in _SERVICE_TYPES:
        return _SERVICE_TYPES[service]
    return None


# --- rule + detection ---------------------------------------------------------------

_LEVELS: dict[str, Severity] = {
    "informational": Severity.INFO,
    "info": Severity.INFO,
    "low": Severity.LOW,
    "medium": Severity.MEDIUM,
    "high": Severity.HIGH,
    "critical": Severity.CRITICAL,
}


def _severity(level: Any) -> Severity:
    if level is None:
        return Severity.MEDIUM
    key = str(level).lower()
    if key not in _LEVELS:
        raise SigmaError(f"unknown level '{level}' (use: {', '.join(_LEVELS)})")
    return _LEVELS[key]


def _techniques(tags: Any) -> list[str]:
    out: list[str] = []
    for tag in tags or []:
        text = str(tag)
        if text.lower().startswith("attack.t"):
            out.append(text.split(".", 1)[1].upper())
    return out


@dataclass(slots=True)
class SigmaRule:
    rule_id: str
    title: str
    severity: Severity
    description: str
    attack_techniques: list[str]
    selections: dict[str, _Selection]
    condition: _Node
    logsource: dict[str, str]
    event_types: set[EventType] | None

    def matches(self, event: Event) -> bool:
        if self.event_types is not None and event.event_type not in self.event_types:
            return False
        results = {name: sel.matches(event) for name, sel in self.selections.items()}
        return self.condition.eval(results)


def build_rule(data: dict[str, Any]) -> SigmaRule:
    """Compile one Sigma YAML document into a :class:`SigmaRule`."""
    if not isinstance(data, dict):
        raise SigmaError("a Sigma rule must be a mapping")

    title = str(data.get("title", "")).strip()
    if not title:
        raise SigmaError("a Sigma rule needs a 'title'")

    detection = data.get("detection")
    if not isinstance(detection, dict):
        raise SigmaError(f"{title}: 'detection' must be a mapping")
    if "timeframe" in detection:
        raise SigmaError(f"{title}: time-windowed aggregation ('timeframe') is not supported")
    if "condition" not in detection:
        raise SigmaError(f"{title}: 'detection' needs a 'condition'")

    selections: dict[str, _Selection] = {}
    for name, value in detection.items():
        if name == "condition":
            continue
        selections[name] = _compile_selection(value, name)
    if not selections:
        raise SigmaError(f"{title}: 'detection' has no selections")

    condition = _parse_condition(detection["condition"], set(selections))

    logsource_raw = data.get("logsource") or {}
    logsource = {k: str(v) for k, v in logsource_raw.items() if isinstance(logsource_raw, dict)}

    rule_id = str(data.get("id") or title).strip()
    return SigmaRule(
        rule_id=rule_id,
        title=title,
        severity=_severity(data.get("level")),
        description=str(data.get("description", title)).strip() or title,
        attack_techniques=_techniques(data.get("tags")),
        selections=selections,
        condition=condition,
        logsource=logsource,
        event_types=_logsource_types(logsource_raw),
    )


class SigmaDetection(Detection):
    """A :class:`~tracehound.detections.base.Detection` driven by a :class:`SigmaRule`."""

    rule_id: ClassVar[str] = ""
    title: ClassVar[str] = ""
    severity: ClassVar[Severity] = Severity.MEDIUM
    description: ClassVar[str] = ""
    attack_techniques: ClassVar[list[str]] = []

    def __init__(self, rule: SigmaRule) -> None:
        self.rule = rule
        self.rule_id = rule.rule_id  # type: ignore[misc]
        self.title = rule.title  # type: ignore[misc]
        self.severity = rule.severity  # type: ignore[misc]
        self.description = rule.description  # type: ignore[misc]
        self.attack_techniques = list(rule.attack_techniques)  # type: ignore[misc]

    def run(self, timeline: Timeline, config: Config) -> Iterator[Finding]:
        rule = self.rule
        for event in timeline:
            if config.ip_allowed(event.source_ip) or config.account_allowed(event.user):
                continue
            if not rule.matches(event):
                continue
            yield Finding(
                rule_id=rule.rule_id,
                title=rule.title,
                severity=rule.severity,
                description=rule.description,
                events=[event],
                attack_techniques=list(rule.attack_techniques),
                metadata={
                    "sigma": True,
                    "sigma_id": rule.rule_id,
                    "logsource": rule.logsource,
                },
            )


def _documents(path: Path) -> list[Any]:
    try:
        import yaml
    except ImportError as exc:  # pragma: no cover - depends on optional extra
        raise SigmaError(
            "Sigma rules are YAML; install tracehound[yaml] (or pyyaml) to load them"
        ) from exc

    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise SigmaError(f"cannot read {path}: {exc}") from exc
    try:
        return [doc for doc in yaml.safe_load_all(text) if doc is not None]
    except yaml.YAMLError as exc:
        raise SigmaError(f"invalid YAML in {path}: {exc}") from exc


def load_sigma_rules(path: Path) -> list[Detection]:
    """Load Sigma rules from a file (one or more YAML documents) or a directory of them.

    Every ``.yml``/``.yaml`` file in a directory is loaded, sorted by name so a run is
    reproducible. Each rule becomes a :class:`SigmaDetection`; a duplicate rule id within
    one load is an error, because two rules answering to the same id cannot both be
    suppressed or reported unambiguously.
    """
    if path.is_dir():
        files = sorted(p for p in path.iterdir() if p.suffix.lower() in {".yml", ".yaml"})
    else:
        files = [path]

    detections: list[Detection] = []
    seen: set[str] = set()
    for file in files:
        for document in _documents(file):
            rule = build_rule(document)
            if rule.rule_id in seen:
                raise SigmaError(f"duplicate rule id '{rule.rule_id}' in {file}")
            seen.add(rule.rule_id)
            detections.append(SigmaDetection(rule))
    return detections
