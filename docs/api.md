# Public API and stability

From **1.0**, tracehound follows [Semantic Versioning](https://semver.org/). The surface
listed here is the public contract: it will not change incompatibly except on a major
version bump. Anything not listed — modules, names and behaviour with a leading underscore,
and internals reached around this surface — may change in any release.

A 1.0 that cannot be depended on is just a version number; this document is what "depend on
it" means.

## Python API

Importable from the package root (`from tracehound import …`):

| Name | Kind | Contract |
|---|---|---|
| `scan(paths, *, year, config, extra_detections, on_disk, incremental)` | function | Returns a `ScanResult`. Keyword-only options may gain new keywords (all optional); existing ones keep their meaning. |
| `build_case(sources, *, year, config, offsets)` | function | Multi-host correlation; returns a `Case`. |
| `Event` | dataclass | Fields (`timestamp`, `source`, `event_type`, `message`, `user`, `source_ip`, `process`, `pid`, `terminal`, `raw`, `metadata`) are stable. `timestamp` is always timezone-aware UTC. New optional fields may be **added**. |
| `Fact` | dataclass | `subject`, `attribute`, `value`, `source`, `metadata`; `kind`/`name` derived. |
| `Finding` | dataclass | `rule_id`, `title`, `severity`, `description`, `events`, `facts`, `attack_techniques`, `metadata`; `first_seen`/`last_seen`; `to_dict()`. |
| `EventType`, `Severity` | enums | Members may be **added**; existing member names and values are stable. |
| `Timeline` | class | In-memory `TimelineLike`. |
| `TimelineLike` | protocol | The timeline query surface detections run against: `__iter__`, `__len__`, `add`, `sort`, `start`, `end`, `of_type`, `by_ip`, `by_user`, `between`, `window`, `sources`. A backend implementing it is a drop-in. |
| `FactBase` | class | The state-fact store. |
| `Config` | dataclass | Tuning knobs; `Config.load(path)` / `from_mapping(dict)`. New optional knobs may be added. |
| `ScanResult`, `Case`, `Host` | dataclasses | `ScanResult.timeline`/`factbase`/`findings`/`artifacts`/`provenance()`. |
| `load_sigma_rules(path)` | function | Sigma rules → detections. |
| `render_l2tcsv`, `render_timesketch_jsonl`, `render_sigma` | functions | Interoperability exports. |

Also stable (imported from their modules): the `Parser` / `FactParser` and `Detection` /
`FactDetection` base classes and their `register` decorators and registries
(`tracehound.parsers`, `tracehound.detections`), the declarative rule loader
(`tracehound.rules.load_rules`), the report renderers (`tracehound.report`), the collection
`Manifest` (`tracehound.manifest`), and the `SqliteTimeline` backend
(`tracehound.sqlite_timeline`).

Errors raised on bad external input are part of the contract and are always one of
`RuleError`, `SigmaError`, `ConfigError` or `ManifestError` (all subclasses of `ValueError`)
— never a bare, unclassified exception.

## Command line

`tracehound scan|case|verify|parsers|rules`, their flags, and the exit codes (`0` clean,
`1` findings-with-`--fail-on-findings`, `2` usage/input error, `3` manifest verification
failure) are stable. New optional flags and new output formats may be added.

## Output formats

The JSON report (`-f json`), the collection `manifest.json`, the l2tcsv columns, the
Timesketch JSONL fields, and the Sigma rule shape are documented in
[schemas.md](schemas.md). Fields may be **added**; existing fields keep their names and
meaning within a major version.

## Rule-id policy

Detection rule ids (`THN-NNNN`, and `THN-1NNN` for cross-host) are permanent identifiers.

- An id, once shipped, is **never reused** for a different rule.
- A retired rule's id is marked deprecated and left documented, so a finding in an archived
  report can always be looked up.
- A rule's *severity*, *title*, *description* and *matching logic* may be refined between
  versions — tuning is expected — but its id and its intent do not silently change.

This is what lets an old report, or a downstream system keyed on rule ids, stay meaningful.
