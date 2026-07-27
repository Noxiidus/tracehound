# Roadmap

Where tracehound is going, and why. Versions are ordered by dependency, not by ambition —
each one unblocks the next.

Nothing here is a commitment to a date. Items may move if something more useful appears,
and the [declined](#considered-and-declined) section is as much a part of the plan as the
rest.

---

## 0.6.0 — State artifacts and the `Fact` model — **shipped**

Delivered in [0.6.0](CHANGELOG.md). A `Fact` model (an entity-attribute-value triple with
no timestamp) sits alongside `Event`, with its own `FactBase`, `FactParser` and
`FactDetection` interfaces. Five state parsers (`/etc/passwd`, `/etc/group`,
`/etc/sudoers`, `authorized_keys`, systemd units) feed five detections: duplicate UID 0
(THN-0040), unexpected sudoers grant (THN-0041), suspicious authorised key (THN-0042),
unit from a world-writable path (THN-0043), and service account with a login shell
(THN-0044).

The model change landed here, at six parsers, precisely because it would only get more
expensive later — everything below builds on top of it.

---

## 0.7.0 — Interoperability — **shipped**

Delivered in [0.7.0](CHANGELOG.md). A scan now flows both ways:

- **`l2tcsv` export** (`--format l2tcsv`) — the plaso/log2timeline super-timeline, so
  tracehound output drops into Timesketch alongside filesystem and browser timelines, with
  finding rule ids in the `notes` column.
- **Timesketch JSONL export** (`--format timesketch`) — findings' rule ids, severity and
  ATT&CK techniques ride along on the events they implicate as tags and fields, so the
  reasoning survives the export, not just the events.
- **`l2tcsv` as an input source** — a parser that reads a super-timeline back in and runs
  detections against it, fusing filesystem MACB timestamps with auth events. The `extra`
  column is enriched with scalar metadata so a round-trip re-fires the original detections.
- **Sigma export** (`--format sigma`) — every finding, event- or fact-based, rendered as a
  Sigma rule with a stable id, ready to forward to a SIEM.

The Sigma *output* here is distinct from the Sigma *input* below: this exports tracehound's
conclusions as rules; 0.8.0 consumes the community's rules as detections.

---

## 0.8.0 — Sigma rule support — **shipped**

Delivered in [0.8.0](CHANGELOG.md). `tracehound scan --sigma RULE_OR_DIR` loads a practical
subset of the [Sigma](https://sigmahq.io/) specification onto the existing `Detection`
interface: `logsource` (used to narrow which events a rule sees when the category or
service is one tracehound maps), named `detection` selections with field modifiers
(`contains`, `startswith`, `endswith`, `re`, `cidr`, `all`), `*`/`?` wildcards, keyword
lists and lists of maps, and a `condition` mini-language (`and`/`or`/`not`, parentheses,
`1 of them`, `all of them`, `N of pattern*`). `level` maps to severity, `attack.*` tags to
ATT&CK techniques.

Deliberately *not* the whole spec: aggregation and correlation (`| count()`, `timeframe`)
and unsupported modifiers raise a clear error rather than silently matching nothing —
tracehound's own format already has threshold clustering for the counting case. The native
YAML rule format stays; Sigma is verbose for "flag this command pattern".

This is the difference between a tool one person wrote rules for and a tool that runs the
rules a community already maintains.

---

## 0.9.0 — Scale

**The problem.** Everything is currently held in memory. That is fine for a triage
snapshot and wrong for a year of `auth.log` from a busy host, which runs to millions of
lines.

**The work.**

- **Streaming parse** — parsers already yield, but `Timeline` materialises everything.
- **Optional on-disk timeline** (SQLite) for datasets that do not fit in RAM, with the
  same query surface so detections do not care which backend they are on.
- **Incremental scanning** — remember where a previous scan stopped and process only what
  is new, for repeated runs against a live host.
- **Benchmarks in CI**, so a regression in throughput is caught rather than discovered.

**Why last before 1.0.** Optimising before the model is settled means optimising the wrong
thing twice.

---

## 1.0.0 — Commitments

Not a feature release. A promise release.

- **Public API freeze** for `scan()`, `build_case()`, `Event`, `Finding`, `Timeline`,
  `Config` and the parser/detection interfaces. Breaking changes only on a major version.
- **Rule ID policy** — IDs are permanent. A retired rule is marked deprecated, never
  reused, so a finding in an old report can always be looked up.
- **Documented compatibility** for manifest and report JSON schemas, so downstream tooling
  can rely on them.
- **PyPI publication**, making `pip install tracehound` work without a git URL.
- **Security policy** and a documented process for reporting issues in the tool itself.

A 1.0 that cannot be depended on is just a version number.

---

## After 1.0 — Windows

EVTX event logs, registry hives, prefetch, amcache, MFT. This roughly doubles the
project's scope and would build on existing parsing libraries rather than reimplementing
binary XML and hive formats.

Explicitly post-1.0 because it changes what the project *is*, and that should not happen
while the Linux side is still moving underneath it. A tool that does Linux well is more
useful than one that does two platforms adequately.

---

## Considered and declined

Listing these matters as much as the plan — several are the obvious next step and are
being deliberately skipped.

**Memory forensics.** Volatility exists, is enormous, and represents a decade of
accumulated knowledge. Reimplementing it would produce a worse copy, not an addition.

**Machine-learning anomaly detection.** A poor fit for forensics. A rule can state *why*
it fired; a model cannot. In an incident report or in front of a lawyer, an unexplainable
finding is worthless — and the same property makes it untunable when it is wrong.

**A live agent or daemon.** Continuous monitoring is EDR, a different product with
different constraints (performance budgets, tamper resistance, fleet management).
tracehound is a triage tool that runs after something happened.

**A web UI.** Timesketch already does timeline browsing well. Building a worse version is
less useful than exporting to it — hence 0.7.0.

**Automated remediation.** Deciding what happened and deciding what to do about it are
separate responsibilities, and a triage tool with confidence intervals should not be
deleting accounts.

---

## Contributing

The items above are not reserved. If you want to take one, open an issue first so the
design can be agreed before code is written — particularly for 0.6.0, where the model
change affects everything else.

Smaller contributions that are always welcome: additional artifact parsers, detection
rules with a clear rationale, and test cases from real-world formats that the current
parsers mishandle.

See [Architecture](https://github.com/Noxiidus/tracehound/wiki/Architecture) for how the
pieces fit together.
