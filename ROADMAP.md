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

## 0.9.0 — Scale — **shipped (streaming + on-disk timeline)**

**The problem.** Everything was held in memory. Fine for a triage snapshot, wrong for a
year of `auth.log` from a busy host, which runs to millions of lines.

Delivered in [0.9.0](CHANGELOG.md): the query surface detections rely on is now the
`TimelineLike` protocol, and an on-disk **`SqliteTimeline`** (stdlib `sqlite3`, so still
dependency-free) implements it. `scan(on_disk=PATH)` / `tracehound scan --sqlite [PATH]`
keeps the timeline in SQLite for datasets too large for RAM; because events store an
ISO-8601 UTC timestamp that sorts lexically in chronological order, both backends produce
byte-identical findings. Inserts stream in batches; `add()` accepts a lazy iterator.

**Incremental scanning — shipped in [0.9.2](CHANGELOG.md).** `scan --sqlite PATH
--incremental` reuses the database across runs: an event-log file unchanged since the last
scan (size, mtime, digest) is not re-parsed, a changed one is dropped and re-parsed, and the
result matches a full scan. A grown file is re-parsed in full for now; byte-offset resumption
is a later refinement.

**Benchmarks in CI — shipped in [0.9.3](CHANGELOG.md).** `benchmarks/bench.py` reports
events/second for both backends, and a CI guard scans 20k events inside a generous ceiling so
an accidental O(n²) is caught rather than discovered on a real host.

Every *Scale* item is now delivered.

**Why Scale is last before 1.0.** Optimising before the model is settled means optimising
the wrong thing twice — which is why the backend was made pluggable only after the event,
fact, interop and Sigma models had settled.

---

## 1.0.0 — Commitments — **shipped**

Not a feature release. A promise release. Delivered in [1.0.0](CHANGELOG.md):

- **Public API freeze** — [docs/api.md](docs/api.md) declares the stable surface under
  SemVer; breaking changes only on a major version. Errors on bad input are contractually a
  typed `RuleError` / `SigmaError` / `ConfigError` / `ManifestError`.
- **Rule ID policy** — `THN-NNNN` ids are permanent and never reused; enforced by a test.
- **Documented schemas** — [docs/schemas.md](docs/schemas.md) covers the report JSON, the
  manifest, and the l2tcsv / Timesketch / Sigma exports.
- **Security policy** — [SECURITY.md](SECURITY.md): private reporting, scope, design stance.
- **PyPI packaging** — clean sdist/wheel (`twine check` passes) and a Trusted-Publishing
  (OIDC) `publish.yml`. The build runs on every tag (always green); the publish step is off
  until enabled, so a tag never fails before PyPI is ready. **To go live, once:** add a PyPI
  trusted publisher for `tracehound` (repo `Noxiidus/tracehound`, workflow `publish.yml`,
  environment `pypi`) and set the Actions variable `PYPI_ENABLED=true`; then `pip install
  tracehound` works and every tag publishes.

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
