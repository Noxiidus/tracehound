# Changelog

All notable changes to this project are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this
project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [0.9.0] — 2026-08-01

Scale. Everything lived in memory, which is fine for a triage snapshot and wrong for a year
of `auth.log` from a busy host — millions of lines that do not fit in RAM. This release
introduces an on-disk timeline behind an interface detections cannot tell apart from the
in-memory one.

### Added

- **`TimelineLike` protocol** — the query surface detections rely on (iteration,
  `of_type`/`by_ip`/`by_user`/`between`/`window`/`sources`, `start`/`end`, `add`, `sort`),
  extracted so a second backend is a drop-in. Exported from the package. `Timeline` is now
  documented as its in-memory implementation.
- **`SqliteTimeline`** — an on-disk (or in-process) SQLite backend implementing the same
  protocol, for datasets too large for memory. Timestamps are stored as ISO-8601 strings,
  which — because every event is UTC — sort lexically in chronological order, so it yields
  events in exactly the same `(timestamp, source, message)` order as the in-memory backend.
  Only the standard-library `sqlite3` is used, so the package stays dependency-free.
- **`scan(..., on_disk=PATH)`** and **`tracehound scan --sqlite [PATH]`** — keep the timeline
  in SQLite instead of memory. Findings are identical either way; only where the events live
  changes. Pass the flag alone for an in-process database, or a path to persist it.
- **Streaming inserts** — `Timeline.add()` now accepts a lazy iterator and returns how many
  events it appended, and `SqliteTimeline` inserts in batches, so a parser's events do not
  all sit in memory at once.

### Notes

Detections, reports and exports now type against `TimelineLike` rather than the concrete
`Timeline`, so either backend flows through the whole pipeline unchanged — a parametrised
contract suite, a field-level round-trip test, a cross-backend equivalence test, and a full
end-to-end scan all confirm the two produce identical output.

The remaining *Scale* roadmap items — incremental scanning and CI throughput benchmarks —
are deferred to a follow-up 0.9.x; the on-disk timeline is the load-bearing piece and ships
now.

## [0.8.6] — 2026-08-01

### Security

- **CSV formula injection in the timeline export.** A log field an attacker controls (a
  username, a message) can begin with `=`, `+`, `-`, `@` or a tab/CR, which Excel and
  LibreOffice execute as a formula the moment an analyst opens the exported CSV. Such cells
  in `--format csv` are now prefixed with a single quote — the value is displayed unchanged
  but never executed. The l2tcsv export is deliberately left verbatim: it feeds
  plaso/Timesketch, which do not execute formulas and whose values a quote would corrupt.

### Fixed

- **Directory symlink cycles could hang a scan forever.** `collect_files` expanded
  directories with `Path.rglob`, which follows symlinked directories, so pointing a scan at
  a tree containing a symlink loop (easy to hit on `/` or a mounted image) generated paths
  endlessly before the de-duplication ran. It now walks with `os.walk(followlinks=False)`,
  which cannot loop; symlinked *files* are still collected, only descending through a
  symlinked *directory* is refused.

Both found in a continued security-oriented repository review.

## [0.8.5] — 2026-07-27

### Fixed

Two more instances of the "malformed input crashes with an uncaught exception instead of a
typed error" bug class, found by extending the fuzzing pass to the manifest and Sigma
metadata surfaces:

- **Manifest loader crashed on a non-numeric artifact `size`.** A manifest with, say,
  `"size": "huge"` raised a bare `ValueError` from `int()` that escaped and took down
  `tracehound verify` / `case --manifest`. It now raises a clear `ManifestError`, and a
  numeric string (`"1024"`) or float is accepted.
- **Sigma loader crashed on a non-list `tags`.** A rule with `tags: 5` (or any non-list
  scalar) raised `TypeError: 'int' object is not iterable` from iterating it. `tags` is
  advisory, so a malformed value now yields no techniques rather than crashing.

All four external-input loaders (declarative rules, Sigma, config, manifest) are now fuzzed
clean — thousands of randomised documents each build or raise their own typed error, never
an uncaught exception.

## [0.8.4] — 2026-07-27

### Fixed

- **Declarative rule loader crashed on a non-integer `threshold.window_seconds`.** The
  `count` field was validated, but `window_seconds` was passed straight to `int()`, so a
  value like `"soon"` raised a bare `ValueError` that escaped the loader (the CLI only
  catches `RuleError`) and crashed the scan. It now raises a clear `RuleError`, same as
  `count`. The `count` and `window_seconds` checks also now reject booleans, which `int()`
  would otherwise have silently accepted as 1/0.

This was the single defect surfaced by a large fuzzing pass — thousands of randomised rules,
configs, Sigma documents, artifacts and multi-host cases — which otherwise confirmed the
parsers never crash and never emit a non-UTC event, every report format renders and stays
valid, scans are deterministic, and every finding serialises. It is the same class of bug as
the 0.8.1 Sigma `logsource` crash: a malformed rule file must fail with a clear error, never
an uncaught exception.

## [0.8.3] — 2026-07-27

### Fixed

- **Collector `-h` help was truncated.** `tracehound-collect.sh -h` printed the usage block
  up to the "Example" heading but cut off the example command itself (an off-by-one in the
  `sed` line range). The example is now shown.
- **Collector version string was stale.** `tracehound-collect.sh` still stamped manifests
  with `version: 0.5.0` although the toolset had moved to 0.8.x, misrepresenting which
  collector produced the evidence. It now tracks the release version. (The collector's
  `VERSION` is a third place the release bump must touch, alongside `pyproject.toml` and
  `__init__.py` — it had been silently missed since 0.5.0.)

A full HTML-report injection sweep in this review — adversarial markup pushed through every
finding, event, fact and artifact field — confirmed the 0.8.2 escaping fix left no siblings.

## [0.8.2] — 2026-07-27

### Security

- **HTML report did not escape the finding rule id.** Every other field in the HTML report
  is escaped, but `rule_id` was interpolated raw. For the built-in rules that is a constant
  like `THN-0001`, but a Sigma rule's id (and title, used as a fallback id) comes from
  user-supplied YAML — so a crafted rule could inject markup into the report, which is often
  shared. The id is now escaped like everything else, and a test injects `<script>` through
  the rule id, title, description and event message to prove it.

### Fixed

- **`authorized_keys` options field was truncated** when an option value contained a key-type
  string as a substring (for example `environment="ssh-rsa=1" ssh-rsa …`). The parser split
  the line on the type string rather than on the token boundary; it now reconstructs the
  options from the tokens preceding the key type. The key, blob and comment were already
  correct — only the options field was affected, which THN-0042 reads.

Found in a continued full-repository bug review.

## [0.8.1] — 2026-07-27

### Fixed

- **Sigma loader crashed on a malformed `logsource`.** A rule whose `logsource` was a scalar
  or list instead of a mapping raised an uncaught `AttributeError` (`'str' object has no
  attribute 'items'`) and took the whole scan down. Since `logsource` is advisory in
  tracehound — it only narrows which events a rule sees — a non-mapping value is now ignored
  (the rule runs against the whole timeline) rather than being fatal.

### Hardened

- A quantifier count of zero (`0 of them`) and an empty selection map (`selection: {}`) now
  raise a clear `SigmaError`. Both previously compiled to a rule that silently matched every
  event — the exact "appears to run but does the wrong thing" failure the loader is meant to
  reject.

Found in a targeted review of the 0.8.0 Sigma code.

## [0.8.0] — 2026-07-25

Sigma rule support. The declarative rule format works, but it is tracehound's own — and the
industry standardised on [Sigma](https://sigmahq.io/), where a large body of public Linux
detection rules already lives. A triage tool that cannot run them leaves that knowledge on
the table. 0.8.0 loads a practical subset of Sigma onto the existing detection interface, so
a community rule is a first-class detection.

### Added

- **`tracehound scan --sigma RULE_OR_DIR`** (repeatable) — load Sigma rules from a file (one
  or more YAML documents) or a directory of them. Each rule becomes a `Detection` that runs
  alongside the built-in and declarative rules.
- **Supported subset:** `logsource` (narrows which events a rule sees when its category or
  service maps to tracehound's model), named `detection` selections, field modifiers
  `contains` / `startswith` / `endswith` / `re` / `cidr` / `all`, `*` and `?` wildcards in
  plain values, keyword lists, lists of maps, and a `condition` mini-language — `and`,
  `or`, `not`, parentheses, `1 of them`, `all of them`, `N of pattern*`. `level` maps to
  severity; `attack.*` `tags` map to ATT&CK techniques.
- **`load_sigma_rules()`** and the `tracehound.sigma` module for library use.
- Sigma field names are resolved against tracehound's event model (`CommandLine`, `Image`,
  `User`, `SourceIp`, …), with an unrecognised field falling back to event metadata.

### Notes

Deliberately *not* the whole spec. Aggregation and correlation (`| count() > N`,
`timeframe`) and any modifier outside the supported set raise a clear `SigmaError` rather
than loading a rule that appears to run but silently matches nothing — tracehound's own
declarative format already provides threshold clustering for the counting case. Because
Sigma's field vocabulary is open, a rule written for a different pipeline may need its field
names adjusted; the mapping is documented and honest about being a mapping. Sigma is YAML, so
this needs the `[yaml]` extra.

## [0.7.2] — 2026-07-25

### Fixed

- **Journal parser: removed a dead, misspelled field lookup.** The parser tried
  ``SYLOG_IDENTIFIER`` (missing an ``S``) before the correct ``SYSLOG_IDENTIFIER``. The
  misspelled key never exists in journald output, so the lookup always returned nothing and
  the correct fallback did the work — process identification was right by accident. The dead
  line is gone and a test now asserts the process field is extracted, so a future edit to
  the fallback cannot silently break it.

Found during a full-repository review before the next feature line; no behavioural change.

## [0.7.1] — 2026-07-25

### Fixed

- **Sigma export produced invalid YAML** for any finding whose description ended in a colon
  or contained one followed by a break — THN-0041 (unexpected sudoers grant) among them.
  The hand-rolled emitter only quoted a colon *followed by a space*, but a plain YAML scalar
  cannot carry a trailing colon at all, so the document failed to parse in a SIEM. The
  scalar serialiser now quotes anything that is not conservatively plain-safe, and folds
  embedded newlines. Regression tests exercise every rule family, not just the brute-force
  chain that happened to have colon-free descriptions.

## [0.7.0] — 2026-07-25

Interoperability. tracehound produced its own timeline in its own formats, and a tool that
cannot feed the platforms a DFIR shop already runs — Timesketch, plaso, a SIEM — stays a
curiosity no matter how good its analysis is. 0.7.0 makes a scan flow both ways: out into
the standard formats, and back in from a super-timeline built by other tools.

### Added

- **`l2tcsv` export** (`--format l2tcsv`) — the log2timeline / plaso super-timeline CSV, so
  tracehound events drop into Timesketch alongside filesystem, browser and registry
  timelines. The `notes` column carries the rule ids of any findings that cite each event.
- **Timesketch JSONL export** (`--format timesketch`) — the timeline as newline-delimited
  JSON, with each finding's rule id, severity and ATT&CK techniques carried onto the events
  it implicates as `tag`s and dedicated fields. The *reasoning* survives the export, not
  just the events.
- **Sigma export** (`--format sigma`) — every finding rendered as a Sigma rule (one YAML
  document each) so a conclusion can be forwarded to a SIEM and made to fire elsewhere.
  Both event and state (`Fact`) findings are exported; rule ids are deterministic, so a
  re-export does not look like a new rule to a SIEM.
- **`l2tcsv` as an input source** — a parser that reads a plaso super-timeline back into
  the timeline, so detections run over a set that already fuses filesystem MACB timestamps
  with the auth events tracehound parses itself. Rows in a non-UTC named zone are skipped
  rather than guessed at.
- The export enriches the l2tcsv `extra` column with each event's scalar metadata, so a
  round-trip — export to a super-timeline, read it back, re-run detections — reproduces the
  original findings rather than only the raw events.
- Public API: `render_l2tcsv`, `render_timesketch_jsonl`, `render_sigma` from the package
  root; the `tracehound.export` module and `tracehound.parsers.l2tcsv`.

### Notes

l2tcsv is a lossy interchange format by nature — it carries a timeline, not tracehound's
full object graph. The `extra` enrichment recovers the scalar metadata the detections key
on, but a value containing the column separator is dropped rather than corrupt the row, so
a metadata field with embedded delimiters may not survive. The timeline, the messages and
the fields the standard detections use always do.

## [0.6.0] — 2026-07-25

State artifacts. Everything tracehound read until now was an *event* — something that
happened at a moment in time. But the most durable evidence an intruder leaves is *state*:
a second UID-0 account, a passwordless sudoers grant, an SSH key nobody recognises, a
service unit pointing at `/tmp`. None of these have a meaningful timestamp, so none of them
fit `Event` — and forcing them in would mean inventing a time, which this project refuses
to do everywhere else.

### Added

- **`Fact` model** — an entity-attribute-value triple (`subject`, `attribute`, `value`,
  `source`, `metadata`) for state artifacts, alongside the existing `Event`. Subjects are
  namespaced by kind (`account:root`, `sudo:%wheel`, `unit:evil.service`) so unrelated
  artifacts never collide. It carries no timestamp on purpose.
- **`FactBase`** — the state counterpart to `Timeline`: unordered, indexed for the flat
  questions detections ask (`with_attribute("uid")`, `value(subject, "shell")`).
- **`FactParser` / `FactDetection`** interfaces with their own registries, mirroring the
  event side. A rule id disables a fact rule exactly as it disables an event rule.
- **Five state parsers**: `/etc/passwd`, `/etc/group`, `/etc/sudoers` (and `sudoers.d`),
  SSH `authorized_keys`, and systemd unit files. These were already gathered by the
  collector and, until now, ignored.
- **Five state detections**:
  - **THN-0040** — multiple, or non-root, accounts with UID 0.
  - **THN-0041** — passwordless or wildcard sudoers grants to a non-standard principal.
  - **THN-0042** — authorised SSH key using a deprecated algorithm or forcing an
    interpreter via a `command=` option.
  - **THN-0043** — systemd unit executing from a world-writable path (`/tmp`, `/var/tmp`,
    `/dev/shm`).
  - **THN-0044** — system account (UID below 1000) with an interactive login shell.
- Reports (text, JSON, HTML) now surface the fact base and render fact-only findings with
  their supporting facts; `tracehound parsers` and `tracehound rules` list the state
  parsers and rules too.

### Notes

This was scheduled deliberately at six parsers rather than later: it is a model change,
and model changes get more expensive with every parser added. Each state detection names
the innocent explanation alongside the suspicious one — an alternate root, a deployment
account, a legacy key can all be legitimate — and every one is suppressible through the
existing `service_accounts` and `disabled_rules` config, so a tuned scan stays quiet.

## [0.5.0] — 2026-07-23

Collection. tracehound could analyse evidence but nothing gathered it, which left two
things permanently out of reach: the clock offsets the multi-host work needs, and any
account of what happened to the evidence between the host and the analyst.

### Added

- **`collect/tracehound-collect.sh`** — dependency-free POSIX shell collector. Runs on
  minimal images and busybox, does not require root, and takes artifacts in volatility
  order: running processes, network state and logged-in users before anything on disk.
- **Clock measurement at collection time.** `-r REFERENCE_UTC` records how far the
  host's clock sits from a trusted source. This is the only moment that measurement can
  be taken, and it is exactly what `--clock-offset` consumes.
- **Collection manifest** (`manifest.json`) — every artifact with its source path,
  size and SHA-256 taken at the moment of collection, plus everything that was skipped
  and why, and the collector's own footprint.
- **`tracehound verify MANIFEST`** — re-hashes every artifact and compares against the
  collection-time digest. Exit 1 on mismatch.
- **`tracehound case --manifest`** — derives host name and clock offset from manifests,
  so measured offsets need no manual entry. Verification runs first and refuses to
  analyse altered evidence (exit 3) unless `--skip-verify` is given.
- `tracehound.manifest` module and `build_case_from_manifests()` for library use.

### Notes

Hashing on ingest — which tracehound already did — proves only that a file has not
changed since analysis began. That is the wrong question. The interval that matters is
between collection and analysis, where evidence is copied, emailed and staged, and only a
digest taken on the host can close it.

---

## [0.4.0] — 2026-07-23

Multi-host investigations. Until now tracehound examined one machine at a time, which
cannot answer the questions that matter most in a real incident: where did this start,
and how did it spread?

### Added

- **`Case` and `Host` model** (`tracehound.case`) — several hosts examined as one
  investigation, with a merged timeline where every event is tagged with its origin host.
- **`tracehound case` command** — scan several hosts and report what only appears when
  their evidence is considered together:

  ```bash
  tracehound case --host web01=/evidence/web01 --host db01=/evidence/db01 --year 2024
  ```

- **Four cross-host detections:**
  - `THN-1001` — shared attacker infrastructure: one source address active against
    multiple hosts, with the order of first contact.
  - `THN-1002` — account reused across hosts: an account created on one machine that
    later authenticated on another. Lateral movement.
  - `THN-1003` — earliest compromised host: the likely entry point for a given attacker.
  - `THN-1004` — cross-host ordering not established: raised when unverified clocks make
    a sequence claim unsafe.
- **Declared clock offsets** — `--clock-offset NAME=SECONDS` applies a measured
  correction to a host's timestamps and marks its clock as verified.
- **Case reports** in text and JSON, including per-host evidence provenance.

### Notes on the clock problem

Clock drift is irrelevant within one host, because every event shifts together. Across
hosts the same drift can invert cause and effect, making it appear that the second
machine compromised the first.

tracehound therefore **never infers a clock offset**. Where two hosts both show one
attacker, the apparent timing difference is genuinely ambiguous — it may be drift, or the
attacker may simply have reached one host before the other — and no arithmetic separates
those from artifacts alone. Offsets are applied only when a human supplies them; without
one, a host is marked `assumed` and ordering claims are hedged rather than asserted.

`SAFE_ORDERING_MARGIN` (5 minutes) is the threshold below which an ordering is not
claimed on unverified clocks. Findings that fall inside it say so in their own text and
downgrade their severity.

---

## [0.3.0] — 2026-07-23

### Added

- **Evidence provenance** — every input file is hashed (SHA-256) on ingest and listed in
  the report with its parser, size and event count, including the files that were skipped
  and why. A triage report that cannot say exactly which bytes it read is weak evidence.
- **Tuning configuration** (`--config`) — allowlisted source addresses and service
  accounts, expected cron globs, adjustable thresholds and per-rule disabling. JSON
  always; YAML with the `[yaml]` extra.
- **systemd journal parser** — reads `journalctl -o json` output, as JSON Lines or a JSON
  array. Needed on hosts and containers where `/var/log/auth.log` does not exist at all.
- **Three anti-forensics detections:**
  - `THN-0030` — gap in log coverage, measured against each source's own median cadence
    rather than a fixed number.
  - `THN-0031` — binary login database truncated mid-record.
  - `THN-0032` — shell history missing for an account that ran privileged commands.
- **Declarative rules** (`--rules`) — JSON or YAML rule files with match filters and
  optional clustering thresholds, so rules can be added without writing Python.

### Changed

- `Detection.run()` now receives the `Config`, so suppression happens at the point of
  judgement rather than as a post-filter. Filtering afterwards loses the reason a finding
  was dropped.
- **The `wtmp` parser now accepts a partial trailing record** instead of rejecting the
  file. That truncation is precisely the evidence worth keeping — the previous behaviour
  discarded it.
- Loaded declarative rules stay out of the global registry, so a rule file cannot leak
  into an unrelated scan in the same process.

---

## [0.2.0] — 2026-07-23

### Added

- **`lastlog` parser** — 292-byte array indexed by UID. Sparse zero records mean "never
  logged in" and are skipped rather than reported as events.
- **Shell history parser** — `.bash_history` and `.zsh_history`, handling both
  `HISTTIMEFORMAT` epochs and the bare default format.
- **Cron log parser** — `CROND` execution records with the scheduled command extracted.
- `THN-0020` — suspicious command recorded in shell history.
- `THN-0021` — scheduled task running from a world-writable path, piping a download into
  a shell, or invoking an inline interpreter.

### Changed

- **Parser selection now uses an explicit `priority`** rather than import order. A cron
  log is also valid syslog, so it must be offered the file before the catch-all
  `auth.log` parser claims it — and that ordering cannot be left to a formatter's whim.

### Notes

Undated shell history is anchored to the file's mtime, tagged
`timestamp_precision: file_mtime`, and any finding built on it says so in its own text.
A timeline that quietly implies precision it does not have is a liability in a report.

---

## [0.1.0] — 2026-07-23

Initial release.

### Added

- **`auth.log` parser** — sshd, sudo, PAM, `useradd`/`usermod`/`groupadd` and
  systemd-logind, in both syslog and ISO-8601 timestamp formats, with year-rollover
  handling for the syslog format's missing year.
- **`wtmp`/`utmp`/`btmp` parser** — 384-byte binary records parsed directly.
- **Unified timeline** with UTC enforced at the model level: `Event` rejects naive
  timestamps outright, so a parser cannot accidentally emit local time.
- **Seven detections** covering credential attacks, persistence and privilege abuse, each
  mapped to MITRE ATT&CK.
- **Reports** in text, JSON, CSV and self-contained HTML.
- Synthetic test fixtures, including byte-accurate `wtmp` records, so no real evidence is
  ever committed to the repository.

### Notes

The brute-force rule counts *attempts*, not log lines. A single failed SSH attempt writes
three or four lines (`Invalid user`, `pam_unix`, `Failed password`), so counting lines
overstated attacks roughly threefold. Events are deduplicated by connection.

[0.5.0]: https://github.com/Noxiidus/tracehound/releases/tag/v0.5.0
[0.4.0]: https://github.com/Noxiidus/tracehound/releases/tag/v0.4.0
[0.3.0]: https://github.com/Noxiidus/tracehound/releases/tag/v0.3.0
[0.2.0]: https://github.com/Noxiidus/tracehound/releases/tag/v0.2.0
[0.1.0]: https://github.com/Noxiidus/tracehound/releases/tag/v0.1.0
