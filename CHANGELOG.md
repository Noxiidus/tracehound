# Changelog

All notable changes to this project are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this
project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

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
