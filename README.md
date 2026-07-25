# tracehound

**Linux DFIR triage — parse host artifacts into a unified timeline and surface attacker behaviour.**

[![CI](https://github.com/Noxiidus/tracehound/actions/workflows/ci.yml/badge.svg)](https://github.com/Noxiidus/tracehound/actions/workflows/ci.yml)
[![Python](https://img.shields.io/badge/python-3.10%2B-blue)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![Changelog](https://img.shields.io/badge/changelog-CHANGELOG.md-orange)](CHANGELOG.md)
[![Wiki](https://img.shields.io/badge/docs-wiki-purple)](https://github.com/Noxiidus/tracehound/wiki)

Point it at `/var/log`, a mounted image, or a folder of collected evidence. It parses what it
recognises, merges everything into one UTC-normalised timeline, and applies detection rules that
turn raw events into findings with MITRE ATT&CK mappings.

```console
$ tracehound scan ./evidence --year 2024

tracehound report
======================================================================

Events parsed : 71
Time range    : 2024-03-06 06:17:15 .. 2024-03-06 06:41:01 UTC
Sources       : auth.log (66), wtmp (5)
Findings      : 7

----------------------------------------------------------------------
[1] CRITICAL  Compromised account 'root' via brute-force from 65.2.161.68
    rule    : THN-0002
    window  : 2024-03-06 06:31:31 .. 2024-03-06 06:32:44 UTC
    ATT&CK  :
              T1110 — Brute Force (Credential Access)
              T1078 — Valid Accounts (Defense Evasion)

    24 failed attempts from 65.2.161.68 preceded a successful login as
    'root' at 2024-03-06 06:32:44 UTC. Treat this account as compromised.
```

## Why

Analysing a compromised Linux host means reading `auth.log` alongside `wtmp`, reconciling their
timestamps, and holding the sequence in your head. It works, but it does not scale and it is easy
to get subtly wrong — the bundled `utmp` parsers most people reach for render timestamps in
**local time**, which silently shifts an entire investigation without ever throwing an error.

tracehound does that correlation mechanically, in UTC, every time.

## Install

Requires Python 3.10 or newer. No third-party runtime dependencies.

```bash
pip install git+https://github.com/Noxiidus/tracehound.git
```

Pin a specific version if you want reproducibility:

```bash
pip install git+https://github.com/Noxiidus/tracehound.git@v0.2.0
```

For development, clone and install in editable mode with the test extras:

```bash
git clone https://github.com/Noxiidus/tracehound
cd tracehound
pip install -e ".[dev]"
```

## Usage

```bash
# Triage a directory of collected artifacts
tracehound scan ./evidence --year 2024

# Only what matters, as JSON, for downstream tooling
tracehound scan /var/log -f json --min-severity high -o findings.json

# A shareable, self-contained HTML report
tracehound scan ./evidence -f html -o report.html

# The full timeline as CSV, for a spreadsheet or a super-timeline
tracehound scan ./evidence -f csv -o timeline.csv

# Non-zero exit if anything is found — for pipelines
tracehound scan /var/log --min-severity high --fail-on-findings

tracehound parsers   # what it can read
tracehound rules     # what it looks for
```

### `--year` matters

Syslog timestamps omit the year. Without a hint tracehound assumes the current one, which is
correct for live triage and wrong for archived evidence. Pass `--year` whenever the logs are not
from this year. Year rollover *within* a file (December followed by January) is detected and
handled automatically.

## As a library

```python
from pathlib import Path
from tracehound import scan

result = scan([Path("evidence/")], year=2024)

for finding in result.findings:
    print(f"[{finding.severity.value}] {finding.title}")
    for technique in finding.attack_techniques:
        print(f"    {technique}")

# The timeline is queryable on its own
for event in result.timeline.by_ip("65.2.161.68"):
    print(event.timestamp, event.message)
```

## Supported artifacts

| Parser | Files | Notes |
|---|---|---|
| `wtmp` | `wtmp`, `utmp`, `btmp` | Binary 384-byte records parsed directly. `btmp` entries are classified as failures. |
| `lastlog` | `lastlog` | 292-byte array indexed by UID. Sparse zero records mean "never logged in" and are skipped. |
| `shell_history` | `.bash_history`, `.zsh_history` | Handles `HISTTIMEFORMAT` epochs; undated entries are flagged, never silently dated. |
| `cron` | `cron`, `cron.log` | `CROND` execution records, with the scheduled command extracted. |
| `journal` | `journalctl -o json` output | JSON Lines or a JSON array. Needed on hosts where `auth.log` does not exist. |
| `auth.log` | `auth.log`, `secure` | sshd, sudo, PAM, useradd/usermod/groupadd, systemd-logind. Both syslog and ISO-8601 timestamps. |
| `l2tcsv` | log2timeline / plaso super-timeline CSV | Reads a plaso timeline back in so detections run over filesystem MACB timestamps and auth events together. The reverse of `--format l2tcsv`. |

State artifacts describe what a host *is* rather than what happened to it, so they produce
timeless `Fact`s (an entity-attribute-value model) rather than timeline events:

| Parser | Files | Notes |
|---|---|---|
| `passwd` | `/etc/passwd` | One `account:<name>` subject per line, carrying uid, gid, shell, home, gecos. |
| `group` | `/etc/group` | `group:<name>` with gid and member list — the standing membership no login event records. |
| `sudoers` | `/etc/sudoers`, `sudoers.d/*` | User specs broken into runas / NOPASSWD / commands; joins line continuations; keeps `Defaults` and aliases. |
| `authorized_keys` | `authorized_keys`, `authorized_keys2` | Options-before-type parsed correctly; records key type, comment, SHA256 fingerprint, inferred account. |
| `systemd_unit` | `*.service` and friends | ExecStart*, User, WorkingDirectory, Type, install targets — the keys that decide what a unit runs and as whom. |

Collect a journal export with:

```bash
journalctl -o json --no-pager > journal.json
```

Parser selection is driven by an explicit `priority`, not import order. A cron log is
also valid syslog, so it must be offered the file before the catch-all `auth.log` parser
claims it — and that ordering cannot be left to a formatter's whim.

## Detection rules

| ID | Severity | Detects | ATT&CK |
|---|---|---|---|
| THN-0001 | High | SSH brute-force — failure volume from one source | T1110, T1110.001 |
| THN-0002 | Critical | Successful login following a brute-force burst | T1110, T1078 |
| THN-0003 | Medium | Password spraying — many users, few attempts each | T1110.003 |
| THN-0010 | Medium | Local account creation | T1136.001 |
| THN-0011 | High | Account added to a privileged group | T1098, T1548.003 |
| THN-0012 | Critical | Backdoor account — created *and* privileged shortly after | T1136.001, T1098 |
| THN-0013 | High | Sensitive sudo command (shadow access, downloads, log destruction, …) | T1548.003 + per-pattern |
| THN-0020 | Medium | Suspicious command recorded in shell history | T1059.004 + per-pattern |
| THN-0021 | High | Scheduled task running from a world-writable path, piping downloads to a shell, … | T1053.003 |
| THN-0030 | Medium | Gap in log coverage — silence in an otherwise active log | T1070.002 |
| THN-0031 | High | Binary login database truncated mid-record | T1070.002 |
| THN-0032 | High | Shell history missing for an account that ran privileged commands | T1070.003 |
| THN-0040 | Critical | Multiple, or non-root, accounts holding UID 0 | T1136.001, T1078.003 |
| THN-0041 | High | Passwordless or wildcard sudoers grant to a non-standard principal | T1548.003 |
| THN-0042 | High/Med | Authorised SSH key forcing an interpreter, or using a deprecated algorithm | T1098.004, T1021.004 |
| THN-0043 | High | systemd unit executing from a world-writable path (`/tmp`, `/var/tmp`, `/dev/shm`) | T1543.002 |
| THN-0044 | Medium | System account (UID below 1000) with an interactive login shell | T1136.001 |

Rules THN-0040..0044 reason over state facts rather than the timeline, so they fire even
on a host whose logs have been wiped — the backdoor account, key or unit is still sitting
in the filesystem.

### Tuning

Run against a real internet-facing host and you will get a brute-force finding every
single day, because the internet brute-forces every SSH port every day. A report nobody
reads is worth nothing, so suppression is a first-class feature:

```jsonc
// tuning.json
{
  "known_ips": ["10.0.0.5", "203.0.113.9"],   // jump hosts, monitoring
  "service_accounts": ["deploy", "ansible"],   // expected automation
  "expected_cron": ["/opt/backup/*", "/usr/lib/sysstat/*"],
  "disabled_rules": ["THN-0003"],
  "brute_force_threshold": 25
}
```

```bash
tracehound scan /var/log -c tuning.json
```

### Custom rules

Most rules are not correlations — they are "flag events of this type whose command
matches this pattern". Requiring Python for those puts rule-writing out of reach of the
people most likely to have the domain knowledge, so rules can also be declared:

```yaml
# rules.yaml  (JSON works too, with no extra dependency)
rules:
  - id: LOCAL-0001
    title: Access to deployment secrets
    severity: high
    description: Someone read the deployment key material.
    attack: [T1552.001]
    match:
      event_type: [privilege_escalation, command_executed]
      command: "/etc/deploy/(id_rsa|secrets\\.env)"

  - id: LOCAL-0002
    title: Repeated sudo failures
    severity: medium
    match:
      event_type: login_failure
    threshold:
      count: 5
      window_seconds: 300
      group_by: source_ip
```

```bash
tracehound scan /var/log -r rules.yaml
```

`match` narrows which events qualify — every key must hold, and any key other than
`event_type`, `message`, `user` and `source_ip` is matched as a regex against that
metadata field. `threshold` turns the rule from "report each match" into "report only
when enough matches cluster together".

YAML needs `pip install tracehound[yaml]`; JSON needs nothing.

## Interoperability

tracehound feeds the platforms a DFIR shop already runs, and reads their timelines back:

```bash
tracehound scan /evidence -f l2tcsv    > timeline.csv     # plaso/log2timeline super-timeline
tracehound scan /evidence -f timesketch > timeline.jsonl  # Timesketch, findings as tags
tracehound scan /evidence -f sigma     > findings.yml      # one Sigma rule per finding
```

| Format | What it is |
|---|---|
| `l2tcsv` | The 17-column log2timeline CSV. Drops into Timesketch alongside filesystem, browser and registry timelines; the `notes` column carries the rule ids of findings that cite each event. |
| `timesketch` | Newline-delimited JSON. Each finding's rule id, severity and ATT&CK techniques ride along on the events it implicates as `tag`s and fields, so the reasoning survives — not just the events. |
| `sigma` | Each finding as a Sigma rule (event *and* state findings), with a stable id, ready to forward to a SIEM. |

The reverse direction works too: point `scan` at an `l2tcsv` super-timeline produced by
plaso and tracehound runs its detections over it, fusing filesystem MACB timestamps with
the auth events it parses itself.

```bash
tracehound scan super-timeline.csv        # detections over a plaso timeline
```

l2tcsv is a lossy interchange format — it carries a timeline, not tracehound's full object
graph — but the export enriches the `extra` column with each event's scalar metadata, so a
round-trip (export, read back, re-scan) reproduces the original findings, not just the raw
events.

## Design notes

**Parsers observe, detections conclude.** A parser turns `Failed password for invalid user admin`
into a `LOGIN_FAILURE` event and stops there. Deciding that twenty of them constitute an attack is
a detection's job. Keeping the boundary strict means new artifact sources immediately benefit from
every existing rule.

**UTC is enforced, not assumed.** `Event.__post_init__` rejects naive datetimes outright. A parser
cannot accidentally emit local time, because the model will not accept it.

**Correlation is the point.** THN-0012 exists because account creation alone is routine and a
privilege grant alone is routine — the two within a minute of each other is not. Findings that
combine evidence across sources are worth more than findings that restate a single log line.

**Absence of findings is not evidence of a clean host.** The reports say so explicitly. A triage
tool that implies otherwise is worse than no tool.

## Development

```bash
pip install -e ".[dev]"

pytest                    # tests
pytest --cov=tracehound   # with coverage
ruff check src tests      # lint
ruff format src tests     # format
mypy                      # type check (strict)
```

The test suite generates its own artifacts — see `tests/synth.py`, which writes byte-accurate
`wtmp` records so parser round-trips actually prove the struct layout. **No real evidence is
committed to this repository**, and none should be.

**Undated evidence stays undated.** Bare `.bash_history` files carry no timestamps at all. Rather
than invent times, entries are anchored to the file's mtime, tagged
`timestamp_precision: file_mtime`, and any finding built on them says so in its own text. A
timeline that quietly implies precision it does not have is a liability in a report.

**Absence is evidence too.** Every rule that reacts to events gets quieter the more thoroughly an
intruder cleans up. THN-0030 through THN-0032 invert that: a log that falls silent on a busy host,
a `wtmp` ending mid-record, a missing history for an account that demonstrably ran commands. Because
absence is weaker evidence than presence, these rules are deliberately conservative — gaps are
measured against each log's own median cadence rather than a fixed number, and every finding names
the benign explanations alongside the suspicious one.

**Every byte is accounted for.** Each input file is hashed on ingest and listed in the report with
its parser and event count, including the ones that were skipped and why. A triage report that
cannot say exactly which bytes it read is weak evidence.

## Collection

Something has to gather the evidence before tracehound can read it, and doing that
correctly is part of the job. [`collect/tracehound-collect.sh`](collect/tracehound-collect.sh)
is a dependency-free POSIX shell script that runs on the target host:

```bash
# On a host with a synced clock, note the reference time:
REF=$(date -u +%Y-%m-%dT%H:%M:%S)

# On the target:
./tracehound-collect.sh -r "$REF"
```

It does three things a plain `tar` does not:

**Records the host clock.** Drift can only be measured while the machine is running.
Captured here, it becomes the `--clock-offset` that turns hedged cross-host orderings
into established ones — see [the clock problem](#the-clock-problem) below.

**Hashes at collection time.** tracehound also hashes on ingest, but that proves nothing
about the interval in between, where evidence is copied, staged and moved. Comparing the
two digests closes that window:

```bash
tracehound verify ./tracehound-web01-.../manifest.json
```

A mismatch is reported and, during a case, refuses to proceed without `--skip-verify`.
Evidence that changed after it left the host is a finding, not an inconvenience.

**Records its own footprint.** Collection touches the host. `footprint.txt` lists every
command run, because documenting the contamination is better than pretending there was
none.

Artifacts are taken in volatility order — running processes, network state and logged-in
users before anything on disk — since that is the evidence that cannot be recovered
later. Root is not required; without it, unreadable artifacts appear in the manifest's
`skipped` list rather than silently vanishing.

## Multi-host investigations

One machine is rarely the whole story. `tracehound case` scans several hosts and reports
what only appears when their evidence is considered together:

```bash
tracehound case \
  --host web01=/evidence/web01 \
  --host db01=/evidence/db01 \
  --host app02=/evidence/app02 \
  --year 2024
```

| ID | Severity | Detects |
|---|---|---|
| THN-1001 | High | One source address active against multiple hosts, with order of first contact |
| THN-1002 | Critical | An account created on one host that later authenticated on another |
| THN-1003 | Medium | The host an attacker reached first — the likely entry point |
| THN-1004 | Medium | Ordering that cannot be established because clocks are unverified |

### The clock problem

Drift is harmless within one host, because every event shifts together. **Across hosts
the same drift can invert cause and effect** — making it look as though the second
machine compromised the first.

tracehound never *infers* an offset. Where two hosts both show one attacker, the apparent
timing difference is genuinely ambiguous: it may be drift, or the attacker may simply
have reached one host before the other. Nothing in the artifacts distinguishes those. So
offsets are applied only when you supply them:

```bash
tracehound case --host web01=/ev/web01 --host db01=/ev/db01 \
  --clock-offset web01=0 --clock-offset db01=-137
```

Without one, a host is marked `assumed`, and any ordering claim inside five minutes is
hedged rather than asserted — THN-1003 downgrades itself to a *candidate*, and THN-1004
explains why. Supply measured offsets and the same findings become conclusions.

If you collected with `tracehound-collect.sh -r`, the offsets are already in the
manifests and nothing needs supplying by hand:

```bash
tracehound case --manifest ev/web01/manifest.json --manifest ev/db01/manifest.json
```

This also verifies every artifact against its collection-time digest before analysing it.

## Roadmap

Full detail, with reasoning, in [ROADMAP.md](ROADMAP.md).

| Version | Theme |
|---|---|
| **0.6.0** | State artifacts and the `Fact` model — `/etc/passwd`, `sudoers`, `authorized_keys`, systemd units |
| **0.7.0** | Interoperability — `l2tcsv` and Timesketch export, plaso super-timelines as input |
| **0.8.0** | Sigma rule support, so the community's existing Linux rules run unmodified |
| **0.9.0** | Scale — streaming parse, optional on-disk timeline, incremental scanning |
| **1.0.0** | API freeze, rule-ID policy, schema compatibility, PyPI |
| post-1.0 | Windows artifacts (EVTX, registry, prefetch, MFT) |

Deliberately **not** planned: memory forensics, ML anomaly detection, a live agent, a web
UI, automated remediation. The [roadmap](ROADMAP.md#considered-and-declined) explains why
each was declined.
- Super-timeline export (`l2tcsv`) for Timesketch interoperability
- Optional YAML rule definitions so detections can be added without writing Python

## License

MIT — see [LICENSE](LICENSE).
