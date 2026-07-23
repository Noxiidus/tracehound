# tracehound

**Linux DFIR triage — parse host artifacts into a unified timeline and surface attacker behaviour.**

[![CI](https://github.com/Noxiidus/tracehound/actions/workflows/ci.yml/badge.svg)](https://github.com/Noxiidus/tracehound/actions/workflows/ci.yml)
[![Python](https://img.shields.io/badge/python-3.10%2B-blue)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/license-MIT-green)](LICENSE)

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
| `auth.log` | `auth.log`, `secure` | sshd, sudo, PAM, useradd/usermod/groupadd, systemd-logind. Both syslog and ISO-8601 timestamps. |

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

## Roadmap

- Parsers: systemd journal export, `/etc/passwd` and `/etc/shadow` diffing, `sudoers`
- Detections: log tampering, SSH key manipulation, impossible-travel logins
- Super-timeline export (`l2tcsv`) for Timesketch interoperability
- Optional YAML rule definitions so detections can be added without writing Python

## License

MIT — see [LICENSE](LICENSE).
