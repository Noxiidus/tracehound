# Security Policy

tracehound is a forensics tool: it is pointed at untrusted, attacker-controlled evidence by
design. A parser that crashes, hangs, or executes attacker-supplied content on hostile input
is a security bug, not merely a robustness one, and is treated as such here.

## Supported versions

Fixes land on the latest minor release line. Once `1.0` is published, security fixes are
backported to the most recent minor series only.

| Version | Supported |
|---|---|
| latest `1.x` | ✅ |
| `0.9.x` | ✅ until 1.1 |
| older | ❌ |

## Reporting a vulnerability

**Please do not open a public issue for a security vulnerability.**

- Preferred: open a private report through GitHub Security Advisories —
  <https://github.com/Noxiidus/tracehound/security/advisories/new>.
- Or email the maintainer at `ankara.herho@gmail.com` with `tracehound security` in the
  subject.

Please include the tracehound version, the input that triggers the issue (a synthetic
artifact is fine — do not send real evidence or PII), and what you observed. A minimal
reproduction against `tests/synth.py`-style generated data is ideal.

You can expect an acknowledgement within a few days and an assessment of severity and fix
timeline. Coordinated disclosure is welcome; credit is given unless you prefer otherwise.

## Scope

In scope — anything reachable by feeding tracehound crafted input or a crafted rule/config:

- A parser or the scan pipeline crashing with an uncaught exception on malformed input
  (rather than a typed `RuleError` / `SigmaError` / `ConfigError` / `ManifestError`, or a
  skipped-artifact record).
- A denial of service — unbounded memory or a hang — from a crafted artifact or evidence
  tree (for example a directory symlink cycle).
- Content injection into a generated report (HTML markup, spreadsheet formulas in CSV) from
  attacker-controlled log fields.
- Any path that would execute attacker-supplied content during analysis.

Out of scope:

- The accuracy or completeness of a detection (a false positive or false negative is a
  detection-tuning matter, not a vulnerability).
- Vulnerabilities in third-party tools whose output tracehound merely reads (plaso,
  journalctl, and so on).

## Design stance

tracehound never executes collected artifacts, keeps everything read-only, and generates its
own synthetic test evidence so no real evidence is ever committed. Malformed input is
expected and must degrade to a typed error or a recorded skip, never a crash — this invariant
is exercised by a randomised fuzzing pass over every parser, loader and report format.
