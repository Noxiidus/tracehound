# Roadmap

Where tracehound is going, and why. Versions are ordered by dependency, not by ambition —
each one unblocks the next.

Nothing here is a commitment to a date. Items may move if something more useful appears,
and the [declined](#considered-and-declined) section is as much a part of the plan as the
rest.

---

## 0.6.0 — State artifacts and the `Fact` model

**The problem.** Everything tracehound reads today is an *event*: something that happened
at a moment in time. But some of the most important evidence on a Linux host is *state* —
what a file contains right now:

- A second account with UID 0 in `/etc/passwd`
- An unexpected `NOPASSWD: ALL` line in `/etc/sudoers`
- An SSH key in `authorized_keys` that nobody recognises
- A systemd unit pointing at `/tmp`

None of these have a meaningful timestamp, so none of them fit `Event`. Forcing them in
would mean inventing a time, which the project already refuses to do elsewhere.

**The work.** A second model alongside `Event`:

```python
@dataclass
class Fact:
    subject: str        # "account:root", "unit:evil.service"
    attribute: str      # "uid", "shell", "exec_start"
    value: str
    source: str
    metadata: dict
```

Plus a `FactDetection` interface, and parsers for `/etc/passwd`, `/etc/group`,
`/etc/sudoers`, `authorized_keys` and systemd unit files. The collector already gathers
most of these — they are currently collected and then ignored.

**Why now.** This is a model change, and model changes get more expensive with every
parser added. Six is a good number to do it at; fifteen would not be.

**Expected rules:** duplicate UID 0, unexpected sudoers grant, SSH key with an unusual
comment or type, systemd unit executing from a world-writable path, service account with a
login shell.

---

## 0.7.0 — Interoperability

**The problem.** tracehound currently produces its own timeline in its own formats. Real
DFIR shops already run Timesketch, plaso and log platforms, and a tool that cannot feed
them is a tool that stays a curiosity.

**The work.**

- **`l2tcsv` export** — the plaso/log2timeline super-timeline format, so tracehound output
  drops into Timesketch alongside filesystem and browser timelines.
- **Timesketch JSONL export** with tracehound findings as annotations, so the *reasoning*
  survives the export, not just the events.
- **plaso CSV as an input source** — a parser that reads a super-timeline and runs
  tracehound detections against it. Filesystem MACB timestamps alongside auth events is a
  strictly better timeline than either alone.
- **Sigma-compatible output** for findings, so they can be forwarded to a SIEM.

**Why after 0.6.0.** Facts need a representation in the export format, and defining that
twice would be wasteful.

---

## 0.8.0 — Sigma rule support

**The problem.** The declarative rule format works, but it is tracehound's own. The
industry already standardised on [Sigma](https://sigmahq.io/), and there is a body of
public Linux rules that tracehound cannot use.

**The work.** A loader for a practical subset of the Sigma specification — `logsource`,
`detection` with selection/condition, `fields`, `level`, `tags` — mapped onto the existing
`Detection` interface. Not the whole spec: the parts that make sense for host artifacts,
with clear errors for the parts that do not.

The native YAML format stays. Sigma is verbose for simple things, and "flag this command
pattern" should not require a `condition` expression.

**Why it matters.** This is the difference between "a tool one person wrote rules for" and
"a tool that runs the rules a community already maintains".

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
