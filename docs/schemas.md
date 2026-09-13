# Output schemas

The machine-readable formats tracehound produces, so downstream tooling can rely on them.
Within a major version, fields are **added** but never removed or repurposed (see
[api.md](api.md)). All timestamps are ISO-8601 and UTC.

## Report JSON (`tracehound scan -f json`)

```jsonc
{
  "tool": "tracehound",
  "generated_at": "2026-09-13T12:00:00+00:00",
  "summary": {
    "event_count": 1234,
    "start": "2026-03-06T06:31:31+00:00",   // null if no events
    "end":   "2026-03-06T06:45:02+00:00",
    "sources": { "auth.log": 1200, "wtmp": 34 },
    "finding_count": 7,
    // present only when state artifacts were parsed:
    "fact_count": 68,
    "fact_subjects": 11,
    "fact_sources": { "passwd": 30, "sudoers": 8 }
  },
  "findings": [ /* Finding objects, see below */ ],
  "provenance": {                            // present when the scan result is supplied
    "tool": "tracehound",
    "tool_version": "1.0.0",
    "scanned_at": "2026-09-13T12:00:00+00:00",
    "artifacts": [ /* ArtifactRecord objects, see below */ ]
  }
}
```

**Finding**

```jsonc
{
  "rule_id": "THN-0002",
  "title": "Successful login after brute-force",
  "severity": "critical",                    // info|low|medium|high|critical
  "description": "…",
  "attack_techniques": ["T1110", "T1078"],
  "first_seen": "…",                          // null for a fact-only finding
  "last_seen":  "…",                          // null for a fact-only finding
  "event_count": 6,
  "fact_count": 0,
  "metadata": { /* rule-specific */ },
  "events": [ /* Event objects; omitted when include_events=false */ ],
  "facts":  [ /* Fact objects;  omitted when include_events=false */ ]
}
```

**Event**: `timestamp, source, event_type, message, user, source_ip, process, pid, terminal,
raw, metadata`. `event_type` is a value of the `EventType` enum; `user`/`source_ip`/
`process`/`pid`/`terminal` may be `null`.

**Fact**: `subject` (namespaced `kind:name`, e.g. `account:root`), `attribute`, `value`,
`source`, `metadata`. No timestamp — a fact describes state, not an event.

**ArtifactRecord**: `path, size, sha256, parser, event_count, fact_count, skipped_reason,
reused`. `parser` is `null` and `skipped_reason` set when a file was not parsed; `reused` is
`true` when an incremental scan reused a prior run's events for an unchanged file.

## Collection manifest (`manifest.json`, from `tracehound-collect`)

```jsonc
{
  "tool": "tracehound-collect",
  "version": "1.0.0",
  "hostname": "web01",
  "collected_by": "root",
  "started_at": "…", "finished_at": "…",
  "hash_algorithm": "sha256",
  "hash_tool": "sha256sum",
  "clock": {
    "host_utc": "…",
    "reference_utc": "…",       // null if no -r reference supplied
    "offset_seconds": 7,        // null if unmeasured; +ve means the host clock ran slow
    "note": "measured against supplied reference"
  },
  "artifacts": [ { "path": "artifacts/auth.log", "source": "/var/log/auth.log",
                   "sha256": "…", "size": 12345 } ],
  "skipped":   [ { "source": "/var/log/btmp", "reason": "permission denied" } ]
}
```

`offset_seconds` is the only clock correction tracehound will apply, and only because a human
measured it; unmeasured hosts stay hedged. `tracehound verify` re-hashes each artifact and
compares against `sha256` here, so a change between collection and analysis is caught.

## Interoperability exports

- **l2tcsv** (`-f l2tcsv`): the standard 17-column log2timeline CSV —
  `date,time,timezone,MACB,source,sourcetype,type,user,host,short,desc,version,filename,inode,notes,format,extra`.
  One row per event; `notes` carries the rule ids of findings citing that event. Read back
  in by the `l2tcsv` parser. Timestamps are UTC.
- **Timesketch JSONL** (`-f timesketch`): one JSON object per line with Timesketch's required
  `datetime`, `timestamp_desc`, `message`, plus tracehound fields; events backing a finding
  carry its rule id, severity and ATT&CK techniques as `tag`s and dedicated fields.
- **Sigma** (`-f sigma`): one Sigma rule YAML document per finding, with a deterministic
  `id`, `level`, `logsource`, `detection`/`condition`, and `attack.*` `tags`.
