#!/bin/sh
# tracehound-collect — forensic artifact collection for Linux hosts.
#
# Collects the artifacts tracehound parses, hashes each one at the moment it is taken,
# and writes a manifest describing exactly what was gathered and under what conditions.
#
# Three things this does that a plain `tar` does not:
#
#   1. Records the host clock. Clock drift is harmless within one machine but can invert
#      cause and effect across machines, and it cannot be recovered after the fact. The
#      only moment it can be measured is now.
#
#   2. Hashes at collection time rather than analysis time. A digest taken later proves
#      only that the file has not changed since analysis began — which is the wrong
#      question.
#
#   3. Records its own footprint. Collection touches the host. Pretending otherwise is
#      worse than documenting it.
#
# POSIX sh with no dependencies beyond coreutils, so it runs on minimal images and
# busybox. Root is not required; without it some artifacts are unreadable and the
# manifest says which.
#
# Usage:
#   ./tracehound-collect.sh [-o OUTPUT_DIR] [-r REFERENCE_UTC] [-n HOSTNAME]
#
#   -o  where to write the collection   (default: ./tracehound-<host>-<timestamp>)
#   -r  trusted UTC time as YYYY-MM-DDTHH:MM:SS, taken from an NTP-synced machine at
#       the moment of collection; used to compute this host's clock offset
#   -n  override the recorded hostname
#
# Example, with a reference clock:
#   ./tracehound-collect.sh -r "$(date -u +%Y-%m-%dT%H:%M:%S)"

set -eu

VERSION="0.8.3"
OUT=""
REFERENCE=""
HOSTNAME_OVERRIDE=""

while getopts "o:r:n:h" opt; do
    case "$opt" in
        o) OUT="$OPTARG" ;;
        r) REFERENCE="$OPTARG" ;;
        n) HOSTNAME_OVERRIDE="$OPTARG" ;;
        h) sed -n '2,33p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *) echo "usage: $0 [-o OUTPUT_DIR] [-r REFERENCE_UTC] [-n HOSTNAME]" >&2; exit 2 ;;
    esac
done

HOST="${HOSTNAME_OVERRIDE:-$(hostname 2>/dev/null || echo unknown)}"
STARTED="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
[ -n "$OUT" ] || OUT="./tracehound-${HOST}-${STAMP}"

ARTIFACTS="$OUT/artifacts"
VOLATILE="$OUT/volatile"
MANIFEST="$OUT/manifest.json"
FOOTPRINT="$OUT/footprint.txt"

mkdir -p "$ARTIFACTS" "$VOLATILE"

# ---------------------------------------------------------------- helpers

log() { printf '%s\n' "$*" >&2; }

# Pick whatever digest tool exists. Order matters only in that sha256sum is the most
# common; the manifest records which was used so a reviewer can reproduce it.
HASH_TOOL=""
if command -v sha256sum >/dev/null 2>&1; then
    HASH_TOOL="sha256sum"
elif command -v shasum >/dev/null 2>&1; then
    HASH_TOOL="shasum -a 256"
elif command -v openssl >/dev/null 2>&1; then
    HASH_TOOL="openssl-dgst"
fi

hash_file() {
    case "$HASH_TOOL" in
        sha256sum)      sha256sum "$1" 2>/dev/null | cut -d' ' -f1 ;;
        "shasum -a 256") shasum -a 256 "$1" 2>/dev/null | cut -d' ' -f1 ;;
        openssl-dgst)   openssl dgst -sha256 "$1" 2>/dev/null | sed 's/.*= //' ;;
        *)              echo "" ;;
    esac
}

file_size() {
    if command -v stat >/dev/null 2>&1; then
        stat -c %s "$1" 2>/dev/null || stat -f %z "$1" 2>/dev/null || echo 0
    else
        wc -c < "$1" 2>/dev/null | tr -d ' ' || echo 0
    fi
}

# Minimal JSON string escaping: backslash and double quote are the only characters that
# can appear in a path and break the document.
json_escape() {
    printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g'
}

ART_ENTRIES=""
SKIP_ENTRIES=""

add_artifact() {
    src="$1"
    dest_rel="$2"
    dest="$ARTIFACTS/$dest_rel"

    if [ ! -e "$src" ]; then
        SKIP_ENTRIES="${SKIP_ENTRIES}    {\"source\": \"$(json_escape "$src")\", \"reason\": \"not present\"},
"
        return 0
    fi
    if [ ! -r "$src" ]; then
        SKIP_ENTRIES="${SKIP_ENTRIES}    {\"source\": \"$(json_escape "$src")\", \"reason\": \"permission denied\"},
"
        return 0
    fi

    mkdir -p "$(dirname "$dest")"
    if ! cp -p "$src" "$dest" 2>/dev/null; then
        SKIP_ENTRIES="${SKIP_ENTRIES}    {\"source\": \"$(json_escape "$src")\", \"reason\": \"copy failed\"},
"
        return 0
    fi

    digest="$(hash_file "$dest")"
    size="$(file_size "$dest")"
    ART_ENTRIES="${ART_ENTRIES}    {\"path\": \"artifacts/$(json_escape "$dest_rel")\", \"source\": \"$(json_escape "$src")\", \"sha256\": \"$digest\", \"size\": $size},
"
    log "  collected $src"
}

record() {
    name="$1"
    shift
    if "$@" > "$VOLATILE/$name" 2>/dev/null; then
        printf '%s\t%s\n' "$name" "$*" >> "$FOOTPRINT"
    else
        rm -f "$VOLATILE/$name"
    fi
}

# ---------------------------------------------------------------- clock

HOST_UTC="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
OFFSET="null"
OFFSET_NOTE="no reference supplied; offset unknown"

if [ -n "$REFERENCE" ]; then
    # Positive offset means this host's clock runs slow relative to the reference, which
    # is the direction tracehound adds when building a case timeline.
    if ref_epoch="$(date -u -d "$REFERENCE" +%s 2>/dev/null)"; then
        host_epoch="$(date -u +%s)"
        OFFSET="$((ref_epoch - host_epoch))"
        OFFSET_NOTE="measured against supplied reference"
    else
        OFFSET_NOTE="reference '$REFERENCE' could not be parsed; offset unknown"
        log "warning: could not parse reference time '$REFERENCE'"
    fi
fi

# ---------------------------------------------------------------- volatile first

# Volatility order: what disappears on reboot or on process exit is taken before what
# sits on disk. Getting this backwards loses exactly the evidence that cannot be
# recovered later.
log "collecting volatile state..."
: > "$FOOTPRINT"
record "processes.txt"    ps auxww
record "network.txt"      sh -c 'ss -tunap 2>/dev/null || netstat -tunap 2>/dev/null'
record "logged_in.txt"    who -a
record "listening.txt"    sh -c 'ss -tlnp 2>/dev/null || netstat -tlnp 2>/dev/null'
record "modules.txt"      lsmod
record "mounts.txt"       cat /proc/mounts
record "uptime.txt"       uptime
record "crontab_root.txt" crontab -l

# ---------------------------------------------------------------- artifacts

log "collecting log artifacts..."
add_artifact /var/log/auth.log      auth.log
add_artifact /var/log/secure        secure
add_artifact /var/log/wtmp          wtmp
add_artifact /var/log/btmp          btmp
add_artifact /var/run/utmp          utmp
add_artifact /var/log/lastlog       lastlog
add_artifact /var/log/cron          cron
add_artifact /var/log/cron.log      cron.log
add_artifact /etc/passwd            etc/passwd
add_artifact /etc/group             etc/group
add_artifact /etc/sudoers           etc/sudoers
add_artifact /etc/crontab           etc/crontab

# systemd journal, where it exists. Exported rather than copied raw: the binary format is
# versioned and machine-specific, while the JSON export is stable and hashable.
if command -v journalctl >/dev/null 2>&1; then
    if journalctl -o json --no-pager > "$ARTIFACTS/journal.json" 2>/dev/null; then
        digest="$(hash_file "$ARTIFACTS/journal.json")"
        size="$(file_size "$ARTIFACTS/journal.json")"
        ART_ENTRIES="${ART_ENTRIES}    {\"path\": \"artifacts/journal.json\", \"source\": \"journalctl -o json\", \"sha256\": \"$digest\", \"size\": $size},
"
        printf '%s\t%s\n' "journal.json" "journalctl -o json" >> "$FOOTPRINT"
        log "  collected journalctl export"
    else
        rm -f "$ARTIFACTS/journal.json"
        SKIP_ENTRIES="${SKIP_ENTRIES}    {\"source\": \"journalctl -o json\", \"reason\": \"export failed\"},
"
    fi
fi

# Shell history for every account with a home directory.
log "collecting shell history..."
for home in /root /home/*; do
    [ -d "$home" ] || continue
    owner="$(basename "$home")"
    [ "$home" = "/root" ] && owner="root"
    for hist in .bash_history .zsh_history .sh_history; do
        [ -f "$home/$hist" ] || continue
        add_artifact "$home/$hist" "home/$owner/$hist"
    done
    [ -f "$home/.ssh/authorized_keys" ] &&
        add_artifact "$home/.ssh/authorized_keys" "home/$owner/authorized_keys"
done

# ---------------------------------------------------------------- manifest

FINISHED="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
ART_JSON="$(printf '%s' "$ART_ENTRIES" | sed '$ s/,$//')"
SKIP_JSON="$(printf '%s' "$SKIP_ENTRIES" | sed '$ s/,$//')"
RUNNING_AS="$(id -un 2>/dev/null || echo unknown)"

cat > "$MANIFEST" <<EOF
{
  "tool": "tracehound-collect",
  "version": "$VERSION",
  "hostname": "$(json_escape "$HOST")",
  "collected_by": "$(json_escape "$RUNNING_AS")",
  "started_at": "$STARTED",
  "finished_at": "$FINISHED",
  "hash_algorithm": "sha256",
  "hash_tool": "$(json_escape "${HASH_TOOL:-none}")",
  "clock": {
    "host_utc": "$HOST_UTC",
    "reference_utc": $( [ -n "$REFERENCE" ] && printf '"%s"' "$(json_escape "$REFERENCE")" || printf 'null' ),
    "offset_seconds": $OFFSET,
    "note": "$(json_escape "$OFFSET_NOTE")"
  },
  "artifacts": [
$ART_JSON
  ],
  "skipped": [
$SKIP_JSON
  ]
}
EOF

log ""
log "collection complete: $OUT"
log "  host      : $HOST (as $RUNNING_AS)"
if [ "$OFFSET" = "null" ]; then
    log "  clock     : NOT measured — cross-host ordering will be hedged"
    log "              re-run with -r \"\$(date -u +%Y-%m-%dT%H:%M:%S)\" from a synced host"
else
    log "  clock     : offset ${OFFSET}s vs reference"
fi
log "  manifest  : $MANIFEST"
log ""
log "Analyse with:"
log "  tracehound scan $ARTIFACTS"
log "  tracehound case --manifest $MANIFEST"
