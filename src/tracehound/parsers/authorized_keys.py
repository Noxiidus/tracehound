"""Parser for SSH ``authorized_keys`` files.

Each non-comment line authorises one public key to log in::

    [options] keytype base64blob [comment]

The optional ``options`` field comes *before* the key type and can contain quoted strings
with spaces (``command="..."``, ``from="..."``), so the line cannot simply be split on
whitespace. The parser instead scans for the first token that is a known key type and
treats everything before it as options.

Each key becomes a subject ``sshkey:<identity>`` where the identity is the key comment if
present, otherwise the SHA256 fingerprint — the same string ``ssh-keygen -lf`` prints, so
an analyst can match it against a key file directly. The owning account is inferred from
the path (``/home/<user>/.ssh/authorized_keys``, ``/root/.ssh/...``) when possible, since
an authorised key is a standing grant of access to *that* account.
"""

from __future__ import annotations

import base64
import hashlib
from collections.abc import Iterator
from pathlib import Path
from typing import ClassVar

from ..models import Fact
from .base import FactParser, ParseContext, register_fact

KEY_TYPES = frozenset(
    {
        "ssh-rsa",
        "ssh-dss",
        "ssh-ed25519",
        "ecdsa-sha2-nistp256",
        "ecdsa-sha2-nistp384",
        "ecdsa-sha2-nistp521",
        "sk-ssh-ed25519@openssh.com",
        "sk-ecdsa-sha2-nistp256@openssh.com",
        "ssh-rsa-cert-v01@openssh.com",
        "ssh-ed25519-cert-v01@openssh.com",
    }
)


def _fingerprint(blob: str) -> str | None:
    """Return the ``SHA256:...`` fingerprint of a base64 key blob, or None if unusable."""
    try:
        raw = base64.b64decode(blob, validate=True)
    except ValueError:  # binascii.Error is a ValueError subclass
        return None
    digest = hashlib.sha256(raw).digest()
    return "SHA256:" + base64.b64encode(digest).decode("ascii").rstrip("=")


def _account_from_path(path: Path) -> str | None:
    parts = [p for p in path.parts]
    for i, part in enumerate(parts):
        if part == ".ssh" and i >= 1:
            owner = parts[i - 1]
            return "root" if owner == "root" else owner
    if "root" in parts:
        return "root"
    return None


def _split_line(line: str) -> tuple[str, str, str, str] | None:
    """Return (options, keytype, blob, comment) or None if no key type is found."""
    tokens = line.split()
    for index, token in enumerate(tokens):
        if token in KEY_TYPES:
            if index + 1 >= len(tokens):
                return None
            options = line.split(token, 1)[0].strip()
            blob = tokens[index + 1]
            comment = " ".join(tokens[index + 2 :]).strip()
            return options, token, blob, comment
    return None


@register_fact
class AuthorizedKeysParser(FactParser):
    name = "authorized_keys"
    description = "SSH authorised public keys (authorized_keys)"
    priority: ClassVar[int] = 20

    def sniff(self, path: Path) -> bool:
        named = path.name in {"authorized_keys", "authorized_keys2"}
        try:
            with path.open("r", encoding="utf-8", errors="replace") as fh:
                for _ in range(40):
                    line = fh.readline()
                    if not line:
                        break
                    stripped = line.strip()
                    if not stripped or stripped.startswith("#"):
                        continue
                    if _split_line(stripped) is not None:
                        return True
                    # A named file with a garbage first line is still not proof; keep
                    # looking. An unnamed file gets no benefit of the doubt.
                    if not named:
                        return False
        except (OSError, UnicodeDecodeError):
            return False
        return False

    def parse(self, path: Path, ctx: ParseContext) -> Iterator[Fact]:
        account = _account_from_path(path)
        with path.open("r", encoding="utf-8", errors="replace") as fh:
            for raw_line in fh:
                line = raw_line.strip()
                if not line or line.startswith("#"):
                    continue
                parsed = _split_line(line)
                if parsed is None:
                    continue

                options, keytype, blob, comment = parsed
                fingerprint = _fingerprint(blob)
                identity = comment or fingerprint or blob[:20]
                subject = f"sshkey:{identity}"
                meta: dict[str, object] = {"raw": line}
                if account:
                    meta["account"] = account
                if fingerprint:
                    meta["fingerprint"] = fingerprint

                yield Fact(
                    subject=subject,
                    attribute="type",
                    value=keytype,
                    source=self.name,
                    metadata=meta,
                )
                yield Fact(
                    subject=subject,
                    attribute="comment",
                    value=comment,
                    source=self.name,
                    metadata=meta,
                )
                yield Fact(
                    subject=subject,
                    attribute="options",
                    value=options,
                    source=self.name,
                    metadata=meta,
                )
                if fingerprint:
                    yield Fact(
                        subject=subject,
                        attribute="fingerprint",
                        value=fingerprint,
                        source=self.name,
                        metadata=meta,
                    )
                if account:
                    yield Fact(
                        subject=subject,
                        attribute="account",
                        value=account,
                        source=self.name,
                        metadata=meta,
                    )
