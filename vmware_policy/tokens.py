"""Bearer tokens for the network MCP transports (HLD §16 D-11).

``vmware-audit token create NAME`` prints a token once; the file
``$OPS_HOME/mcp-tokens`` keeps only ``name:sha256`` lines, owner-only. A server
reads the file again whenever it changes, so ``token revoke`` takes effect on the
next request without a restart. Tokens are never logged, never audited, and
never accepted anywhere but the ``Authorization`` header (the SDK's auth path).

This authenticates the client to this server only. It authorizes nothing at
vCenter: every caller of an endpoint acts with that server's account (D-12).
"""

from __future__ import annotations

import contextlib
import hashlib
import hmac
import os
import re
import secrets
import threading
from collections.abc import Iterator
from pathlib import Path

from vmware_policy.fsperms import check_secret_file
from vmware_policy.paths import ops_path

_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")


class TokenError(ValueError):
    """A token operation cannot be done; the message says what to change."""


def token_file() -> Path:
    """Where token hashes live: ``$OPS_HOME/mcp-tokens`` (default ``~/.vmware``)."""
    return ops_path("mcp-tokens")


def _hash(secret: str) -> str:
    return hashlib.sha256(secret.encode("utf-8")).hexdigest()


def _read(path: Path) -> dict[str, str]:
    if not path.exists():
        return {}
    check = check_secret_file(path)
    if check.verdict == "too_open":
        raise TokenError(
            f"{path} is readable by other users; it must be 0600 before it is used. {check.message}"
        )
    entries: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        name, _, digest = line.partition(":")
        if _NAME.match(name) and re.fullmatch(r"[0-9a-f]{64}", digest):
            entries[name] = digest
    return entries


def _write(path: Path, entries: dict[str, str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        fh.write("# name:sha256 — created by `vmware-audit token create`; secrets are not stored\n")
        for name in sorted(entries):
            fh.write(f"{name}:{entries[name]}\n")
    os.chmod(tmp, 0o600)
    os.replace(tmp, path)


@contextlib.contextmanager
def _exclusive(path: Path) -> Iterator[None]:
    """Serialize read-modify-write of the token file across processes (POSIX).

    Two concurrent `token create` runs would otherwise each read the file, add
    their entry and write it back, and one entry would be lost. On platforms
    without fcntl the commands run unlocked (they are interactive, one at a time).
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        import fcntl
    except ImportError:
        yield
        return
    fd = os.open(path.with_name(path.name + ".lock"), os.O_RDWR | os.O_CREAT, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        yield
    finally:
        fcntl.flock(fd, fcntl.LOCK_UN)
        os.close(fd)


def create_token(name: str, path: Path | None = None) -> str:
    """Create a token for ``name`` and return the secret.

    The secret is not stored and cannot be shown again.
    """
    if not _NAME.match(name):
        raise TokenError(
            f"Invalid token name {name!r}: use 1-64 letters, digits, '.', '_' or '-', "
            "starting with a letter or digit (it becomes the audit user 'token:<name>')."
        )
    path = path or token_file()
    with _exclusive(path):
        entries = _read(path)
        if name in entries:
            raise TokenError(
                f"A token named {name!r} already exists. Revoke it first "
                f"('vmware-audit token revoke {name}') or choose another name."
            )
        secret = secrets.token_urlsafe(32)  # 256 bits
        _write(path, {**entries, name: _hash(secret)})
    return secret


def revoke_token(name: str, path: Path | None = None) -> None:
    """Remove ``name``; running servers refuse it from their next request."""
    path = path or token_file()
    with _exclusive(path):
        entries = _read(path)
        if name not in entries:
            raise TokenError(
                f"There is no token named {name!r}. 'vmware-audit token list' shows the names."
            )
        _write(path, {k: v for k, v in entries.items() if k != name})


def list_tokens(path: Path | None = None) -> list[str]:
    """Token names, sorted. Hashes are not shown."""
    return sorted(_read(path or token_file()))


class TokenStore:
    """Answers "which name does this token belong to?", re-reading the file when it changes."""

    def __init__(self, path: Path | None = None) -> None:
        self._path = path or token_file()
        self._lock = threading.Lock()
        self._stamp: tuple[int, int, int] | None = None
        self._entries: dict[str, str] = {}

    @property
    def path(self) -> Path:
        return self._path

    def _current(self) -> dict[str, str]:
        try:
            st = self._path.stat()
            # os.replace gives a new inode, so a same-size rewrite within one
            # mtime tick (coarse filesystems, scripted rotation) is still seen.
            stamp = (st.st_ino, st.st_mtime_ns, st.st_size)
        except FileNotFoundError:
            stamp = None
        with self._lock:
            if stamp != self._stamp or stamp is None:
                # Replace the dict whole: a reader never sees a half-built set.
                self._entries = _read(self._path) if stamp is not None else {}
                self._stamp = stamp
            return self._entries

    def count(self) -> int:
        return len(self._current())

    def identify(self, secret: str) -> str | None:
        """The token's name, or None. Every entry is compared, in constant time."""
        if not secret:
            return None
        digest = _hash(secret)
        found = None
        for name, stored in self._current().items():
            if hmac.compare_digest(stored, digest):
                found = name
        return found


class FileTokenVerifier:
    """The SDK ``TokenVerifier`` for a :class:`TokenStore` (mcp is imported only when used)."""

    def __init__(self, store: TokenStore) -> None:
        self._store = store

    async def verify_token(self, token: str):  # -> AccessToken | None
        from mcp.server.auth.provider import AccessToken

        name = self._store.identify(token)
        if name is None:
            return None
        # The secret is not carried further: nothing downstream needs it.
        return AccessToken(token="[redacted]", client_id=name, scopes=[])
