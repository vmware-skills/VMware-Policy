"""Bearer tokens for the network MCP transports (HLD §16 D-11, §18 D-20/D-24).

``vmware-audit token create NAME`` prints a token once; the file
``$OPS_HOME/mcp-tokens`` keeps only ``name:sha256`` lines, owner-only. A server
reads the file again whenever it changes, so ``token revoke`` takes effect on the
next request without a restart. Tokens are never logged, never audited, and
never accepted anywhere but the ``Authorization`` header (the SDK's auth path).

Roles (§18) keep their tokens in a **separate** file, ``<token file>.v2``, with
``name:sha256:role`` lines. An older vmware-policy (another skill's venv on the
same host) neither reads nor rewrites it — its ``token create`` rewrites the
legacy file from what it parsed, which would delete role lines kept there.
``vmware-audit roles enable`` moves every legacy token into the v2 file and leaves
the legacy file with no entries, so older servers then refuse every request
(fail closed) and newer ones read only the v2 file.

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
from collections.abc import Iterator, Mapping
from dataclasses import dataclass
from pathlib import Path

from vmware_policy.fsperms import check_secret_file
from vmware_policy.paths import ops_path

_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
_DIGEST = re.compile(r"[0-9a-f]{64}")


class TokenError(ValueError):
    """A token operation cannot be done; the message says what to change."""


def token_file() -> Path:
    """Where token hashes live: ``$OPS_HOME/mcp-tokens`` (default ``~/.vmware``)."""
    return ops_path("mcp-tokens")


def v2_file(path: Path | None = None) -> Path:
    """The role-token file next to ``path``: ``<path>.v2``."""
    path = path or token_file()
    return path.with_name(path.name + ".v2")


def roles_enabled(path: Path | None = None) -> bool:
    """Opted in (D-24): the v2 file exists."""
    return v2_file(path).exists()


def _hash(secret: str) -> str:
    return hashlib.sha256(secret.encode("utf-8")).hexdigest()


def _check_mode(path: Path) -> None:
    check = check_secret_file(path)
    if check.verdict == "too_open":
        raise TokenError(
            f"{path} is readable by other users; it must be 0600 before it is used. {check.message}"
        )


def _lines(path: Path) -> Iterator[list[str]]:
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            yield line.split(":")


def _read(path: Path) -> dict[str, str]:
    """Legacy file: ``name -> sha256``. Lines in any other shape are ignored."""
    if not path.exists():
        return {}
    _check_mode(path)
    entries: dict[str, str] = {}
    for parts in _lines(path):
        if len(parts) == 2 and _NAME.match(parts[0]) and _DIGEST.fullmatch(parts[1]):
            entries[parts[0]] = parts[1]
    return entries


def _read_v2(path: Path) -> dict[str, tuple[str, str]]:
    """v2 file: ``name -> (sha256, role)``."""
    if not path.exists():
        return {}
    _check_mode(path)
    entries: dict[str, tuple[str, str]] = {}
    for parts in _lines(path):
        if (
            len(parts) == 3
            and _NAME.match(parts[0])
            and _DIGEST.fullmatch(parts[1])
            and _NAME.match(parts[2])
        ):
            entries[parts[0]] = (parts[1], parts[2])
    return entries


def _atomic_write(path: Path, header: str, lines: list[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        fh.write(header)
        for line in lines:
            fh.write(line + "\n")
    os.chmod(tmp, 0o600)
    os.replace(tmp, path)


def _write(path: Path, entries: Mapping[str, str]) -> None:
    _atomic_write(
        path,
        "# name:sha256 — created by `vmware-audit token create`; secrets are not stored\n",
        [f"{name}:{entries[name]}" for name in sorted(entries)],
    )


def _write_v2(path: Path, entries: Mapping[str, tuple[str, str]]) -> None:
    _atomic_write(
        path,
        "# name:sha256:role — role tokens (HLD §18); "
        "`vmware-audit token create NAME --role ROLE`\n",
        [f"{name}:{digest}:{role}" for name, (digest, role) in sorted(entries.items())],
    )


@contextlib.contextmanager
def _exclusive(path: Path) -> Iterator[None]:
    """Serialize read-modify-write of the token files across processes (POSIX).

    Two concurrent `token create` runs would otherwise each read the file, add
    their entry and write it back, and one entry would be lost. On platforms
    without fcntl the commands run unlocked (they are interactive, one at a time).
    The same lock covers the legacy and the v2 file.
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


def _check_name(name: str, what: str = "token") -> None:
    if not _NAME.match(name):
        raise TokenError(
            f"Invalid {what} name {name!r}: use 1-64 letters, digits, '.', '_' or '-', "
            "starting with a letter or digit"
            + (" (it becomes the audit user 'token:<name>')." if what == "token" else ".")
        )


def create_token(name: str, path: Path | None = None, *, role: str | None = None) -> str:
    """Create a token for ``name`` and return the secret.

    The secret is not stored and cannot be shown again. With ``role`` the token is
    written to the v2 file (which opts the deployment in to roles); without it,
    to the legacy file — refused once roles are enabled.
    """
    _check_name(name)
    if role is not None:
        _check_name(role, "role")
    path = path or token_file()
    with _exclusive(path):
        legacy, v2 = _read(path), _read_v2(v2_file(path))
        if name in legacy or name in v2:
            raise TokenError(
                f"A token named {name!r} already exists. Revoke it first "
                f"('vmware-audit token revoke {name}') or choose another name."
            )
        secret = secrets.token_urlsafe(32)  # 256 bits
        if role is not None:
            _write_v2(v2_file(path), {**v2, name: (_hash(secret), role)})
        elif v2_file(path).exists():
            raise TokenError(
                "Roles are enabled on this host, so every token needs one: "
                f"'vmware-audit token create {name} --role ROLE' (built in: reader, admin)."
            )
        else:
            _write(path, {**legacy, name: _hash(secret)})
    return secret


def revoke_token(name: str, path: Path | None = None) -> None:
    """Remove ``name`` from whichever file holds it; servers refuse it from the next request."""
    path = path or token_file()
    with _exclusive(path):
        legacy, v2 = _read(path), _read_v2(v2_file(path))
        if name not in legacy and name not in v2:
            raise TokenError(
                f"There is no token named {name!r}. 'vmware-audit token list' shows the names."
            )
        if name in legacy:
            _write(path, {k: v for k, v in legacy.items() if k != name})
        if name in v2:
            _write_v2(v2_file(path), {k: v for k, v in v2.items() if k != name})


def set_role(name: str, role: str, path: Path | None = None) -> str:
    """Give the role token ``name`` a new role; returns the old one."""
    _check_name(role, "role")
    path = path or token_file()
    with _exclusive(path):
        v2 = _read_v2(v2_file(path))
        if name not in v2:
            raise TokenError(
                f"There is no role token named {name!r}. Legacy tokens get a role through "
                "'vmware-audit roles enable'; 'vmware-audit token list' shows each token's file."
            )
        digest, old = v2[name]
        _write_v2(v2_file(path), {**v2, name: (digest, role)})
    return old


def enable_roles(
    path: Path | None = None, assign: Mapping[str, str] | None = None
) -> dict[str, str]:
    """Opt in (D-24): move every legacy token into the v2 file and empty the legacy file.

    Each moved token gets ``assign[name]`` or ``admin`` (what it could do before).
    Returns ``{name: role}`` for the moved tokens. Idempotent.
    """
    assign = dict(assign or {})
    for role in assign.values():
        _check_name(role, "role")
    path = path or token_file()
    with _exclusive(path):
        legacy, v2 = _read(path), _read_v2(v2_file(path))
        clash = sorted(set(legacy) & set(v2))
        if clash:
            raise TokenError(
                f"Tokens {', '.join(clash)} exist in both {path} and {v2_file(path)}; "
                "revoke one copy first."
            )
        unknown = sorted(set(assign) - set(legacy))
        if unknown:
            raise TokenError(f"No legacy token named {', '.join(unknown)} to assign a role to.")
        moved = {name: assign.get(name, "admin") for name in legacy}
        merged = {**v2, **{name: (legacy[name], role) for name, role in moved.items()}}
        _write_v2(v2_file(path), merged)  # written first: never a moment with neither file
        _write(path, {})
    return moved


@dataclass(frozen=True)
class TokenInfo:
    name: str
    role: str  # "admin" for legacy tokens before opt-in
    file: Path
    usable: bool
    note: str = ""


def list_token_info(path: Path | None = None) -> list[TokenInfo]:
    """Every token with its role and file; hashes are never returned."""
    path = path or token_file()
    legacy, v2 = _read(path), _read_v2(v2_file(path))
    enabled = v2_file(path).exists()
    out = [TokenInfo(n, r, v2_file(path), n not in legacy) for n, (_, r) in v2.items()]
    for name in legacy:
        if enabled:
            note = "legacy token after roles were enabled: refused; recreate it with --role"
        else:
            note = ""
        out.append(TokenInfo(name, "admin", path, not enabled and name not in v2, note))
    return sorted(out, key=lambda t: t.name)


def list_tokens(path: Path | None = None) -> list[str]:
    """Token names, sorted. Hashes are not shown."""
    return sorted({t.name for t in list_token_info(path)})


class TokenStore:
    """Answers "which name does this token belong to?", re-reading the files when they change.

    Before opt-in it reads the legacy file (every token acts as ``admin``). Once the
    v2 file exists only v2 tokens are accepted: a legacy line written later — by an
    older ``token create`` — is refused, and a name present in both files is refused.
    """

    def __init__(self, path: Path | None = None) -> None:
        self._path = path or token_file()
        self._v2 = v2_file(self._path)
        self._lock = threading.Lock()
        self._stamp: tuple[object, object] | None = None
        self._entries: dict[str, tuple[str, str]] = {}

    @property
    def path(self) -> Path:
        return self._path

    @property
    def v2_path(self) -> Path:
        return self._v2

    @staticmethod
    def _stat(path: Path) -> tuple[int, int, int] | None:
        try:
            st = path.stat()
        except FileNotFoundError:
            return None
        # os.replace gives a new inode, so a same-size rewrite within one
        # mtime tick (coarse filesystems, scripted rotation) is still seen.
        return (st.st_ino, st.st_mtime_ns, st.st_size)

    def _current(self) -> dict[str, tuple[str, str]]:
        stamp = (self._stat(self._path), self._stat(self._v2))
        with self._lock:
            if stamp != self._stamp or stamp == (None, None):
                legacy = _read(self._path) if stamp[0] is not None else {}
                if stamp[1] is not None:
                    v2 = _read_v2(self._v2)
                    entries = {n: e for n, e in v2.items() if n not in legacy}
                else:
                    entries = {n: (d, "admin") for n, d in legacy.items()}
                # Replace the dict whole: a reader never sees a half-built set.
                self._entries = entries
                self._stamp = stamp
            return self._entries

    def roles_enabled(self) -> bool:
        return self._v2.exists()

    def count(self) -> int:
        return len(self._current())

    def identify(self, secret: str) -> str | None:
        """The token's name, or None. Every entry is compared, in constant time."""
        if not secret:
            return None
        digest = _hash(secret)
        found = None
        for name, (stored, _role) in self._current().items():
            if hmac.compare_digest(stored, digest):
                found = name
        return found

    def role_of(self, name: str) -> str | None:
        """The role name recorded for an accepted token, read now (never cached in the session)."""
        entry = self._current().get(name)
        return entry[1] if entry else None


class FileTokenVerifier:
    """The SDK ``TokenVerifier`` for a :class:`TokenStore` (mcp is imported only when used)."""

    def __init__(self, store: TokenStore) -> None:
        self._store = store

    async def verify_token(self, token: str):  # -> AccessToken | None
        from mcp.server.auth.provider import AccessToken

        name = self._store.identify(token)
        if name is None:
            return None
        # The secret is not carried further: nothing downstream needs it. Neither
        # is the role: it is looked up by name at every check (review R2-Mb).
        return AccessToken(token="[redacted]", client_id=name, scopes=[])
