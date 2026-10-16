"""Keep tools away from this server's own control files (HLD §18, Order of work step 0).

Some tools read or write a path on the server host: a guest-file download
target, an OVA or deployment spec to read, a kubeconfig to write, a bundle
manifest. Over a network transport the caller names that path, so without a
check any token holder could overwrite ``$OPS_HOME/mcp-tokens`` (and give
themselves a token) or ``rules.yaml`` (and drop every deny rule), read a skill's
``.env`` passwords, or upload the TLS private key into a VM. A prompt-injected
agent on stdio could do the same.

``check_host_path`` refuses any path that resolves — ``~``, ``..`` and symlinks
included — into a protected location:

* ``$OPS_HOME`` (default ``~/.vmware``): tokens, rules, audit log;
* every ``~/.vmware-*`` directory: each skill's config and ``.env``;
* the directory of any ``VMWARE_*_CONFIG`` file named in the environment;
* files a running server registered with :func:`register_protected` (the token
  file and TLS certificate and key passed to ``<cli> mcp``).

Device and process paths (``/dev``, ``/proc``) are always refused. Over a
network transport host files are off unless the operator sets
``VMWARE_MCP_FILE_ROOT``, and then only paths inside it are allowed.

Each skill calls it where it opens a caller-supplied path, so the MCP tools, the
CLI, plans and workflows are all covered; ``@vmware_tool`` also checks the
family's host-path parameter names before a tool runs.
"""

from __future__ import annotations

import os
import re
import sys
from pathlib import Path

#: Tool parameters that name a file on the server host (not a datastore, guest,
#: NSX or API path). ``@vmware_tool`` checks these before the tool runs; the
#: family gate keeps every registered parameter classified.
HOST_PATH_PARAMS = frozenset(
    {"local_path", "ova_path", "spec_path", "manifest_path", "output_path"}
)

_CONFIG_ENV = re.compile(r"^VMWARE_[A-Z0-9_]+_CONFIG$")
_registered: set[str] = set()
_network_serving = False


class HostPathRefusedError(ValueError):
    """A tool was asked to read or write one of this server's control files."""


def register_protected(path: str | os.PathLike[str]) -> None:
    """Protect one more file or directory for the life of this process."""
    _registered.add(os.path.realpath(os.path.expanduser(os.fspath(path))))


def reset_registered() -> None:
    """For tests."""
    _registered.clear()


def set_network_serving(on: bool) -> None:
    """Mark this process as serving MCP over a network transport (set by ``serve``).

    Process-wide, not per call: a thread a tool starts does not inherit the
    caller's context, and the network rule must not fail open there.
    """
    global _network_serving
    _network_serving = on


def _ops_home() -> str:
    return os.path.expanduser(os.environ.get("OPS_HOME") or "~/.vmware")


def protected_roots() -> list[str]:
    """Real paths of every protected location, as of now."""
    roots = [_ops_home()]
    home = Path(os.path.expanduser("~"))
    try:
        roots += [str(p) for p in home.glob(".vmware-*") if p.is_dir()]
    except OSError:
        pass
    for name, value in os.environ.items():
        if _CONFIG_ENV.match(name) and value.strip():
            roots.append(str(Path(os.path.expanduser(value)).parent))
    return sorted({os.path.realpath(r) for r in roots} | _registered)


_DEVICE_ROOTS = ("/dev", "/proc")
FILE_ROOT_ENV = "VMWARE_MCP_FILE_ROOT"


def _fold(path: str) -> str:
    return os.path.normcase(path).casefold()


def _inside(path: str, root: str) -> bool:
    """``path`` is ``root`` or below it — by name ignoring case, or by file identity.

    The default macOS (and Windows) filesystem ignores case, so ``~/.VMWARE``
    opens ``~/.vmware``: names are compared case-folded. Identity covers what
    names cannot (another spelling of the same directory): any existing
    ancestor of ``path`` that is the same file as ``root`` puts it inside.
    """
    try:
        if os.path.commonpath([_fold(path), _fold(root)]) == _fold(root):
            return True
    except ValueError:  # different drives on Windows
        return False
    if not os.path.exists(root):
        return False
    current = path
    while True:
        if os.path.exists(current):
            try:
                if os.path.samefile(current, root):
                    return True
            except OSError:
                pass
        parent = os.path.dirname(current)
        if parent == current:
            return False
        current = parent


def _network_caller() -> bool:
    if _network_serving:
        return True
    from vmware_policy import caller

    return caller.current_caller() is not None


def _inside_exact(path: str, root: str) -> bool:
    """Like :func:`_inside` but names compared exactly: used for the allow-list,
    where folding case would let ``FILES`` (a sibling on a case-sensitive
    filesystem) through. Identity still catches other spellings of the root."""
    try:
        if os.path.commonpath([path, root]) == root:
            return True
    except ValueError:
        return False
    if not os.path.exists(root):
        return False
    current = path
    while True:
        if os.path.exists(current):
            try:
                if os.path.samefile(current, root):
                    return True
            except OSError:
                pass
        parent = os.path.dirname(current)
        if parent == current:
            return False
        current = parent


def file_root_problem(value: str) -> str | None:
    """Why ``VMWARE_MCP_FILE_ROOT=value`` would not restrict anything, or None."""
    expanded = os.path.expanduser(value)
    if not os.path.isabs(expanded):
        return f"{FILE_ROOT_ENV} must be an absolute path (got {value!r})."
    root = os.path.realpath(expanded)
    home = os.path.realpath(os.path.expanduser("~"))
    if root == os.path.dirname(root) or _inside(home, root):
        return (
            f"{FILE_ROOT_ENV}={value!r} contains the home directory or is the filesystem root, so "
            "it restricts nothing. Point it at a dedicated directory for files tools may use."
        )
    code = os.path.realpath(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    for inside in (os.path.realpath(sys.prefix), code):
        if _inside(inside, root):
            return (
                f"{FILE_ROOT_ENV}={value!r} contains this server's own installed code ({inside}), "
                "which tools could then overwrite. Point it at a dedicated directory."
            )
    return None


def check_host_path(path: str | os.PathLike[str] | None) -> None:
    """Raise :class:`HostPathRefusedError` unless a tool may use ``path`` on this host.

    Always refused: this server's control files (see the module docstring) and
    device / process paths (``/dev/fd/N`` reaches the server's own open files).
    Over a network transport host files are off unless the operator sets
    ``VMWARE_MCP_FILE_ROOT``, and then only paths inside it are allowed: a token
    holder must not reach ``~/.ssh``, the installed packages or other secrets.
    """
    if isinstance(path, os.PathLike):
        path = os.fspath(path)
    if not isinstance(path, str) or not path.strip():
        return
    real = os.path.realpath(os.path.expanduser(path))
    for root in _DEVICE_ROOTS:
        if _inside(real, root):
            raise HostPathRefusedError(
                f"Device and process paths ({root}) are never read or written by tools. "
                f"Refused: {path}"
            )
    for root in protected_roots():
        if _inside(real, root):
            raise HostPathRefusedError(
                "Choose a path outside the directories that hold this server's configuration, "
                f"tokens and audit log ({root}); tools may not read or write there. "
                f"Refused: {path}"
            )
    if not _network_caller():
        return
    allowed = os.environ.get(FILE_ROOT_ENV, "").strip()
    if not allowed:
        raise HostPathRefusedError(
            "Over the network, tools may not read or write files on this server unless the "
            f"operator sets {FILE_ROOT_ENV} to a directory for them. Refused: {path}"
        )
    problem = file_root_problem(allowed)
    if problem:
        raise HostPathRefusedError(f"{problem} Refused: {path}")
    root = os.path.realpath(os.path.expanduser(allowed))
    if not _inside_exact(real, root):
        raise HostPathRefusedError(
            f"Over the network, tools read and write only inside {FILE_ROOT_ENV} ({root}). "
            f"Refused: {path}"
        )
