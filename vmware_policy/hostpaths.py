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

Each skill calls it where it opens a caller-supplied path, so the MCP tools, the
CLI, plans and workflows are all covered; ``@vmware_tool`` also checks the
family's host-path parameter names before a tool runs.
"""

from __future__ import annotations

import os
import re
from pathlib import Path

#: Tool parameters that name a file on the server host (not a datastore, guest,
#: NSX or API path). ``@vmware_tool`` checks these before the tool runs; the
#: family gate keeps every registered parameter classified.
HOST_PATH_PARAMS = frozenset(
    {"local_path", "ova_path", "spec_path", "manifest_path", "output_path"}
)

_CONFIG_ENV = re.compile(r"^VMWARE_[A-Z0-9_]+_CONFIG$")
_registered: set[str] = set()


class HostPathRefusedError(ValueError):
    """A tool was asked to read or write one of this server's control files."""


def register_protected(path: str | os.PathLike[str]) -> None:
    """Protect one more file or directory for the life of this process."""
    _registered.add(os.path.realpath(os.path.expanduser(os.fspath(path))))


def reset_registered() -> None:
    """For tests."""
    _registered.clear()


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


def _inside(path: str, root: str) -> bool:
    try:
        return os.path.commonpath([path, root]) == root
    except ValueError:  # different drives on Windows
        return False


def check_host_path(path: str | os.PathLike[str] | None) -> None:
    """Raise :class:`HostPathRefusedError` if ``path`` resolves into a protected location."""
    if isinstance(path, os.PathLike):
        path = os.fspath(path)
    if not isinstance(path, str) or not path.strip():
        return
    real = os.path.realpath(os.path.expanduser(path))
    for root in protected_roots():
        if _inside(real, root):
            raise HostPathRefusedError(
                "Choose a path outside the directories that hold this server's configuration, "
                f"tokens and audit log ({root}); tools may not read or write there. "
                f"Refused: {path}"
            )
