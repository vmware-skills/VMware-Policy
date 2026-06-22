"""Home-directory resolution for the governance harness.

``ops_home()`` parameterizes where harness state (audit / policy / budget / undo)
is stored, via the ``OPS_HOME`` environment variable.

Back-compat: when ``OPS_HOME`` is unset the default is ``~/.vmware``, so every
existing install keeps its current paths with no migration.
"""

from __future__ import annotations

import os
from pathlib import Path

_DEFAULT_HOME = "~/.vmware"


def ops_home() -> Path:
    """Return the harness state directory, honoring ``OPS_HOME`` (default ~/.vmware)."""
    return Path(os.environ.get("OPS_HOME") or _DEFAULT_HOME).expanduser()


def ops_path(*parts: str) -> Path:
    """Resolve a file under the harness home, e.g. ``ops_path('audit.db')``."""
    return ops_home().joinpath(*parts)
