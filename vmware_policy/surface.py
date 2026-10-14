"""Which entry point a call came in through — the ``surface`` audit column (HLD §16 D-14).

The same tool name is reachable from MCP and from the CLI (I-9), so without this
an audit row could not say which door was used. Every writer names its surface:
the CLI guard passes ``cli`` explicitly, the AIops daemon passes ``daemon``, and
MCP tools take the process surface, which :func:`set_process_surface` sets when
a server starts on a network transport (stdio when nothing set it).
"""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from contextvars import ContextVar

#: The closed set. A value outside it is a bug in the caller, refused rather
#: than filed: an audit column that accepts anything stops meaning anything.
SURFACES = frozenset({"mcp-stdio", "mcp-https", "mcp-http-loopback", "cli", "daemon"})

_process_surface = "mcp-stdio"
_override: ContextVar[str | None] = ContextVar("vmware_policy_surface", default=None)


def validate(value: str) -> str:
    if value not in SURFACES:
        raise ValueError(f"unknown audit surface {value!r}; expected one of {sorted(SURFACES)}")
    return value


def set_process_surface(value: str) -> None:
    """Set the surface for every MCP call this process serves (called by ``serve()``)."""
    global _process_surface
    _process_surface = validate(value)


def current_surface() -> str:
    """The surface for a call that did not name one."""
    return _override.get() or _process_surface


@contextmanager
def use_surface(value: str) -> Iterator[None]:
    """Name the surface for calls made inside this block (this thread / task only)."""
    token = _override.set(validate(value))
    try:
        yield
    finally:
        _override.reset(token)
