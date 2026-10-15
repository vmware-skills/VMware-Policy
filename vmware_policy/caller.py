"""Who is calling, when it is not the process's own user (HLD §16 D-12).

Over an authenticated network transport the SDK stores the verified bearer
token in a context variable for the request; that is the caller. The audit
``user`` becomes ``token:<name>``. stdio and the CLI have no such token, and
the process's OS user remains the answer there.

The SDK is imported only when present: vmware-policy does not depend on it.
"""

from __future__ import annotations

import getpass


def current_caller() -> str | None:
    """``token:<name>`` for an authenticated network request, else None."""
    try:
        from mcp.server.auth.middleware.auth_context import get_access_token
    except ImportError:
        return None
    access = get_access_token()
    client = getattr(access, "client_id", None) if access is not None else None
    return f"token:{client}" if client else None


def audit_user() -> str:
    """The value for the audit ``user`` column: the network caller, else the OS user."""
    caller = current_caller()
    if caller:
        return caller
    try:
        return getpass.getuser()
    except Exception:
        return "unknown"
