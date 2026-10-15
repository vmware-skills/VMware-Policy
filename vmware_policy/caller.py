"""Who is calling, when it is not the process's own user (HLD §16 D-12).

Over an authenticated network transport the SDK stores the verified bearer
token in a context variable for the request; that is the caller. The audit
``user`` becomes ``token:<name>``. stdio and the CLI have no such token, and
the process's OS user remains the answer there.

The SDK is imported only when present: vmware-policy does not depend on it.
"""

from __future__ import annotations

import getpass
import re


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


_UNSAFE = re.compile(r"[^A-Za-z0-9._:-]")
_TRACE_ID = re.compile(r"^[0-9a-f]{32}$")
_MAX_ID = 128


def current_correlation_id() -> str:
    """The calling platform's trace id for this request, or ``""``.

    W3C ``traceparent`` first (its trace-id), then ``X-Request-ID``, then
    ``X-Correlation-ID``. Only network requests carry headers; stdio and the CLI
    return ``""``. The value is reduced to ``[A-Za-z0-9._:-]`` and 128
    characters: it is caller-supplied text going into the audit log.
    """
    try:
        from mcp.server.lowlevel.server import request_ctx
    except ImportError:
        return ""
    try:
        ctx = request_ctx.get()
    except LookupError:
        return ""
    headers = getattr(getattr(ctx, "request", None), "headers", None)
    if not headers:
        return ""
    parent = headers.get("traceparent") or ""
    parts = parent.strip().split("-")
    if len(parts) >= 4 and _TRACE_ID.match(parts[1]) and parts[1] != "0" * 32:
        return parts[1]
    for name in ("x-request-id", "x-correlation-id"):
        value = _UNSAFE.sub("", headers.get(name) or "")[:_MAX_ID]
        if value:
            return value
    return ""
