"""A call ``@vmware_tool`` audits as failed is a failed MCP frame (``isError``).

Found 2026-10-18: 13 of 14 family skills answered a failure with
``isError=False``. The audit row said ``error`` — ``report_tool_failure``, or
the returned ``{"error": ...}`` envelope — but the protocol frame did not, so a
client reading the frame (vmware-pilot ``--dispatch``, any agent) took a failed
write, or a failed undo during rollback, for a success. Only vmware-aiops marked
its frames, with its own copy of the logic.

Now the decorator's own verdict is the source: when the outermost
``@vmware_tool`` call of an MCP request ends with status ``error``, it marks the
request (:func:`mark_failed`), and :func:`install` — run by
``serve.configure`` for every transport — re-wraps that request's result with
``isError=True``. Authored content and structured business fields survive;
``structuredContent.vmware_error`` adds one common error/hint view. SDK
ToolError failures retain the SDK text and receive the same view.

Prose is not read: a string is a failure only if the tool declared it with
``report_tool_failure`` — the same rule the audit row follows.
"""

from __future__ import annotations

import contextvars
import logging
from typing import Any

_log = logging.getLogger("vmware-policy.frame")

#: One list per MCP request, set by the installed handler. The decorator of the
#: outermost tool call appends to it; nested in-process tool calls see ``None``
#: (the decorator rebinds it), so an inner failure the outer tool recovered from
#: does not mark the request. A list rather than a value: the mark is written
#: inside the call (possibly in a worker thread with a copied context) and read
#: after it returns, and mutating a shared object survives both.
_request_sink: contextvars.ContextVar[list[bool] | None] = contextvars.ContextVar(
    "vmware_policy_request_failed", default=None
)

def claim() -> tuple[list[bool] | None, contextvars.Token]:
    """For the decorator: take the request's sink and hide it from nested calls."""
    sink = _request_sink.get()
    return sink, _request_sink.set(None)


def release(token: contextvars.Token) -> None:
    _request_sink.reset(token)


def mark_failed(sink: list[bool] | None) -> None:
    if sink is not None:
        sink.append(True)


def _error_frame(converted: Any) -> Any:
    from mcp import types as mcp_types

    from vmware_policy.response_contract import with_error_view

    if isinstance(converted, mcp_types.CallToolResult):
        return converted.model_copy(update={
            "isError": True,
            "structuredContent": with_error_view(
                list(converted.content), converted.structuredContent,
            ),
        })
    if isinstance(converted, tuple) and len(converted) == 2:
        unstructured, structured = converted
    elif isinstance(converted, list):
        unstructured, structured = converted, None
    else:
        # A shape FastMCP 1.30 does not return (a task handle, say): leave it as
        # it is rather than guess how to mark it. The audit row still says error.
        return converted
    blocks = list(unstructured)
    return mcp_types.CallToolResult(
        content=blocks,
        structuredContent=with_error_view(blocks, structured),
        isError=True,
    )


def install(server: Any) -> None:
    """Register a ``tools/call`` handler that marks failed calls.

    Safe to call twice: registering replaces the handler, and the new one wraps
    FastMCP's own ``call_tool`` (a bound method), never the previous handler.
    """
    lowlevel = getattr(server, "_mcp_server", None)
    if lowlevel is None or not hasattr(server, "call_tool"):
        # Not a FastMCP server (or an SDK that moved its internals): say so —
        # failed calls on it will not be marked isError.
        _log.warning("vmware-policy: %s has no FastMCP lowlevel server; failed tool calls "
                     "will not be marked isError", type(server).__name__)
        return
    call = server.call_tool

    async def call_tool(name: str, arguments: dict[str, Any]) -> Any:
        from mcp import types as mcp_types
        from mcp.server.fastmcp.exceptions import ToolError

        sink: list[bool] = []
        token = _request_sink.set(sink)
        try:
            try:
                converted = await call(name, arguments)
            except ToolError as exc:
                # The SDK would return this same ToolError text as an error
                # frame outside this handler. Keep it and add the shared view.
                converted = mcp_types.CallToolResult(
                    content=[mcp_types.TextContent(type="text", text=str(exc))], isError=True,
                )
        finally:
            _request_sink.reset(token)
        failed = sink or (isinstance(converted, mcp_types.CallToolResult) and converted.isError)
        return _error_frame(converted) if failed else converted

    # FastMCP registers its handler once, in __init__; registering again replaces
    # it. validate_input=False is what FastMCP itself passes.
    lowlevel.call_tool(validate_input=False)(call_tool)
