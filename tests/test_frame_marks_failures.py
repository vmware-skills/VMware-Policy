"""A call @vmware_tool audits as failed is a failed MCP frame (``isError``).

Found 2026-10-18 with a live gate over the family (scripts/lib/
tool_failures_set_iserror.py): 272 of 349 tool calls in 13 of 14 skills
answered a failure with ``isError=False``. The audit row said ``error``
(``report_tool_failure`` or the returned ``{"error": ...}`` envelope) but the
frame did not, so a client that reads the frame — vmware-pilot ``--dispatch``,
any agent — took a failed write, or a failed undo during rollback, for success.
Only vmware-aiops marked its frames, with its own copy of this logic.

Fixed once here: the decorator's verdict marks the in-flight call, and
``serve.configure`` (which every skill's ``run_server`` calls, stdio included)
installs a call handler that turns a marked call into an error frame with the
content unchanged. Driven through a real in-memory MCP client.
"""

from __future__ import annotations

import asyncio
from typing import Any

import pytest

pytest.importorskip("mcp")

from mcp.server.fastmcp import FastMCP  # noqa: E402
from mcp.shared.memory import create_connected_server_and_client_session  # noqa: E402

from vmware_policy import serve  # noqa: E402
from vmware_policy.decorators import report_tool_failure, vmware_tool  # noqa: E402


@pytest.fixture
def ops_home(tmp_path, monkeypatch):
    import vmware_policy.audit as audit_mod

    monkeypatch.setenv("OPS_HOME", str(tmp_path / ".vmware"))
    monkeypatch.setattr(audit_mod, "_engine", None, raising=False)
    audit_mod.reset_engine()
    return tmp_path


def _server(configured: bool = True) -> FastMCP:
    mcp = FastMCP("probe")

    @mcp.tool()
    @vmware_tool(risk_level="low")
    def says_error() -> str:
        """Returns the family's string error shape and declares it."""
        report_tool_failure("boom")
        return "Error: boom. Run x."

    @mcp.tool()
    @vmware_tool(risk_level="low")
    def envelope() -> dict:
        """Returns the family's error envelope."""
        return {"error": "VM 'x' not found", "hint": "list VMs"}

    @mcp.tool()
    @vmware_tool(risk_level="low")
    def one_row() -> list:
        """A list tool's error shape."""
        return [{"error": "boom"}]

    @mcp.tool()
    @vmware_tool(risk_level="low")
    def fine() -> dict:
        """A success that mentions errors as data."""
        return {"error": None, "items": [{"error_count": 3}], "text": "Error: quoted"}

    @mcp.tool()
    @vmware_tool(risk_level="low")
    def preview(confirm: bool = False) -> dict:
        """A gated tool's preview is not a failure."""
        return {"action": "preview", "blast_radius": {}}

    @mcp.tool()
    @vmware_tool(risk_level="low")
    def recovers() -> str:
        """Calls a failing tool in-process, recovers, and succeeds."""
        inner = envelope_inner()
        return f"recovered from {inner['error']}"

    @vmware_tool(risk_level="low")
    def envelope_inner() -> dict:
        return {"error": "inner failure"}

    @mcp.tool()
    @vmware_tool(risk_level="low")
    def raises() -> str:
        """Raising was already an error frame; must stay one."""
        raise ValueError("bad argument: name")

    if configured:
        serve.configure(mcp, serve.ServeOptions(skill="probe"))
    return mcp


def _call(mcp: FastMCP, name: str, args: dict[str, Any] | None = None):
    async def run():
        async with create_connected_server_and_client_session(mcp._mcp_server) as client:
            return await client.call_tool(name, args or {})

    return asyncio.run(run())


def _text(result) -> str:
    return " ".join(getattr(c, "text", "") or "" for c in result.content)


@pytest.mark.unit
# "raises" is a control: FastMCP always made a raised exception an error frame.
@pytest.mark.parametrize("tool", ["says_error", "envelope", "one_row", "raises"])
def test_a_failed_call_is_an_error_frame(ops_home, tool):
    assert _call(_server(), tool).isError is True


@pytest.mark.unit
@pytest.mark.parametrize("tool", ["fine", "preview", "recovers"])
def test_a_successful_call_is_not_marked(ops_home, tool):
    assert _call(_server(), tool).isError is False


@pytest.mark.unit
def test_the_content_is_unchanged(ops_home):
    """Only isError changes: the authored message and structured payload survive."""
    plain = _call(_server(configured=False), "envelope")
    marked = _call(_server(), "envelope")
    assert plain.isError is False
    assert _text(marked) == _text(plain)
    assert marked.structuredContent == plain.structuredContent


@pytest.mark.unit
def test_stdio_is_covered(ops_home):
    """configure() returns early for stdio; the marking must happen before that."""
    mcp = _server(configured=False)
    serve.configure(mcp, serve.ServeOptions(skill="probe", transport="stdio"))
    assert _call(mcp, "says_error").isError is True


@pytest.mark.unit
def test_configure_twice_does_not_double_wrap(ops_home):
    mcp = _server()
    serve.configure(mcp, serve.ServeOptions(skill="probe"))
    assert _call(mcp, "fine").isError is False
    assert _call(mcp, "envelope").isError is True


@pytest.mark.unit
def test_concurrent_calls_do_not_mark_each_other(ops_home):
    mcp = _server()

    async def run():
        async with create_connected_server_and_client_session(mcp._mcp_server) as client:
            return await asyncio.gather(*(
                client.call_tool(name, {})
                for name in ("fine", "envelope", "fine", "says_error", "fine")
            ))

    results = asyncio.run(run())
    assert [r.isError for r in results] == [False, True, False, True, False]


@pytest.mark.unit
def test_a_subclass_that_already_marks_is_unaffected(ops_home):
    """vmware-aiops marks its own frames; installing ours on top must not break it."""
    from mcp import types as mcp_types

    class Marked(FastMCP):
        async def call_tool(self, name, arguments):
            converted = await super().call_tool(name, arguments)
            return mcp_types.CallToolResult(
                content=list(converted[0]), structuredContent=converted[1], isError=True
            ) if name == "envelope" else converted

    mcp = Marked("probe")

    @mcp.tool()
    @vmware_tool(risk_level="low")
    def envelope() -> dict:
        """x"""
        return {"error": "boom"}

    @mcp.tool()
    @vmware_tool(risk_level="low")
    def fine() -> dict:
        """x"""
        return {"ok": True}

    serve.configure(mcp, serve.ServeOptions(skill="probe"))
    assert _call(mcp, "envelope").isError is True
    assert _call(mcp, "fine").isError is False


# ── review of b7295ea: paths the first tests did not pin ─────────────────


def _rich_server(offloaded: bool, pooled: bool = False) -> FastMCP:
    """Async tools that await (so concurrent calls really interleave), a nested
    envelope the outer tool returns as its own, and the network path's
    worker-thread offload."""
    import anyio

    mcp = FastMCP("probe2")

    @mcp.tool()
    @vmware_tool(risk_level="low")
    async def slow_fail(delay: float = 0.05) -> dict:
        """Fails after yielding to the loop."""
        await anyio.sleep(delay)
        return {"error": "late failure"}

    @mcp.tool()
    @vmware_tool(risk_level="low")
    async def slow_ok(delay: float = 0.05) -> dict:
        """Succeeds after yielding to the loop."""
        await anyio.sleep(delay)
        return {"ok": True}

    @vmware_tool(risk_level="low")
    def inner() -> dict:
        return {"error": "inner failed"}

    @mcp.tool()
    @vmware_tool(risk_level="low")
    def passes_inner() -> dict:
        """Returns a nested tool's failure as its own result: a failed call."""
        return inner()

    @mcp.tool()
    @vmware_tool(risk_level="low")
    def sync_fail() -> str:
        """A sync tool the network path runs in a worker thread."""
        report_tool_failure("boom")
        return "Error: boom"

    @mcp.tool()
    @vmware_tool(risk_level="low")
    def sync_ok() -> str:
        """x"""
        return "fine"

    if offloaded:
        from vmware_policy.callgate import offload_sync_tools

        offload_sync_tools(mcp, pooled=pooled)
    serve.configure(mcp, serve.ServeOptions(skill="probe2"))
    return mcp


@pytest.mark.unit
def test_interleaved_async_calls_are_marked_per_call(ops_home):
    """A request-global flag would mark the successes too."""
    mcp = _rich_server(offloaded=False)

    async def run():
        async with create_connected_server_and_client_session(mcp._mcp_server) as client:
            return await asyncio.gather(
                client.call_tool("slow_ok", {"delay": 0.15}),
                client.call_tool("slow_fail", {"delay": 0.05}),
                client.call_tool("slow_ok", {"delay": 0.10}),
            )

    assert [r.isError for r in asyncio.run(run())] == [False, True, False]


@pytest.mark.unit
def test_an_outer_tool_returning_the_inner_failure_is_marked(ops_home):
    assert _call(_rich_server(offloaded=False), "passes_inner").isError is True


@pytest.mark.unit
@pytest.mark.parametrize("pooled", [False, True])
def test_the_network_paths_worker_threads_carry_the_mark(ops_home, pooled):
    """offload_sync_tools runs sync tools in a worker with a copied context."""
    mcp = _rich_server(offloaded=True, pooled=pooled)
    assert _call(mcp, "sync_fail").isError is True
    assert _call(mcp, "sync_ok").isError is False


@pytest.mark.unit
def test_an_unknown_result_shape_is_returned_untouched():
    """_error_frame must not crash on a shape FastMCP may return later (tasks)."""
    from vmware_policy.frame import _error_frame

    odd = {"taskId": "t-1"}
    assert _error_frame(odd) is odd
