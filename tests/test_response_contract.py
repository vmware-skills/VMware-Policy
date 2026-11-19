"""Error projection preserves the legacy payload and never classifies success."""

import asyncio
import copy

import pytest

pytest.importorskip("mcp")
from mcp import types  # noqa: E402
from mcp.server.fastmcp import FastMCP  # noqa: E402
from mcp.shared.memory import create_connected_server_and_client_session  # noqa: E402

from vmware_policy.frame import _error_frame, install  # noqa: E402
from vmware_policy.response_contract import error_view  # noqa: E402


def text(s):
    return types.TextContent(type="text", text=s)


@pytest.mark.parametrize("body", [
    {"error": "missing", "hint": "list objects", "blast_radius": {"count": 0}},
    {"result": [{"error": "missing", "hint": "list objects"}]},
])
def test_legacy_structured_values_and_text_survive(body):
    original = copy.deepcopy(body)
    content = [text("authored legacy text")]
    result = _error_frame((content, body))
    assert result.isError
    assert result.content == content
    assert body == original
    for key, value in body.items():
        assert result.structuredContent[key] == value
    assert result.structuredContent["vmware_error"] == {
        "error": "missing", "hint": "list objects",
    }


@pytest.mark.parametrize("message,expected", [
    ('[{"error":"missing","hint":"list objects"}]',
     {"error": "missing", "hint": "list objects"}),
    ('{"error":"missing","hint":42}', {"error": "missing", "hint": None}),
    ("Error: missing. List objects.",
     {"error": "Error: missing. List objects.", "hint": None}),
])
def test_text_shapes_have_one_structured_view(message, expected):
    result = _error_frame([text(message)])
    assert result.content == [text(message)]
    assert result.structuredContent["vmware_error"] == expected


def test_existing_error_frame_preserves_extra_metadata():
    frame = types.CallToolResult(content=[text("failure")], isError=True,
                                structuredContent={"action": "blocked"}, _meta={"trace": "x"})
    result = _error_frame(frame)
    assert result.meta == frame.meta
    assert result.structuredContent["action"] == "blocked"
    assert result.structuredContent["vmware_error"]["error"] == "failure"


def test_no_text_error_is_explicit_without_inventing_a_hint():
    view = error_view([], None)
    assert view["error"]
    assert view["hint"] is None


def test_native_sdk_error_keeps_text_and_success_is_unchanged():
    async def run(configured):
        server = FastMCP("contract-probe")

        @server.tool()
        def broken() -> dict:
            raise ValueError("safe test failure")

        @server.tool()
        def success() -> dict:
            return {"error": None, "text": "Error: quoted as data"}

        if configured:
            install(server)
        async with create_connected_server_and_client_session(server._mcp_server) as client:
            return await client.call_tool("broken", {}), await client.call_tool("success", {})

    old_error, old_ok = asyncio.run(run(False))
    new_error, new_ok = asyncio.run(run(True))
    assert new_error.isError
    assert new_error.content == old_error.content
    assert new_error.structuredContent["vmware_error"]["error"]
    assert new_ok == old_ok


def test_policy_denial_stays_denied_and_never_reaches_body(tmp_path, monkeypatch):
    import sqlite3

    from vmware_policy import vmware_tool
    from vmware_policy.audit import reset_engine
    from vmware_policy.policy import reset_policy_engine
    from vmware_policy.serve import ServeOptions, configure

    home = tmp_path / "ops"
    home.mkdir()
    (home / "rules.yaml").write_text(
        'deny:\n  - name: block-test-delete\n    operations: [delete_probe]\n'
        '    reason: "Test denial"\n', encoding="utf-8"
    )
    monkeypatch.setenv("OPS_HOME", str(home))
    reset_engine()
    reset_policy_engine()
    calls = []
    server = FastMCP("denial-probe")

    @server.tool()
    @vmware_tool(risk_level="critical")
    def delete_probe() -> dict:
        calls.append("executed")
        return {"deleted": True}

    configure(server, ServeOptions(skill="denial-probe"))

    async def run():
        async with create_connected_server_and_client_session(server._mcp_server) as client:
            return await client.call_tool("delete_probe", {})

    try:
        result = asyncio.run(run())
        assert result.isError
        assert result.structuredContent["vmware_error"]["error"]
        assert calls == []
        with sqlite3.connect(home / "audit.db") as db:
            rows = db.execute("SELECT status FROM audit_log WHERE tool='delete_probe'").fetchall()
        assert rows == [("denied",)]
    finally:
        reset_engine()
        reset_policy_engine()


def test_cancellation_propagates_instead_of_becoming_an_error_frame():
    class LowLevel:
        def call_tool(self, **_kwargs):
            def register(fn):
                self.handler = fn
                return fn
            return register

    class Server:
        _mcp_server = LowLevel()

        async def call_tool(self, name, arguments):
            raise asyncio.CancelledError()

    server = Server()
    install(server)
    with pytest.raises(asyncio.CancelledError):
        asyncio.run(server._mcp_server.handler("probe", {}))
