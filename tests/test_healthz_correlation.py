"""Load-balancer health checks and request correlation over network transports.

A bank deployment (2026-10-16) runs the server behind a load balancer and keeps
its traces on the agent platform:

* the balancer's health probe carries no token, so it needs an unauthenticated
  ``/healthz`` that reveals nothing (no version, no targets) — every other path
  stays behind the token;
* the platform's trace id (``traceparent``, else ``X-Request-ID`` /
  ``X-Correlation-ID``) is recorded on each audit row, so a platform trace and
  this server's audit rows can be joined.
"""

from __future__ import annotations

import pytest

pytest.importorskip("mcp")

from mcp.server.fastmcp import FastMCP  # noqa: E402

from tests import test_serve  # noqa: E402
from tests.test_serve import ACCEPT, _call, _run_app, _session  # noqa: E402
from vmware_policy import serve, tokens  # noqa: E402
from vmware_policy.decorators import vmware_tool  # noqa: E402

ops_home = test_serve.ops_home

TRACE = "4bf92f3577b34da6a3ce929d0e0e4736"


def _server() -> FastMCP:
    mcp = FastMCP("hz")

    @mcp.tool(annotations={"readOnlyHint": True})
    @vmware_tool
    def get_thing(target: str = "") -> dict:
        """[READ] A thing."""
        return {"ok": True}

    serve.configure(mcp, serve.ServeOptions(skill="storage", transport="http"))
    return mcp


@pytest.mark.unit
def test_healthz_answers_without_a_token_and_says_nothing_else(ops_home):  # noqa: F811
    tokens.create_token("alice")
    server = _server()

    async def flow(c):
        get = await c.get("/healthz")
        head = await c.head("/healthz")
        other = await c.get("/mcp", headers={**ACCEPT, "Host": "127.0.0.1:8443"})
        return get, head, other

    get, head, other = _run_app(server, flow)
    assert get.status_code == 200 and get.json() == {"status": "ok"}
    assert head.status_code == 200
    assert other.status_code == 401  # everything else still needs the token


@pytest.mark.unit
def test_healthz_is_registered_once_when_configure_runs_twice(ops_home):  # noqa: F811
    tokens.create_token("alice")
    mcp = FastMCP("twice")
    opts = serve.ServeOptions(skill="storage", transport="http")
    serve.configure(mcp, opts)
    serve.configure(mcp, opts)
    paths = [getattr(r, "path", "") for r in mcp._custom_starlette_routes]
    assert paths.count("/healthz") == 1


@pytest.mark.unit
def test_stdio_registers_no_route(ops_home):  # noqa: F811
    mcp = FastMCP("stdio")
    serve.configure(mcp, serve.ServeOptions(skill="storage", transport="stdio"))
    assert not mcp._custom_starlette_routes


def _audit_row(tool: str) -> dict:
    from vmware_policy.audit import AuditEngine

    return next(r for r in AuditEngine().query(limit=5) if r["tool"] == tool)


@pytest.mark.unit
@pytest.mark.parametrize(
    ("headers", "expected"),
    [
        ({"traceparent": f"00-{TRACE}-00f067aa0ba902b7-01"}, TRACE),
        ({"X-Request-ID": "req-123:abc"}, "req-123:abc"),
        ({"X-Correlation-ID": "corr.9"}, "corr.9"),
        ({"X-Request-ID": "bad id;<script>"}, "badidscript"),
        ({"traceparent": "garbage", "X-Request-ID": "fallback"}, "fallback"),
        ({"traceparent": "00-" + "0" * 32 + "-00f067aa0ba902b7-01"}, ""),
        ({}, ""),
    ],
)
def test_the_audit_row_carries_the_callers_correlation_id(ops_home, headers, expected):  # noqa: F811
    secret = tokens.create_token("alice")
    server = _server()

    async def flow(c):
        _, _, h = await _session(c, secret)
        return await _call(c, {**h, **headers}, "get_thing", {"target": "a"})

    _run_app(server, flow)
    assert _audit_row("get_thing")["correlation_id"] == expected


@pytest.mark.unit
def test_a_long_request_id_is_cut(ops_home):  # noqa: F811
    secret = tokens.create_token("alice")
    server = _server()

    async def flow(c):
        _, _, h = await _session(c, secret)
        return await _call(c, {**h, "X-Request-ID": "a" * 500}, "get_thing", {"target": "a"})

    _run_app(server, flow)
    assert _audit_row("get_thing")["correlation_id"] == "a" * 128


@pytest.mark.unit
def test_audit_can_be_queried_by_correlation_id(ops_home):  # noqa: F811
    from vmware_policy.audit import AuditEngine

    engine = AuditEngine()
    engine.log(skill="s", tool="t1", correlation_id="abc")
    engine.log(skill="s", tool="t2", correlation_id="def")
    rows = engine.query(correlation_id="abc")
    assert [r["tool"] for r in rows] == ["t1"]


@pytest.mark.unit
def test_outside_a_network_request_there_is_no_correlation_id():
    from vmware_policy.caller import current_correlation_id

    assert current_correlation_id() == ""


@pytest.mark.unit
def test_healthz_answers_a_probe_by_ip_or_any_host(ops_home):  # noqa: F811
    tokens.create_token("alice")
    server = _server()

    async def flow(c):
        return [
            (await c.get("/healthz", headers={"Host": h})).status_code
            for h in ("10.0.0.5:8443", "lb-internal", "127.0.0.1:8443")
        ]

    assert _run_app(server, flow) == [200, 200, 200]


@pytest.mark.unit
def test_cli_log_filters_by_correlation_id(ops_home):  # noqa: F811
    from typer.testing import CliRunner

    from vmware_policy.audit import AuditEngine
    from vmware_policy.cli import app

    engine = AuditEngine()
    engine.log(skill="s", tool="wanted_tool", correlation_id="abc")
    engine.log(skill="s", tool="other_tool", correlation_id="def")
    out = CliRunner().invoke(app, ["log", "--correlation-id", "abc"], terminal_width=200)
    assert out.exit_code == 0, out.output
    # Rich folds the tool column in a narrow console, so count rows instead.
    assert "(last 1 entries)" in out.output


@pytest.mark.unit
def test_healthz_with_a_trailing_slash_answers_without_a_redirect(ops_home):  # noqa: F811
    tokens.create_token("alice")
    server = _server()

    async def flow(c):
        return await c.get("/healthz/", headers={"Host": "evil:1"})

    r = _run_app(server, flow)
    assert r.status_code == 200 and r.json() == {"status": "ok"}
    assert "location" not in {k.lower() for k in r.headers}


@pytest.mark.unit
def test_cli_export_filters_by_correlation_id(ops_home):  # noqa: F811
    import json

    from typer.testing import CliRunner

    from vmware_policy.audit import AuditEngine
    from vmware_policy.cli import app

    engine = AuditEngine()
    engine.log(skill="s", tool="wanted_tool", correlation_id="abc")
    engine.log(skill="s", tool="other_tool", correlation_id="def")
    out = CliRunner().invoke(app, ["export", "--correlation-id", "abc"])
    assert out.exit_code == 0, out.output
    assert [r["tool"] for r in json.loads(out.stdout)] == ["wanted_tool"]
