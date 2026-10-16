"""Network MCP transports (HLD §16 D-10/D-11/D-12/D-13, I-11).

These drive the real SDK app in process: the same Starlette app `serve()` hands
to uvicorn, reached through httpx's ASGI transport. Nothing binds a port.
"""

from __future__ import annotations

import json
import threading
import time

import pytest

pytest.importorskip("mcp")

import anyio  # noqa: E402
import httpx  # noqa: E402
from mcp.server.fastmcp import FastMCP  # noqa: E402

from vmware_policy import serve, tokens  # noqa: E402
from vmware_policy.decorators import vmware_tool  # noqa: E402

ACCEPT = {"Accept": "application/json, text/event-stream", "Content-Type": "application/json"}


@pytest.fixture
def ops_home(tmp_path, monkeypatch):
    """A fresh OPS_HOME, and the process-wide engines dropped so they reopen there."""
    import vmware_policy.audit as audit_mod
    import vmware_policy.policy as policy_mod
    from vmware_policy.budget import reset_budget

    monkeypatch.setenv("OPS_HOME", str(tmp_path))
    audit_mod._engine = None
    policy_mod._engine = None
    reset_budget()
    yield tmp_path
    audit_mod._engine = None
    policy_mod._engine = None
    reset_budget()
    # configure() sets the process-wide audit surface; put stdio back for the
    # tests that run after these.
    from vmware_policy.surface import set_process_surface

    set_process_surface("mcp-stdio")
    from vmware_policy import hostpaths

    hostpaths.set_network_serving(False)


def _server(log: list | None = None) -> FastMCP:
    mcp = FastMCP("test")
    seen = log if log is not None else []

    @mcp.tool(annotations={"readOnlyHint": True})
    @vmware_tool
    def get_thing(target: str = "", delay: float = 0.0) -> dict:
        """[READ] Return a thing, optionally after a delay."""
        start = time.monotonic()
        time.sleep(delay)
        seen.append(("target", target, start, time.monotonic(), threading.get_ident()))
        return {"target": target}

    @mcp.tool(annotations={"readOnlyHint": True})
    @vmware_tool
    def across_targets(delay: float = 0.0) -> dict:
        """[READ] A tool with no target argument."""
        start = time.monotonic()
        time.sleep(delay)
        seen.append(("all", None, start, time.monotonic(), threading.get_ident()))
        return {"ok": True}

    return mcp


def _sse_json(text: str) -> dict:
    for line in text.splitlines():
        if line.startswith("data:"):
            return json.loads(line[5:].strip())
    return json.loads(text)


async def _session(client: httpx.AsyncClient, token: str | None, host: str = "127.0.0.1:8443"):
    headers = {**ACCEPT, "Host": host}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    init = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": "2025-06-18",
            "capabilities": {},
            "clientInfo": {"name": "t", "version": "0"},
        },
    }
    r = await client.post("/mcp", json=init, headers=headers)
    if r.status_code != 200:
        return r, None, headers
    sid = r.headers["mcp-session-id"]
    headers = {**headers, "mcp-session-id": sid}
    await client.post(
        "/mcp", json={"jsonrpc": "2.0", "method": "notifications/initialized"}, headers=headers
    )
    return r, sid, headers


async def _call(client, headers, name, args, rid=2):
    body = {
        "jsonrpc": "2.0",
        "id": rid,
        "method": "tools/call",
        "params": {"name": name, "arguments": args},
    }
    r = await client.post("/mcp", json=body, headers=headers)
    return r.status_code, _sse_json(r.text)


def _run_app(server, coro_fn):
    async def main():
        app = server.streamable_http_app()
        async with server.session_manager.run():
            transport = httpx.ASGITransport(app=app)
            async with httpx.AsyncClient(
                transport=transport, base_url="http://127.0.0.1:8443"
            ) as c:
                return await coro_fn(c)

    return anyio.run(main)


def _configured(ops_home, log=None, **kw):
    server = _server(log)
    opts = dict(skill="storage", transport="http", host="127.0.0.1", port=8443)
    opts.update(kw)
    serve.configure(server, serve.ServeOptions(**opts))
    return server


@pytest.mark.unit
def test_no_tokens_means_no_listener(ops_home):
    with pytest.raises(serve.ServeError, match="token create"):
        serve.configure(_server(), serve.ServeOptions(skill="storage", transport="http"))


@pytest.mark.unit
@pytest.mark.parametrize("host", ["0.0.0.0", "10.0.0.5", "sup.example.com"])
def test_plain_http_binds_loopback_only(ops_home, host):
    tokens.create_token("alice")
    with pytest.raises(serve.ServeError, match="loopback"):
        serve.configure(_server(), serve.ServeOptions(skill="storage", transport="http", host=host))


@pytest.mark.unit
def test_https_needs_a_certificate_and_public_names(ops_home, tmp_path):
    tokens.create_token("alice")
    with pytest.raises(serve.ServeError, match="--cert"):
        serve.configure(
            _server(), serve.ServeOptions(skill="storage", transport="https", host="0.0.0.0")
        )
    cert = tmp_path / "c.pem"
    cert.write_text("x", encoding="utf-8")
    with pytest.raises(serve.ServeError, match="--public-name"):
        serve.configure(
            _server(),
            serve.ServeOptions(
                skill="storage", transport="https", host="0.0.0.0", certfile=cert, keyfile=cert
            ),
        )


@pytest.mark.unit
def test_an_unknown_transport_is_refused(ops_home):
    with pytest.raises(serve.ServeError, match="stdio, https, http"):
        serve.configure(_server(), serve.ServeOptions(skill="storage", transport="sse"))


@pytest.mark.unit
def test_unauthenticated_requests_get_401(ops_home):
    tokens.create_token("alice")

    r, _, _ = _run_app(_configured(ops_home), lambda c: _session(c, None))
    assert r.status_code == 401
    r, _, _ = _run_app(_configured(ops_home), lambda c: _session(c, "not-a-token"))
    assert r.status_code == 401


@pytest.mark.unit
def test_a_host_outside_the_allowed_names_is_refused(ops_home):
    secret = tokens.create_token("alice")
    server = _configured(ops_home)

    r, _, _ = _run_app(server, lambda c: _session(c, secret, host="evil.example.com"))
    assert r.status_code in (400, 421)


@pytest.mark.unit
def test_the_audit_row_names_the_token(ops_home):
    secret = tokens.create_token("alice")
    server = _configured(ops_home)

    async def flow(c):
        r, sid, headers = await _session(c, secret)
        assert r.status_code == 200
        return await _call(c, headers, "get_thing", {"target": "vc1"})

    status, body = _run_app(server, flow)
    assert status == 200 and not body["result"].get("isError"), body

    from vmware_policy.audit import AuditEngine

    rows = AuditEngine().query(limit=5)
    row = next(r for r in rows if r["tool"] == "get_thing")
    assert row["user"] == "token:alice"
    assert row["surface"] == "mcp-http-loopback"


@pytest.mark.unit
def test_different_targets_run_in_parallel_and_one_target_in_series(ops_home):
    secret = tokens.create_token("alice")
    log: list = []
    server = _configured(ops_home, log)

    async def flow(c):
        _, _, headers = await _session(c, secret)
        async with anyio.create_task_group() as tg:
            tg.start_soon(_call, c, headers, "get_thing", {"target": "a", "delay": 0.4}, 10)
            tg.start_soon(_call, c, headers, "get_thing", {"target": "b", "delay": 0.4}, 11)
            tg.start_soon(_call, c, headers, "get_thing", {"target": "a", "delay": 0.4}, 12)

    _run_app(server, flow)
    by_target: dict[str, list] = {}
    for kind, target, start, end, _ in log:
        by_target.setdefault(target, []).append((start, end))
    a1, a2 = sorted(by_target["a"])
    (b,) = by_target["b"]
    assert a2[0] >= a1[1] - 0.01  # same target: one after the other
    assert b[0] < a1[1] and a1[0] < b[1]  # different targets: overlapping


@pytest.mark.unit
def test_a_tool_without_target_runs_alone(ops_home):
    secret = tokens.create_token("alice")
    log: list = []
    server = _configured(ops_home, log)

    async def flow(c):
        _, _, headers = await _session(c, secret)
        async with anyio.create_task_group() as tg:
            tg.start_soon(_call, c, headers, "get_thing", {"target": "a", "delay": 0.3}, 20)
            tg.start_soon(_call, c, headers, "across_targets", {"delay": 0.3}, 21)
            tg.start_soon(_call, c, headers, "get_thing", {"target": "b", "delay": 0.3}, 22)

    _run_app(server, flow)
    spans = sorted((s, e, kind) for kind, _, s, e, _ in log)
    excl = next((s, e) for s, e, k in spans if k == "all")
    for s, e, k in spans:
        if k != "all":
            assert e <= excl[0] + 0.01 or s >= excl[1] - 0.01


@pytest.mark.unit
def test_a_returned_failure_in_the_worker_still_audits_as_error(ops_home):
    secret = tokens.create_token("alice")
    server = FastMCP("t2")

    @server.tool(annotations={"readOnlyHint": True})
    @vmware_tool
    def get_broken(target: str = "") -> dict:
        """[READ] Returns an error envelope."""
        return {"error": "nope"}

    serve.configure(server, serve.ServeOptions(skill="storage", transport="http"))

    async def flow(c):
        _, _, headers = await _session(c, secret)
        return await _call(c, headers, "get_broken", {"target": "x"})

    _run_app(server, flow)
    from vmware_policy.audit import AuditEngine

    row = next(r for r in AuditEngine().query(limit=5) if r["tool"] == "get_broken")
    assert row["status"] == "error"


@pytest.mark.unit
def test_stdio_is_left_alone(ops_home):
    server = _server()
    tools_before = {t.name: t.fn for t in server._tool_manager.list_tools()}
    serve.configure(server, serve.ServeOptions(skill="storage", transport="stdio"))
    assert {t.name: t.fn for t in server._tool_manager.list_tools()} == tools_before


@pytest.mark.unit
def test_run_server_refuses_before_binding_with_exit_2(ops_home, capsys):
    with pytest.raises(SystemExit) as excinfo:
        serve.run_server(_server(), skill="storage", transport="https", host="0.0.0.0")
    assert excinfo.value.code == 2
    assert "not started" in capsys.readouterr().err


@pytest.mark.unit
def test_run_server_applies_exposure_before_serving(ops_home, capsys):
    server = _server()
    with pytest.raises(SystemExit):
        serve.run_server(server, skill="storage", expose="bogus")
    assert "not started" in capsys.readouterr().err


@pytest.mark.unit
def test_a_cancelled_call_releases_its_target():
    """A client timeout / Esc cancels the call; the next call on that target must not hang."""
    from vmware_policy.callgate import CallGate

    gate = CallGate()

    async def main():
        async with anyio.create_task_group() as tg:

            async def holder():
                await gate.acquire("vc1")
                try:
                    await anyio.sleep(10)
                finally:
                    # the exact shape of _offloaded: release inside a cancelled scope
                    await gate.release("vc1")

            tg.start_soon(holder)
            await anyio.sleep(0.05)
            tg.cancel_scope.cancel()
        with anyio.fail_after(2):
            await gate.acquire("vc1")
            await gate.release("vc1")
            await gate.acquire(None)
            await gate.release(None)

    anyio.run(main)


@pytest.mark.unit
def test_a_cancelled_offloaded_call_does_not_wedge_the_server(ops_home):
    """End to end through the offload wrapper, as a request cancellation does it."""
    from vmware_policy.callgate import CallGate, _offloaded

    gate = CallGate()

    def slow(target: str = "") -> dict:
        time.sleep(0.3)
        return {}

    run = _offloaded(slow, gate, takes_target=True)

    async def main():
        with anyio.move_on_after(0.05):
            await run(target="vc1")
        with anyio.fail_after(3):
            await run(target="vc1")
            await _offloaded(lambda: {}, gate, takes_target=False)()

    anyio.run(main)


@pytest.mark.unit
def test_a_call_without_a_target_runs_alone_even_on_a_target_tool(ops_home):
    """The default target has a real name only the skill knows; it must not run beside that name."""
    secret = tokens.create_token("alice")
    log: list = []
    server = _configured(ops_home, log)

    async def flow(c):
        _, _, headers = await _session(c, secret)
        async with anyio.create_task_group() as tg:
            tg.start_soon(
                _call, c, headers, "get_thing", {"target": "home-vcenter", "delay": 0.3}, 30
            )
            tg.start_soon(_call, c, headers, "get_thing", {"delay": 0.3}, 31)

    _run_app(server, flow)
    (s1, e1), (s2, e2) = sorted((s, e) for _, _, s, e, _ in log)
    assert s2 >= e1 - 0.01


def _no_bind(monkeypatch):
    import uvicorn

    def refuse(*a, **k):
        raise AssertionError("uvicorn.run was reached")

    monkeypatch.setattr(uvicorn, "run", refuse)


@pytest.mark.unit
def test_run_refuses_to_bind_if_auth_is_not_actually_enforced(ops_home, monkeypatch):
    tokens.create_token("alice")
    _no_bind(monkeypatch)
    real = serve.configure

    def configure_without_verifier(server, opts):
        surface = real(server, opts)
        server._token_verifier = None  # what an SDK rename would leave behind
        return surface

    monkeypatch.setattr(serve, "configure", configure_without_verifier)
    with pytest.raises(serve.ServeError, match="Self-check failed"):
        serve.run(_server(), serve.ServeOptions(skill="storage", transport="http"))


@pytest.mark.unit
def test_configure_refuses_an_app_built_too_early(ops_home):
    tokens.create_token("alice")
    server = _server()
    server.streamable_http_app()
    with pytest.raises(serve.ServeError, match="built before"):
        serve.configure(server, serve.ServeOptions(skill="storage", transport="http"))


@pytest.mark.unit
def test_the_self_check_passes_when_auth_is_on(ops_home, monkeypatch):
    tokens.create_token("alice")
    reached = []
    import uvicorn

    monkeypatch.setattr(uvicorn, "run", lambda *a, **k: reached.append(k))
    serve.run(_server(), serve.ServeOptions(skill="storage", transport="http"))
    assert reached and reached[0]["host"] == "127.0.0.1"


@pytest.mark.unit
def test_an_open_token_file_is_a_clean_refusal(ops_home, capsys):
    import os as _os

    tokens.create_token("alice")
    _os.chmod(tokens.token_file(), 0o644)
    with pytest.raises(SystemExit) as excinfo:
        serve.run_server(_server(), skill="storage", transport="http")
    assert excinfo.value.code == 2
    assert "0600" in capsys.readouterr().err


@pytest.mark.unit
@pytest.mark.parametrize("bad", ["mcp.corp:443", "fe80::1%en0", "a b", "https://x"])
def test_public_names_are_host_names_only(ops_home, tmp_path, bad):
    tokens.create_token("alice")
    cert = tmp_path / "c.pem"
    cert.write_text("x", encoding="utf-8")
    with pytest.raises(serve.ServeError, match="--public-name"):
        serve.configure(
            _server(),
            serve.ServeOptions(
                skill="storage",
                transport="https",
                host="0.0.0.0",
                certfile=cert,
                keyfile=cert,
                public_names=(bad,),
            ),
        )


@pytest.mark.unit
def test_ipv6_loopback_is_usable_by_default(ops_home):
    secret = tokens.create_token("alice")
    server = _configured(ops_home, host="::1")

    r, _, _ = _run_app(server, lambda c: _session(c, secret, host="[::1]:8443"))
    assert r.status_code == 200


@pytest.mark.unit
def test_named_calls_are_not_starved_by_a_stream_of_unnamed_ones():
    """Callers relying on the default target must not lock out a caller naming one."""
    from vmware_policy.callgate import CallGate

    gate = CallGate()
    done = []

    async def unnamed_loop():
        while not done:
            await gate.acquire(None)
            try:
                await anyio.sleep(0.05)
            finally:
                await gate.release(None)

    async def main():
        async with anyio.create_task_group() as tg:
            for _ in range(3):
                tg.start_soon(unnamed_loop)
            await anyio.sleep(0.1)
            with anyio.fail_after(2):
                await gate.acquire("vc2")
                await gate.release("vc2")
            done.append(True)

    anyio.run(main)


@pytest.mark.unit
def test_a_cancelled_call_holds_its_target_until_its_worker_ends():
    """abandon_on_cancel=False: the target is not reused while the old worker still runs."""
    from vmware_policy.callgate import CallGate, _offloaded

    gate = CallGate()
    spans = []

    def slow(target: str = "") -> dict:
        start = time.monotonic()
        time.sleep(0.3)
        spans.append((start, time.monotonic()))
        return {}

    run = _offloaded(slow, gate, takes_target=True)

    async def main():
        with anyio.move_on_after(0.05):
            await run(target="vc1")
        await run(target="vc1")

    anyio.run(main)
    (s1, e1), (s2, e2) = sorted(spans)
    assert s2 >= e1 - 0.01


@pytest.mark.unit
def test_gate_invariants_under_random_load():
    """No two conflicting holders at once; every call finishes (no deadlock)."""
    import random

    from vmware_policy.callgate import CallGate

    gate = CallGate()
    holders: list = []
    finished = []
    rng = random.Random(7)

    async def worker(i):
        key = rng.choice([None, "a", "b", "c"])
        await gate.acquire(key)
        try:
            for other in holders:
                assert not (other is None or key is None or other == key), (other, key)
            holders.append(key)
            await anyio.sleep(rng.uniform(0, 0.01))
            holders.remove(key)
        finally:
            await gate.release(key)
        finished.append(i)

    async def main():
        with anyio.fail_after(10):
            async with anyio.create_task_group() as tg:
                for i in range(200):
                    tg.start_soon(worker, i)

    anyio.run(main)
    assert len(finished) == 200
