"""Pooled skills over a network transport (HLD §16 D-13(2) acceptance).

N callers on one target run side by side up to the pool size, a session never
carries two calls at once, the session is held until the result is serialized,
and a returned failure still audits as ``error``.
"""

from __future__ import annotations

import threading
import time

import anyio
import pytest

pytest.importorskip("mcp")

from mcp.server.fastmcp import FastMCP  # noqa: E402

from tests import test_serve  # noqa: E402
from tests.test_serve import _call, _run_app, _session  # noqa: E402
from vmware_policy import serve, tokens  # noqa: E402
from vmware_policy.decorators import vmware_tool  # noqa: E402
from vmware_policy.pool import SessionPool, in_call_scope  # noqa: E402

ops_home = test_serve.ops_home  # the same sandbox fixture


class Sess:
    def __init__(self, key: str) -> None:
        self.key = key
        self.users = 0
        self.max_users = 0
        self.lock = threading.Lock()


class Lazy:
    """Stands in for a pyVmomi object whose properties are fetched on first read."""

    def __init__(self, seen: list) -> None:
        self.seen = seen

    def __str__(self) -> str:
        self.seen.append(in_call_scope())
        return "lazy"


def _pooled_server(log: list, made: list, lazy_seen: list) -> FastMCP:
    def create(key: str) -> Sess:
        s = Sess(key)
        made.append(s)
        return s

    pool = SessionPool("t", create=create, is_alive=lambda s: True, close=lambda s: None, size=2)
    mcp = FastMCP("pooled")

    @mcp.tool(annotations={"readOnlyHint": True})
    @vmware_tool
    def get_thing(target: str = "", delay: float = 0.0) -> dict:
        """[READ] Hold a session for `delay` seconds."""
        s = pool.get(target or "default")
        with s.lock:
            s.users += 1
            s.max_users = max(s.max_users, s.users)
        start = time.monotonic()
        time.sleep(delay)
        log.append((target, start, time.monotonic()))
        with s.lock:
            s.users -= 1
        return {"target": target}

    # No @vmware_tool here: its audit step already stringifies results, which
    # would hide whether the offload itself serializes inside the scope.
    @mcp.tool(annotations={"readOnlyHint": True})
    def get_lazy(target: str = "") -> dict:
        """[READ] Return something read lazily."""
        pool.get(target or "default")
        return {"value": Lazy(lazy_seen)}

    @mcp.tool(annotations={"readOnlyHint": True})
    @vmware_tool
    def get_broken(target: str = "") -> dict:
        """[READ] Returns an error envelope."""
        pool.get(target or "default")
        return {"error": "nope"}

    serve.configure(mcp, serve.ServeOptions(skill="storage", transport="http", pooled=True))
    return mcp


@pytest.mark.unit
def test_two_calls_on_one_target_overlap_and_a_third_waits(ops_home):  # noqa: F811
    secret = tokens.create_token("alice")
    log: list = []
    made: list = []
    server = _pooled_server(log, made, [])

    async def flow(c):
        _, _, headers = await _session(c, secret)
        async with anyio.create_task_group() as tg:
            for i in range(3):
                tg.start_soon(_call, c, headers, "get_thing", {"target": "a", "delay": 0.4}, 10 + i)

    t0 = time.monotonic()
    _run_app(server, flow)
    elapsed = time.monotonic() - t0
    spans = sorted((s, e) for _, s, e in log)
    assert len(spans) == 3
    assert spans[1][0] < spans[0][1]  # first two overlap
    assert spans[2][0] >= min(spans[0][1], spans[1][1]) - 0.01  # third waited for a session
    assert elapsed < 1.1  # 2 rounds, not 3
    assert len(made) == 2 and all(s.max_users == 1 for s in made)


@pytest.mark.unit
def test_calls_with_no_target_are_not_serialized_when_pooled(ops_home):  # noqa: F811
    secret = tokens.create_token("alice")
    log: list = []
    server = _pooled_server(log, [], [])

    async def flow(c):
        _, _, headers = await _session(c, secret)
        async with anyio.create_task_group() as tg:
            tg.start_soon(_call, c, headers, "get_thing", {"delay": 0.4}, 20)
            tg.start_soon(_call, c, headers, "get_thing", {"delay": 0.4}, 21)

    _run_app(server, flow)
    (s1, e1), (s2, e2) = sorted((s, e) for _, s, e in log)
    assert s2 < e1


@pytest.mark.unit
def test_the_result_is_serialized_while_the_session_is_held(ops_home):  # noqa: F811
    secret = tokens.create_token("alice")
    lazy_seen: list = []
    server = _pooled_server([], [], lazy_seen)

    async def flow(c):
        _, _, headers = await _session(c, secret)
        return await _call(c, headers, "get_lazy", {"target": "a"})

    status, body = _run_app(server, flow)
    assert status == 200 and "lazy" in str(body)
    assert lazy_seen and lazy_seen[0] is True


@pytest.mark.unit
def test_a_returned_failure_audits_as_error_when_pooled(ops_home):  # noqa: F811
    secret = tokens.create_token("alice")
    server = _pooled_server([], [], [])

    async def flow(c):
        _, _, headers = await _session(c, secret)
        return await _call(c, headers, "get_broken", {"target": "x"})

    _run_app(server, flow)
    from vmware_policy.audit import AuditEngine

    row = next(r for r in AuditEngine().query(limit=5) if r["tool"] == "get_broken")
    assert row["status"] == "error"
