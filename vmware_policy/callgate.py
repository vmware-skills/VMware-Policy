"""Run sync MCP tools off the event loop, one call per target at a time (HLD §16 D-13).

FastMCP calls a synchronous tool directly on the event loop, so over a network
transport one slow call stalls every caller (Storage#18 measured 3 callers x
2 s = 6 s each). The decorated functions must stay synchronous — the CLI,
tests and the plan/workflow executors call them directly — so the offload is
done here, on the registered MCP tool only.

Concurrency rule for v1: calls naming the same ``target`` run one at a time,
calls naming different targets run in parallel, and a call that names no target
(the skill's default target, or a tool with no ``target`` parameter: cross-target
tools, Debug, Pilot, Harden, AVI) runs alone. That is one session per
target — the protection a single event loop gave each target — without the
cross-target and cross-caller blocking. A waiting exclusive call blocks new
per-target calls, so it is not starved.

The whole ``@vmware_tool`` body (policy pre-check, the call, the returned-
failure signal, the audit row) runs inside the worker with the caller's
context copied in, so the signal is read where it was set ([H6]) and the audit
sees the authenticated caller.

Pooled skills (D-13(2)): a skill whose connections come from
``vmware_policy.pool.SessionPool`` holds its own session per call, so the gate
is not needed and is skipped (``pooled=True``). Every offloaded call runs in a
``call_scope``; its sessions go back to the pool when the tool returns, before
FastMCP serializes the result, so a tool must return plain data, not live
pyVmomi objects (the family's tools build dicts; [H7]). A returned
iterator is drained inside the scope, so a generator cannot run after it.
"""

from __future__ import annotations

import functools
import inspect
from collections import Counter
from collections.abc import Iterator
from typing import Any

import anyio
import anyio.to_thread

from vmware_policy.pool import call_scope


class CallGate:
    """Per-target serialization with an exclusive mode, granted first-come first-served.

    A waiting call may start when it conflicts with no running call *and* with
    no call that arrived before it and is still waiting. Two calls conflict when
    either is exclusive (``key is None``) or both name the same target. So
    nothing is overtaken by a later conflicting call — a stream of exclusive
    calls cannot starve a named one, nor the reverse — while calls that do not
    conflict still run side by side.
    """

    def __init__(self) -> None:
        self._cond = anyio.Condition()
        self._busy: Counter[str] = Counter()
        self._exclusive = False
        self._waiting: list[tuple[int, str | None]] = []
        self._tickets = 0

    @staticmethod
    def _conflict(a: str | None, b: str | None) -> bool:
        return a is None or b is None or a == b

    def _can_start(self, entry: tuple[int, str | None]) -> bool:
        key = entry[1]
        if self._exclusive or (key is None and self._busy) or (key is not None and self._busy[key]):
            return False
        for earlier in self._waiting:
            if earlier is entry:
                return True
            if self._conflict(earlier[1], key):
                return False
        return True

    async def acquire(self, key: str | None) -> None:
        async with self._cond:
            self._tickets += 1
            entry = (self._tickets, key)
            self._waiting.append(entry)
            try:
                while not self._can_start(entry):
                    await self._cond.wait()
            except BaseException:
                self._waiting.remove(entry)
                self._cond.notify_all()  # a later waiter may now be first
                raise
            self._waiting.remove(entry)
            if key is None:
                self._exclusive = True
            else:
                self._busy[key] += 1
            self._cond.notify_all()  # compatible waiters behind this one may start too

    async def release(self, key: str | None) -> None:
        # Always shielded: release runs from `finally` blocks of cancelled calls,
        # and a release that a cancellation can interrupt leaks the slot.
        with anyio.CancelScope(shield=True):
            async with self._cond:
                if key is None:
                    self._exclusive = False
                else:
                    self._busy[key] -= 1
                    if not self._busy[key]:
                        del self._busy[key]
                self._cond.notify_all()


def _in_scope(fn: Any, kwargs: dict[str, Any]) -> Any:
    with call_scope():
        result = fn(**kwargs)
        if isinstance(result, Iterator):  # a generator would run after the scope ends
            result = list(result)
        return result


def _pooled(fn: Any) -> Any:
    @functools.wraps(fn)
    async def run(**kwargs: Any) -> Any:
        return await anyio.to_thread.run_sync(
            functools.partial(_in_scope, fn, kwargs), abandon_on_cancel=False
        )

    return run


def _offloaded(fn: Any, gate: CallGate, takes_target: bool) -> Any:
    @functools.wraps(fn)
    async def run(**kwargs: Any) -> Any:
        # Only an explicitly named target is a key. "No target" means the
        # skill's default, whose real name the skill resolves later — keying it
        # separately would let it run beside a call naming that same target, on
        # the same unlocked connection. So an unnamed target runs alone.
        named = kwargs.get("target") if takes_target else None
        key = named if isinstance(named, str) and named.strip() else None
        await gate.acquire(key)
        try:
            # abandon_on_cancel=False: a cancelled request still waits for its
            # worker to finish, so the target is not released while that thread
            # is using its session.
            return await anyio.to_thread.run_sync(
                functools.partial(_in_scope, fn, kwargs), abandon_on_cancel=False
            )
        finally:
            # Shielded: a cancelled scope would otherwise raise on the lock
            # acquire inside release(), leak the slot, and wedge the target (and
            # then every exclusive call, and through it every target) forever.
            with anyio.CancelScope(shield=True):
                await gate.release(key)

    return run


def offload_sync_tools(server: Any, gate: CallGate | None = None, *, pooled: bool = False) -> int:
    """Replace each registered synchronous tool's callable with a threaded one.

    Gated per target unless ``pooled`` (the skill's sessions come from a
    ``SessionPool``). Uses the SDK's ``Tool.fn`` / ``Tool.is_async`` (mcp<2.0);
    the argument model was built from the original signature and is unchanged.
    Returns the number of tools offloaded.
    """
    gate = gate or CallGate()
    count = 0
    for tool in server._tool_manager.list_tools():
        if tool.is_async:
            continue
        if pooled:
            tool.fn = _pooled(tool.fn)
        else:
            takes_target = "target" in inspect.signature(tool.fn).parameters
            tool.fn = _offloaded(tool.fn, gate, takes_target)
        tool.is_async = True
        count += 1
    return count
