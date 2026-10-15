"""Per-target session pools for MCP servers that serve several callers (HLD §16 D-13(2)).

A *session* is whatever a skill connects with: a pyVmomi ServiceInstance, or a
REST client holding its own token. One session must never carry two calls at
once (pyVmomi interleaves SOAP on one connection; a REST client refreshes its
token in place), so a call **holds** a session for its whole body:

* Inside :func:`call_scope` (set by ``vmware_policy.serve`` around each MCP call
  on a network transport), :meth:`SessionPool.get` checks a session out for the
  rest of the call. The same call asking again for the same target gets the
  same session. Different calls get different sessions, up to the pool size
  (``VMWARE_MCP_POOL_SIZE``, default 2); beyond that a call waits for one to be
  returned, and gives up with :class:`PoolTimeoutError` after ``wait_timeout``.
* A call that already holds a session never waits: if the target's pool is full
  it gets a temporary extra session, closed when the call ends. Two calls taking
  two targets in opposite order therefore cannot deadlock.
* Outside a call scope (the CLI, stdio, tests) ``get`` returns the target's one
  dedicated unscoped session, as the one-session-per-target managers did — those
  callers are sequential. It is never one of the pooled sessions, so it is never
  handed to a call. A thread a tool starts itself does not inherit the scope
  (ContextVars do not follow into a ThreadPoolExecutor) and would share that
  session: a tool that fans out must run each branch in ``contextvars.copy_context()``.
* Extra sessions are not capped: at most one per target per running call. Each
  waiting call occupies a worker thread until it is served or times out.

Every checkout probes the session (``is_alive``); a dead one is closed and
replaced. :meth:`discard` closes a target's idle sessions now and its busy ones
when their calls return.
"""

from __future__ import annotations

import contextlib
import logging
import os
import threading
import time
from collections.abc import Callable, Iterator
from contextvars import ContextVar
from dataclasses import dataclass, field
from typing import Any, Generic, TypeVar

S = TypeVar("S")

_log = logging.getLogger(__name__)

POOL_SIZE_ENV = "VMWARE_MCP_POOL_SIZE"
DEFAULT_POOL_SIZE = 2


class PoolTimeoutError(RuntimeError):
    """Every session to a target stayed busy for longer than the wait limit."""


@dataclass
class _Held:
    pool: SessionPool[Any]
    key: str
    session: Any
    generation: int
    extra: bool


@dataclass
class _Lease:
    held: list[_Held] = field(default_factory=list)

    def find(self, pool: SessionPool[Any], key: str) -> _Held | None:
        for h in self.held:
            if h.pool is pool and h.key == key:
                return h
        return None

    def release_all(self) -> None:
        for h in reversed(self.held):
            try:
                h.pool._return(h)
            except Exception:  # never let one return strand the others
                _log.exception("returning a %s session for %r failed", h.pool.name, h.key)
        self.held.clear()


_scope: ContextVar[_Lease | None] = ContextVar("vmware_policy_pool_scope", default=None)


@contextlib.contextmanager
def call_scope() -> Iterator[None]:
    """Sessions taken from any pool inside this block are held until it ends.

    Nested scopes share the outer one, so a tool calling another tool keeps one
    session per target.
    """
    if _scope.get() is not None:
        yield
        return
    lease = _Lease()
    token = _scope.set(lease)
    try:
        yield
    finally:
        _scope.reset(token)
        lease.release_all()


def in_call_scope() -> bool:
    return _scope.get() is not None


def _size_from_env() -> int:
    raw = os.environ.get(POOL_SIZE_ENV, "").strip()
    if not raw:
        return DEFAULT_POOL_SIZE
    try:
        size = int(raw)
    except ValueError:
        size = 0
    if size < 1:
        raise ValueError(
            f"{POOL_SIZE_ENV} must be a whole number of at least 1 (got {raw!r}); it is the number "
            f"of sessions an MCP server keeps per target. Unset it for the default "
            f"({DEFAULT_POOL_SIZE})."
        )
    return size


class SessionPool(Generic[S]):
    """Sessions per target key. Thread-safe; see the module docstring for the rules."""

    def __init__(
        self,
        name: str,
        *,
        create: Callable[[str], S],
        is_alive: Callable[[S], bool],
        close: Callable[[S], None],
        size: int | None = None,
        wait_timeout: float = 300.0,
    ) -> None:
        self.name = name
        self.size = size if size is not None else _size_from_env()
        if self.size < 1:
            raise ValueError(f"pool size must be at least 1 (got {self.size})")
        self.wait_timeout = wait_timeout
        self._create = create
        self._is_alive = is_alive
        self._close = close
        self._cond = threading.Condition()
        self._idle: dict[str, list[tuple[S, int]]] = {}
        self._shared: dict[str, tuple[S, int]] = {}  # unscoped callers (CLI, stdio)
        self._count: dict[str, int] = {}  # pooled sessions that exist (idle + checked out)
        self._generation: dict[str, int] = {}

    # -- public -----------------------------------------------------------------

    def get(self, key: str) -> S:
        lease = _scope.get()
        if lease is None:
            return self._get_shared(key)
        held = lease.find(self, key)
        if held is not None:
            return held.session
        return self._checkout(key, lease)

    def keys(self) -> list[str]:
        """Targets with at least one open session."""
        with self._cond:
            return sorted({k for k, n in self._count.items() if n} | set(self._shared))

    def discard(self, key: str) -> None:
        """Close the target's idle sessions now and its busy ones when their calls end."""
        with self._cond:
            self._generation[key] = self._generation.get(key, 0) + 1
            idle = self._idle.pop(key, [])
            self._count[key] = self._count.get(key, 0) - len(idle)
            self._prune(key)
            shared = self._shared.pop(key, None)
            self._cond.notify_all()
        for session, _ in idle + ([shared] if shared else []):
            self._safe_close(session)

    def close_all(self) -> None:
        for key in self.keys():
            self.discard(key)

    # -- internals --------------------------------------------------------------

    def _prune(self, key: str) -> None:
        if self._count.get(key, 0) <= 0:
            self._count.pop(key, None)

    def _safe_close(self, session: S) -> None:
        try:
            self._close(session)
        except Exception:  # a session may already be dead
            _log.debug("closing a %s session failed", self.name, exc_info=True)

    def _alive(self, session: S) -> bool:
        try:
            return bool(self._is_alive(session))
        except Exception:
            return False

    def _get_shared(self, key: str) -> S:
        """The key's dedicated unscoped session: never one of the pooled sessions calls hold."""
        with self._cond:
            entry = self._shared.get(key)
        if entry is not None:
            session, gen = entry
            if self._alive(session):
                return session
            with self._cond:
                if self._shared.get(key, (None,))[0] is session:
                    del self._shared[key]
            self._safe_close(session)
        while True:
            with self._cond:
                gen = self._generation.get(key, 0)
            session = self._create(key)
            with self._cond:
                if self._generation.get(key, 0) == gen:
                    old = self._shared.get(key)
                    self._shared[key] = (session, gen)
                    break
            self._safe_close(session)  # discard() ran while it was being created
        if old is not None and old[0] is not session:
            self._safe_close(old[0])  # another thread replaced it at the same time
        return session

    def _checkout(self, key: str, lease: _Lease) -> S:
        deadline = time.monotonic() + self.wait_timeout
        extra = False
        session: S | None = None
        with self._cond:
            while True:
                idle = self._idle.get(key)
                if idle:
                    session, gen = idle.pop()
                    break
                if self._count.get(key, 0) < self.size:
                    self._count[key] = self._count.get(key, 0) + 1
                    gen = self._generation.get(key, 0)
                    break
                if lease.held:  # never wait while holding: no lock-order deadlock
                    extra = True
                    gen = self._generation.get(key, 0)
                    break
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise PoolTimeoutError(
                        f"All {self.size} {self.name} sessions to target '{key}' stayed busy for "
                        f"{self.wait_timeout:.0f} s. Retry when the other calls finish, or raise "
                        f"{POOL_SIZE_ENV} on the server (each session is a login on the target)."
                    )
                self._cond.wait(remaining)
        try:
            if session is not None and not self._alive(session):
                self._safe_close(session)
                with self._cond:  # its slot is reused by the replacement below
                    gen = self._generation.get(key, 0)
                session = None
            if session is None:
                session = self._create(key)
        except BaseException:
            if not extra:  # free the slot this call reserved or popped
                with self._cond:
                    self._count[key] = self._count.get(key, 0) - 1
                    self._prune(key)
                    self._cond.notify_all()
            if session is not None:
                self._safe_close(session)
            raise
        lease.held.append(_Held(self, key, session, gen, extra))
        return session

    def _return(self, held: _Held) -> None:
        if held.extra:
            self._safe_close(held.session)
            return
        with self._cond:
            current = self._generation.get(held.key, 0)
            if held.generation == current:
                self._idle.setdefault(held.key, []).append((held.session, current))
                self._cond.notify_all()
                return
            self._count[held.key] = self._count.get(held.key, 0) - 1
            self._prune(held.key)
            self._cond.notify_all()
        self._safe_close(held.session)
