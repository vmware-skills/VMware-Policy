"""Per-target session pools (HLD §16 D-13(2)).

A call holds one session per target for its whole body; different calls on one
target get different sessions up to the pool size; a call that already holds a
session never blocks on another target (it gets a temporary extra session), so
multi-target calls cannot deadlock. Outside a call scope (CLI, stdio) the pool
behaves like the old one-cached-session-per-target manager.
"""

from __future__ import annotations

import itertools
import threading
import time

import pytest

from vmware_policy import pool as pool_mod
from vmware_policy.pool import PoolTimeoutError, SessionPool, call_scope, in_call_scope


class FakeSession:
    _ids = itertools.count(1)

    def __init__(self, key: str) -> None:
        self.key = key
        self.id = next(self._ids)
        self.alive = True
        self.closed = False
        self.users = 0
        self.max_users = 0
        self._lock = threading.Lock()

    def use(self, seconds: float = 0.0) -> None:
        with self._lock:
            self.users += 1
            self.max_users = max(self.max_users, self.users)
        time.sleep(seconds)
        with self._lock:
            self.users -= 1


def make_pool(size: int = 2, **kw) -> tuple[SessionPool, list[FakeSession]]:
    made: list[FakeSession] = []

    def create(key: str) -> FakeSession:
        s = FakeSession(key)
        made.append(s)
        return s

    def close(s: FakeSession) -> None:
        s.closed = True

    p = SessionPool("test", create=create, is_alive=lambda s: s.alive, close=close, size=size, **kw)
    return p, made


@pytest.mark.unit
def test_outside_a_call_the_same_session_is_reused():
    p, made = make_pool()
    assert not in_call_scope()
    a = p.get("vc1")
    b = p.get("vc1")
    assert a is b and len(made) == 1


@pytest.mark.unit
def test_a_dead_session_is_closed_and_replaced():
    p, made = make_pool()
    a = p.get("vc1")
    a.alive = False
    b = p.get("vc1")
    assert b is not a and a.closed and len(made) == 2


@pytest.mark.unit
def test_within_one_call_the_same_target_gives_the_same_session():
    p, _ = make_pool()
    with call_scope():
        assert p.get("vc1") is p.get("vc1")


@pytest.mark.unit
def test_two_concurrent_calls_on_one_target_get_different_sessions():
    p, made = make_pool(size=2)
    seen: list[FakeSession] = []
    barrier = threading.Barrier(2)

    def call() -> None:
        with call_scope():
            s = p.get("vc1")
            seen.append(s)
            barrier.wait(5)
            s.use(0.05)

    threads = [threading.Thread(target=call) for _ in range(2)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(5)
    assert len({s.id for s in seen}) == 2
    assert all(s.max_users <= 1 for s in made)


@pytest.mark.unit
def test_a_session_is_never_used_by_two_calls_at_once():
    p, made = make_pool(size=2)

    def call() -> None:
        with call_scope():
            p.get("vc1").use(0.01)

    threads = [threading.Thread(target=call) for _ in range(12)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(10)
    assert len(made) == 2
    assert all(s.max_users <= 1 for s in made)


@pytest.mark.unit
def test_a_long_call_leaves_the_other_session_usable():
    p, _ = make_pool(size=2)
    started = threading.Event()
    done = threading.Event()

    def long_call() -> None:
        with call_scope():
            p.get("vc1")
            started.set()
            done.wait(5)

    t = threading.Thread(target=long_call)
    t.start()
    started.wait(5)
    t0 = time.monotonic()
    with call_scope():
        p.get("vc1")
    assert time.monotonic() - t0 < 0.5
    done.set()
    t.join(5)


@pytest.mark.unit
def test_a_full_pool_waits_then_times_out_with_a_teaching_error():
    p, _ = make_pool(size=1, wait_timeout=0.2)
    hold = threading.Event()
    started = threading.Event()

    def holder() -> None:
        with call_scope():
            p.get("vc1")
            started.set()
            hold.wait(5)

    t = threading.Thread(target=holder)
    t.start()
    started.wait(5)
    with call_scope(), pytest.raises(PoolTimeoutError, match="vc1"):
        p.get("vc1")
    hold.set()
    t.join(5)


@pytest.mark.unit
def test_a_waiting_call_gets_the_session_when_it_is_returned():
    p, made = make_pool(size=1)
    started = threading.Event()

    def holder() -> None:
        with call_scope():
            p.get("vc1")
            started.set()
            time.sleep(0.1)

    t = threading.Thread(target=holder)
    t.start()
    started.wait(5)
    with call_scope():
        s = p.get("vc1")
    t.join(5)
    assert s is made[0] and len(made) == 1


@pytest.mark.unit
def test_multi_target_calls_in_opposite_order_do_not_deadlock():
    p, made = make_pool(size=1, wait_timeout=2)
    barrier = threading.Barrier(2)
    errors: list[BaseException] = []

    def call(first: str, second: str) -> None:
        try:
            with call_scope():
                p.get(first)
                barrier.wait(5)
                p.get(second).use(0.01)
        except BaseException as exc:  # noqa: BLE001
            errors.append(exc)

    a = threading.Thread(target=call, args=("vc1", "vc2"))
    b = threading.Thread(target=call, args=("vc2", "vc1"))
    a.start()
    b.start()
    a.join(5)
    b.join(5)
    assert not errors
    # the extra sessions were temporary
    extras = [s for s in made if s.closed]
    assert len(extras) == 2
    assert all(s.max_users <= 1 for s in made)


@pytest.mark.unit
def test_a_failed_create_frees_its_slot():
    calls = {"n": 0}

    def create(key: str) -> FakeSession:
        calls["n"] += 1
        if calls["n"] == 1:
            raise ConnectionError("boom")
        return FakeSession(key)

    p = SessionPool("t", create=create, is_alive=lambda s: True, close=lambda s: None, size=1)
    with call_scope(), pytest.raises(ConnectionError):
        p.get("vc1")
    with call_scope():
        assert p.get("vc1") is not None


@pytest.mark.unit
def test_discard_closes_idle_sessions_now_and_busy_ones_on_return():
    p, made = make_pool(size=2)
    started = threading.Event()
    release = threading.Event()

    def busy() -> None:
        with call_scope():
            p.get("vc1")
            started.set()
            release.wait(5)

    t = threading.Thread(target=busy)
    t.start()
    started.wait(5)
    with call_scope():
        idle = p.get("vc1")  # second session, returned idle at the end of this call
    held = made[0]
    assert idle is not held
    p.discard("vc1")
    assert idle.closed and not held.closed
    release.set()
    t.join(5)
    assert held.closed
    assert p.keys() == []


@pytest.mark.unit
def test_nested_scopes_share_the_outer_lease():
    p, made = make_pool(size=1, wait_timeout=0.2)
    with call_scope():
        a = p.get("vc1")
        with call_scope():
            assert p.get("vc1") is a
        assert in_call_scope()
    assert len(made) == 1


@pytest.mark.unit
def test_pool_size_comes_from_the_environment(monkeypatch):
    monkeypatch.setenv("VMWARE_MCP_POOL_SIZE", "3")
    p = SessionPool("t", create=FakeSession, is_alive=lambda s: True, close=lambda s: None)
    assert p.size == 3


@pytest.mark.unit
@pytest.mark.parametrize("bad", ["0", "-1", "two", "1.5"])
def test_a_bad_pool_size_is_refused(monkeypatch, bad):
    monkeypatch.setenv("VMWARE_MCP_POOL_SIZE", bad)
    with pytest.raises(ValueError, match="VMWARE_MCP_POOL_SIZE"):
        SessionPool("t", create=FakeSession, is_alive=lambda s: True, close=lambda s: None)


@pytest.mark.unit
def test_a_dead_session_found_at_checkout_is_closed_and_replaced_in_a_call():
    p, made = make_pool(size=1)
    with call_scope():
        a = p.get("vc1")
    a.alive = False
    with call_scope():
        b = p.get("vc1")
    assert b is not a and a.closed and len(made) == 2


@pytest.mark.unit
def test_close_all_closes_everything():
    p, made = make_pool()
    p.get("vc1")
    p.get("vc2")
    p.close_all()
    assert all(s.closed for s in made) and p.keys() == []


@pytest.mark.unit
def test_random_interleavings_keep_the_invariants():
    import random

    rng = random.Random(7)
    p, made = make_pool(size=2, wait_timeout=10)
    errors: list[BaseException] = []

    def call(seed: int) -> None:
        r = random.Random(seed)
        try:
            with call_scope():
                for key in r.sample(["a", "b", "c"], r.randint(1, 3)):
                    p.get(key).use(r.random() * 0.005)
        except BaseException as exc:  # noqa: BLE001
            errors.append(exc)

    threads = [threading.Thread(target=call, args=(rng.randint(0, 10**6),)) for _ in range(40)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(20)
    assert not errors
    assert all(s.max_users <= 1 for s in made)
    pooled = [s for s in made if not s.closed]
    for key in "abc":
        assert sum(1 for s in pooled if s.key == key) <= 2
    assert pool_mod  # module imported for monkeypatching elsewhere


@pytest.mark.unit
def test_a_failed_extra_session_does_not_free_a_pooled_slot():
    fail = {"on": False}

    def create(key: str) -> FakeSession:
        if fail["on"]:
            raise ConnectionError("down")
        return FakeSession(key)

    p = SessionPool(
        "t", create=create, is_alive=lambda s: True, close=lambda s: None, size=1, wait_timeout=0.2
    )
    started, release = threading.Event(), threading.Event()

    def holder() -> None:
        with call_scope():
            p.get("vc1")
            started.set()
            release.wait(5)

    t = threading.Thread(target=holder)
    t.start()
    started.wait(5)
    with call_scope():
        p.get("vc2")
        fail["on"] = True
        with pytest.raises(ConnectionError):
            p.get("vc1")  # pool full and this call holds vc2 -> extra session, which fails
        fail["on"] = False
    # vc1 still has its one pooled session checked out: a new call must wait, not open a second
    with call_scope(), pytest.raises(PoolTimeoutError):
        p.get("vc1")
    release.set()
    t.join(5)
