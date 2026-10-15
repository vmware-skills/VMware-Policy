"""On a network transport the breaker and ceilings are per caller (HLD §16 D-13(3), [H5]).

One process serves many callers there. A runaway loop by one caller must not
lock out the others, and a lifetime ceiling counted across every caller of a
long-lived server would eventually stop the server for everyone.
"""

from __future__ import annotations

import pytest

from vmware_policy import budget


@pytest.fixture
def tracker(monkeypatch):
    monkeypatch.setenv("VMWARE_RUNAWAY_MAX", "3")
    monkeypatch.setenv("VMWARE_RUNAWAY_WINDOW_SEC", "60")
    return budget.BudgetTracker()


def _as(monkeypatch, who):
    monkeypatch.setattr(budget, "current_caller", lambda: who)


@pytest.mark.unit
def test_one_callers_loop_does_not_trip_another(tracker, monkeypatch):
    _as(monkeypatch, "token:alice")
    for _ in range(3):
        tracker.check_and_record("get_vm", {"name": "x"})
    with pytest.raises(budget.BudgetExceeded):
        tracker.check_and_record("get_vm", {"name": "x"})

    _as(monkeypatch, "token:bob")
    tracker.check_and_record("get_vm", {"name": "x"})  # bob is not affected


@pytest.mark.unit
def test_lifetime_ceilings_do_not_apply_to_network_callers(tracker, monkeypatch):
    monkeypatch.setenv("VMWARE_MAX_TOOL_CALLS", "2")
    _as(monkeypatch, "token:alice")
    for i in range(5):
        tracker.check_and_record("get_vm", {"name": str(i)})


@pytest.mark.unit
def test_lifetime_ceilings_still_apply_without_a_network_caller(tracker, monkeypatch):
    monkeypatch.setenv("VMWARE_MAX_TOOL_CALLS", "2")
    _as(monkeypatch, None)
    tracker.check_and_record("get_vm", {"name": "1"})
    tracker.check_and_record("get_vm", {"name": "2"})
    with pytest.raises(budget.BudgetExceeded, match="budget reached"):
        tracker.check_and_record("get_vm", {"name": "3"})


@pytest.mark.unit
def test_expired_windows_are_evicted(tracker, monkeypatch):
    _as(monkeypatch, "token:alice")
    clock = [1000.0]
    monkeypatch.setattr(budget.time, "time", lambda: clock[0])
    for i in range(50):
        tracker.check_and_record("get_vm", {"name": str(i)})
    clock[0] += 120
    tracker.check_and_record("get_vm", {"name": "fresh"})
    assert tracker.tracked_fingerprints("token:alice") == 1
