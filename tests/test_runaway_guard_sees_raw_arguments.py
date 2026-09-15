"""The runaway guard compares the arguments the tool received, not the redacted copy.

The breaker refuses the 26th call to the same tool with identical arguments inside
120 s — a stuck poll loop. It fingerprinted ``safe_params``, the copy that goes to
the audit row, where every ``sensitive_params`` value is ``***``. Review on
2026-09-15: once vmware-debug's ``incident_timeline`` redacted its ``events``
argument, 26 calls with *different* events were "identical" and the 26th was
refused. Any tool that declares a large or secret argument sensitive had the same
false trip.

The fingerprint is now a SHA-256 digest of the real arguments: different inputs
never collide, and neither the arguments nor a secret in them is kept in memory.
"""

from __future__ import annotations

import pytest

from vmware_policy import BudgetExceeded, vmware_tool
from vmware_policy.budget import get_budget


@pytest.fixture
def rows(monkeypatch):
    captured: list[dict] = []

    class _Recorder:
        def log(self, **kw):
            captured.append(kw)

    monkeypatch.setattr("vmware_policy.guard.get_engine", lambda: _Recorder())
    return captured


def _correlate():
    @vmware_tool(risk_level="low", sensitive_params=["events"])
    def incident_timeline(events: list, top_n: int = 5) -> dict:
        return {"event_count": len(events)}

    return incident_timeline


def test_calls_that_differ_only_in_a_redacted_argument_are_not_identical(rows):
    tool = _correlate()

    for i in range(30):
        tool(events=[{"ts": f"2026-09-15T05:{i:02d}:00Z", "text": f"event {i}"}])

    assert all(r["status"] == "ok" for r in rows), [r["status"] for r in rows]
    assert len(rows) == 30


def test_identical_calls_still_trip_the_guard(rows):
    tool = _correlate()
    same = [{"ts": "2026-09-15T05:00:00Z", "text": "same event"}]

    for _ in range(25):
        tool(events=same)
    with pytest.raises(BudgetExceeded):
        tool(events=same)

    assert rows[-1]["status"] == "budget_exceeded"


def test_the_guard_keeps_no_argument_text_in_memory(rows):
    tool = _correlate()

    tool(events=[{"text": "login failed password=Hunter2Secret!"}])

    keys = " ".join(get_budget()._state.windows.keys())
    assert "Hunter2Secret" not in keys
    assert "login failed" not in keys
