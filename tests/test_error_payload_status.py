"""A tool that *returns* its failure must be audited as a failure.

The family has two ways a tool reports a failure, and ``@vmware_tool`` only ever
saw one of them. Raising propagates to the wrapper and is recorded correctly.
Returning an error payload — which is what ``tool_errors`` in vmware-aiops does
for ~41 tools, and what every hand-written ``except`` block in the other skills
does — looked to the wrapper exactly like a successful call.

Three things went wrong at once, all from the same missing distinction:

1. The audit row said ``status=ok`` for an operation that failed. In a family
   whose stated purpose is a trustworthy audit trail, that is the defect that
   matters most: the log is not merely incomplete, it is affirmatively wrong.
2. ``_record_undo`` ran. Its own docstring promises "a recorded undo always
   corresponds to a change that actually happened" — so a failed write could
   leave an undo token for a change that never occurred, and vmware-pilot would
   happily offer to reverse it.
3. The circuit breaker was told ``success=True``. CLAUDE.md mandates a
   three-layer recovery model whose third layer is "熔断保护 — 连续 3 次同类失败
   触发". A tool that fails by returning can never trip it, so for most of the
   family that layer was silently dead.

Detection is deliberately narrow. Dict-shaped payloads carrying a truthy
``error`` key are the family's own documented envelope, so recognising them is
reading a convention rather than guessing. Bare strings are NOT sniffed: skills
that return console text (vmware-avi, vmware-log-insight) can legitimately emit
output beginning with "Error:" as *data*, and mis-marking a successful call is
the same class of lie as the bug being fixed. Those skills use the explicit
signal instead.
"""

from __future__ import annotations

import asyncio

import pytest

from vmware_policy import report_tool_failure, vmware_tool


@pytest.fixture
def audited(monkeypatch):
    """Capture audit rows without touching ~/.vmware/audit.db."""
    rows: list[dict] = []

    class _Recorder:
        def log(self, **kw):
            rows.append(kw)

    monkeypatch.setattr("vmware_policy.decorators.get_engine", lambda: _Recorder())
    return rows


def _status(rows: list[dict]) -> str:
    assert len(rows) == 1, f"expected exactly one audit row, got {len(rows)}"
    return rows[0]["status"]


# ── dict / list payloads: the documented envelope ────────────────────────────


def test_dict_error_payload_is_audited_as_error(audited):
    @vmware_tool(risk_level="low")
    def failing() -> dict:
        return {"error": "VM 'web-99' not found.", "hint": "Run list_vms."}

    failing()
    assert _status(audited) == "error"


def test_single_element_list_error_payload_is_audited_as_error(audited):
    """``tool_errors(shape="list")`` returns exactly this."""

    @vmware_tool(risk_level="low")
    def failing() -> list:
        return [{"error": "not found", "hint": "Run list_vms."}]

    failing()
    assert _status(audited) == "error"


def test_successful_dict_result_stays_ok(audited):
    @vmware_tool(risk_level="low")
    def fine() -> dict:
        return {"items": [], "total": 0}

    fine()
    assert _status(audited) == "ok"


def test_falsy_error_key_is_not_a_failure(audited):
    """``{"error": None}`` is a result that says "nothing went wrong"."""

    @vmware_tool(risk_level="low")
    def fine() -> dict:
        return {"status": "healthy", "error": None}

    fine()
    assert _status(audited) == "ok"


def test_multi_element_list_is_not_a_failure(audited):
    """A batch result whose items happen to carry per-item errors is a
    successful call that returned partial results, not a failed call."""

    @vmware_tool(risk_level="low")
    def fine() -> list:
        return [{"name": "a", "error": "skipped"}, {"name": "b"}]

    fine()
    assert _status(audited) == "ok"


def test_bare_error_string_is_not_sniffed(audited):
    """Console-text skills emit strings starting with "Error:" as data.

    Marking those calls failed would be the same lie in the other direction, so
    the string shape must use ``report_tool_failure`` to be recognised.
    """

    @vmware_tool(risk_level="low")
    def prints_a_log() -> str:
        return "Error: connection refused\nError: retrying\n"

    prints_a_log()
    assert _status(audited) == "ok"


# ── explicit signal: for tools whose return type cannot carry a marker ───────


def test_explicit_signal_marks_the_call_failed(audited):
    @vmware_tool(risk_level="low")
    def failing() -> str:
        report_tool_failure("VS 'web-01' not found.")
        return "Error: VS 'web-01' not found. Run vs_list."

    failing()
    assert _status(audited) == "error"


def test_signal_does_not_leak_into_the_next_call(audited):
    @vmware_tool(risk_level="low")
    def failing() -> str:
        report_tool_failure("boom")
        return "Error: boom"

    @vmware_tool(risk_level="low")
    def fine() -> str:
        return "all good"

    failing()
    fine()
    assert [r["status"] for r in audited] == ["error", "ok"]


def test_signal_from_an_inner_tool_does_not_fail_the_outer_one(audited):
    """Skills delegate in-process (vmware-aiops calls vmware-monitor's library).

    An inner failure that the outer tool handles and recovers from must not
    silently mark the outer call failed — the outer tool's own return value is
    the authority on its own outcome.
    """

    @vmware_tool(risk_level="low")
    def inner() -> str:
        report_tool_failure("inner blew up")
        return "Error: inner blew up"

    @vmware_tool(risk_level="low")
    def outer() -> dict:
        inner()
        return {"items": ["recovered"], "total": 1}

    outer()
    assert [r["status"] for r in audited] == ["error", "ok"]


# ── async tools take a separate code path ────────────────────────────────────
#
# The two wrappers are written out twice, and the async one already carries a
# comment about a bug that hit it alone ("a sync wrapper would return an
# un-awaited coroutine and audit it as ok"). Testing only the sync path leaves
# the duplicate free to drift — a mutation that deleted the async wrapper's
# context reset was survived by an earlier version of this file for exactly
# that reason.


# Driven with ``asyncio.run`` rather than pytest-asyncio: vmware-policy is a
# transitive dependency of twelve skills and does not need another one for four
# tests. Each test awaits everything inside a *single* coroutine, because
# ``asyncio.run`` copies the context per call — two separate runs would pass the
# leak test for free and prove nothing.


def test_async_dict_error_payload_is_audited_as_error(audited):
    @vmware_tool(risk_level="low")
    async def failing() -> dict:
        return {"error": "not found", "hint": "Run list_vms."}

    asyncio.run(failing())
    assert _status(audited) == "error"


def test_async_explicit_signal_marks_the_call_failed(audited):
    @vmware_tool(risk_level="low")
    async def failing() -> str:
        report_tool_failure("boom")
        return "Error: boom"

    asyncio.run(failing())
    assert _status(audited) == "error"


def test_async_signal_does_not_leak_into_the_next_call(audited):
    @vmware_tool(risk_level="low")
    async def failing() -> str:
        report_tool_failure("boom")
        return "Error: boom"

    @vmware_tool(risk_level="low")
    async def fine() -> str:
        return "all good"

    async def both():
        await failing()
        await fine()

    asyncio.run(both())
    assert [r["status"] for r in audited] == ["error", "ok"]


def test_async_inner_failure_does_not_fail_the_outer_call(audited):
    @vmware_tool(risk_level="low")
    async def inner() -> str:
        report_tool_failure("inner blew up")
        return "Error: inner blew up"

    @vmware_tool(risk_level="low")
    async def outer() -> dict:
        await inner()
        return {"items": ["recovered"], "total": 1}

    asyncio.run(outer())
    assert [r["status"] for r in audited] == ["error", "ok"]


# ── the two downstream consequences ──────────────────────────────────────────


def test_failed_call_records_no_undo_token(audited):
    """Undo's contract is that a token implies a change actually happened."""
    recorded: list = []

    @vmware_tool(risk_level="high", undo=lambda params, result: {"tool": "undo_it", "params": {}})
    def failing() -> dict:
        return {"error": "delete failed", "hint": "Run doctor."}

    import vmware_policy.decorators as dec

    class _Store:
        def record(self, **kw):
            recorded.append(kw)
            return "undo-1"

    import vmware_policy.undo as undo_mod

    original = undo_mod.get_undo_store
    undo_mod.get_undo_store = lambda: _Store()
    try:
        result = failing()
    finally:
        undo_mod.get_undo_store = original

    assert recorded == [], "recorded an undo token for a change that never happened"
    assert "_undo_id" not in result
    assert dec  # keep the import meaningful for readers


def test_failed_call_reports_failure_to_the_circuit_breaker(audited, monkeypatch):
    """Layer three of CLAUDE.md's recovery model only works if it sees failures."""
    outcomes: list[bool] = []

    class _Pattern:
        pattern_id = "p1"

    class _Match:
        armed = True
        pattern = _Pattern()

    class _Engine:
        def match(self, *a, **kw):
            return _Match()

        def report_outcome(self, *, pattern_id, target, success):
            outcomes.append(success)

    monkeypatch.setattr("vmware_policy.decorators.get_pattern_engine", lambda: _Engine())

    @vmware_tool(risk_level="low")
    def failing() -> dict:
        return {"error": "boom", "hint": "Run doctor."}

    failing()
    assert outcomes == [False], "a returned failure never reaches the breaker"
