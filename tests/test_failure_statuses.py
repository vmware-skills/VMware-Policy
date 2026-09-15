"""A call that did not return normally, or whose result says it failed, is never audited ``ok``.

HLD §8.2 / I-5, extended 2026-09-15c. A family survey that day found three ways a
failed call still produced an ``ok`` row, each reproduced here before the fix:

* ``@vmware_tool`` and the CLI decorators caught ``Exception`` only. A tool that
  raised ``SystemExit(2)`` or was interrupted recorded ``ok`` — and vmware-avi's
  ops raise ``SystemExit(1)`` for "not found", so its failed CLI reads and writes
  all did. A cancelled MCP call (``asyncio.CancelledError``) did the same; a long
  write the client gave up on may still be running, so it is ``interrupted``.
* The returned-failure rule knew only ``{"error": …}``. Results that say in their
  own words that the call failed — ``ok: false`` / ``success: false`` /
  ``outcome: failed`` (vmware-aiops guest steps and host network faults,
  vmware-pilot workflows) — were ``ok``. ``status`` stays unread on purpose: a
  successful poll of a failed task also says ``status: error``.
* A CLI command that printed its error and returned had no way to say it failed.
  ``report_tool_failure`` already marked an MCP tool failed; the CLI decorators now
  honour it too.
"""

from __future__ import annotations

import asyncio

import pytest
from click.exceptions import Exit

from vmware_policy import report_tool_failure, vmware_tool
from vmware_policy.cli_guard import audited, guarded


@pytest.fixture
def rows(monkeypatch):
    """Capture audit rows from both surfaces without touching ~/.vmware/audit.db."""
    captured: list[dict] = []

    class _Recorder:
        def log(self, **kw):
            captured.append(kw)

    monkeypatch.setattr("vmware_policy.guard.get_engine", lambda: _Recorder())
    return captured


def _only(rows: list[dict]) -> dict:
    assert len(rows) == 1, f"expected exactly one audit row, got {len(rows)}: {rows}"
    return rows[0]


# ── MCP: calls that do not return normally ───────────────────────────────────


@pytest.mark.parametrize(
    ("raised", "expected"),
    [
        (SystemExit(2), "error"),
        (SystemExit("fatal: vm not found"), "error"),
        (KeyboardInterrupt(), "interrupted"),
    ],
)
def test_mcp_tool_that_does_not_return_normally_is_not_ok(rows, raised, expected):
    @vmware_tool
    def tool():
        raise raised

    with pytest.raises(type(raised)):
        tool()
    assert _only(rows)["status"] == expected


@pytest.mark.parametrize("code", [0, None])
def test_mcp_tool_clean_system_exit_stays_ok(rows, code):
    @vmware_tool
    def tool():
        raise SystemExit(code)

    with pytest.raises(SystemExit):
        tool()
    assert _only(rows)["status"] == "ok"


def test_cancelled_async_mcp_call_is_interrupted(rows):
    @vmware_tool
    async def tool():
        raise asyncio.CancelledError()

    with pytest.raises(asyncio.CancelledError):
        asyncio.run(tool())
    assert _only(rows)["status"] == "interrupted"


def test_interrupted_async_mcp_call_is_interrupted(rows):
    @vmware_tool
    async def tool():
        raise KeyboardInterrupt()

    with pytest.raises(KeyboardInterrupt):
        asyncio.run(tool())
    assert _only(rows)["status"] == "interrupted"


# ── MCP: results that say the call failed ────────────────────────────────────


@pytest.mark.parametrize(
    "payload",
    [
        {"ok": False, "message": "VM 'web-99' not found"},
        {"success": False, "fault": "host network change rejected"},
        {"outcome": "failed", "workflow_id": "wf-1"},
        [{"success": False, "completed_steps": 0}],
    ],
)
def test_result_that_says_it_failed_is_error(rows, payload):
    @vmware_tool
    def tool():
        return payload

    assert tool() == payload
    assert _only(rows)["status"] == "error"


@pytest.mark.parametrize(
    "payload",
    [
        {"ok": True},
        {"success": True, "completed_steps": 3},
        {"outcome": "completed"},
        {"ok": None},
        # A successful poll of a task that failed: `status` is never read.
        {"status": "error", "task": "task-123"},
        # A batch: several items, some failed — the call itself succeeded.
        [{"success": False}, {"success": True}],
    ],
)
def test_result_that_does_not_say_it_failed_stays_ok(rows, payload):
    @vmware_tool
    def tool():
        return payload

    tool()
    assert _only(rows)["status"] == "ok"


def test_async_result_that_says_it_failed_is_error(rows):
    @vmware_tool
    async def tool():
        return {"success": False}

    asyncio.run(tool())
    assert _only(rows)["status"] == "error"


# ── CLI: calls that do not return normally ───────────────────────────────────


@pytest.mark.parametrize("decorator", [audited, guarded], ids=["audited", "guarded"])
@pytest.mark.parametrize(
    ("raised", "expected"),
    [
        (SystemExit(3), "error"),
        (SystemExit(0), "ok"),
        (KeyboardInterrupt(), "interrupted"),
    ],
)
def test_cli_command_that_does_not_return_normally(rows, decorator, raised, expected):
    @decorator("vs_status")
    def command(target=None):
        raise raised

    with pytest.raises(type(raised)):
        command()
    assert _only(rows)["status"] == expected


def test_cli_plain_exit_zero_stays_ok(rows):
    @audited("list_things")
    def command(target=None):
        raise Exit(0)

    with pytest.raises(Exit):
        command()
    assert _only(rows)["status"] == "ok"


# ── CLI: a command that prints its failure and returns ───────────────────────


@pytest.mark.parametrize("decorator", [audited, guarded], ids=["audited", "guarded"])
def test_cli_command_that_reports_failure_and_returns_is_error(rows, decorator):
    @decorator("tkc_versions")
    def command(target=None):
        report_tool_failure("Supervisor 'wcp-01' not found")
        return None

    command()
    row = _only(rows)
    assert row["status"] == "error"
    assert "wcp-01" in str(row["result"])


def test_cli_failure_signal_does_not_leak_into_the_next_command(rows):
    @audited("first")
    def first(target=None):
        report_tool_failure("broke")

    @audited("second")
    def second(target=None):
        return None

    first()
    second()
    assert [r["status"] for r in rows] == ["error", "ok"]
