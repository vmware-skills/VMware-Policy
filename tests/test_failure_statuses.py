"""A call that did not return normally, or whose result says it failed, is never audited ``ok``.

HLD §8.2 / I-5, extended 2026-09-15c. A family survey that day found three ways a
failed call still produced an ``ok`` row, each reproduced here before the fix:

* ``@vmware_tool`` and the CLI decorators caught ``Exception`` only. A tool that
  raised ``SystemExit(2)`` or was interrupted recorded ``ok`` — and vmware-avi's
  ops raise ``SystemExit(1)`` for "not found", so its failed CLI reads and writes
  all did. A cancelled MCP call (``asyncio.CancelledError``) did the same; a long
  write the client gave up on may still be running, so it is ``interrupted``.
* The returned-failure rule knew only ``{"error": …}``. vmware-pilot workflows say
  ``outcome: "failed"`` and were ``ok``. ``status`` stays unread on purpose: a
  successful poll of a failed task also says ``status: error``.
* A CLI command that printed its error and returned had no way to say it failed.
  ``report_tool_failure`` already marked an MCP tool failed; the CLI decorators now
  honour it too.

Narrowed the same day after review (decision D2): ``ok: false`` / ``success: false``
are NOT read. No producer in the family uses them to mean "this call failed"
without also carrying a truthy ``error``, and one uses ``success: false`` as the
answer: vmware-aiops ``vmk_ping`` returns it for an unreachable host or an esxcli
fault (``Message too long`` is how an MTU probe reports the path MTU). Reading it
filed a successful probe as ``error`` and disagreed with AIops' own MCP frame
detector, which reads ``error`` only.

Review follow-ups pinned here too: typer ≥0.26 raises its own ``Exit``/``Abort``
classes, not click's (D1); an interrupted call is not a failure for the circuit
breaker (D5); ``vmware-audit stats`` shows ``interrupted`` in yellow (D6); the
per-call failure signal is reset even when the audit write raises (D7).
"""

from __future__ import annotations

import asyncio
import contextvars
import importlib
import re

import pytest
from click.exceptions import Exit
from rich.console import Console
from typer.testing import CliRunner

from vmware_policy import report_tool_failure, vmware_tool
from vmware_policy.audit import AuditEngine
from vmware_policy.cli_guard import audited, guarded
from vmware_policy.decorators import _failure_signal


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


def _exception_classes(name: str) -> list[type[BaseException]]:
    """Every distinct ``name`` class a CLI command can raise here.

    click's, and typer's public one. On typer <0.26 they are the same class; on
    typer ≥0.26 typer vendors click and ``typer.Exit`` is a different class, which
    is the case D1 is about. Run this file with ``uv run --with 'typer>=0.26'`` to
    exercise both.
    """
    found: list[type[BaseException]] = []
    for module in ("click.exceptions", "typer"):
        try:
            cls = getattr(importlib.import_module(module), name)
        except (ImportError, AttributeError):
            continue
        if cls not in found:
            found.append(cls)
    assert found, f"no {name} class importable — the parametrisation would test nothing"
    return found


def _cls_id(cls: type) -> str:
    return f"{cls.__module__}.{cls.__qualname__}"


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
        {"error": "VM 'web-99' not found", "hint": "Run vm_list."},
        {"outcome": "failed", "workflow_id": "wf-1"},
        [{"outcome": "failed", "workflow_id": "wf-2"}],
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
        # `ok` / `success` are not read (D2). vmware-aiops vmk_ping answers an
        # unreachable host or an esxcli fault with `success: False` — for an MTU
        # probe that IS the result, not a failed call — and AIops' MCP frame
        # detector reads `error` only. A real failure in this family also
        # carries a truthy `error`.
        {
            "request": {"host": "esx-01", "source_vmk": "vmk1", "dest_ip": "10.0.0.9"},
            "success": False,
            "fault": "Message too long",
            "hint": "For df=True, 'Message too long' means the path MTU is below size+28.",
        },
        {"ok": False, "message": "no matching VMs"},
        [{"success": False, "completed_steps": 0}],
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
        return {"outcome": "failed"}

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


# ── CLI: typer ≥0.26 exceptions (D1) ─────────────────────────────────────────


@pytest.mark.parametrize("exit_cls", _exception_classes("Exit"), ids=_cls_id)
@pytest.mark.parametrize("decorator", [audited, guarded], ids=["audited", "guarded"])
def test_cli_exit_zero_is_ok_whichever_exit_class(rows, decorator, exit_cls):
    @decorator("list_things")
    def command(target=None):
        raise exit_cls()

    with pytest.raises(exit_cls):
        command()
    row = _only(rows)
    filed = f"{_cls_id(exit_cls)}(0) was filed {row['status']}: {row['result']}"
    assert row["status"] == "ok", filed


@pytest.mark.parametrize("exit_cls", _exception_classes("Exit"), ids=_cls_id)
def test_cli_nonzero_exit_is_error_with_a_readable_reason(rows, exit_cls):
    @audited("incident_timeline")
    def command(target=None):
        raise exit_cls(2)

    with pytest.raises(exit_cls):
        command()
    row = _only(rows)
    assert row["status"] == "error"
    error = (row["result"] or {}).get("error", "")
    assert error, f"a non-zero exit recorded no reason: {row['result']!r}"
    assert "2" in error


@pytest.mark.parametrize("exit_cls", _exception_classes("Exit"), ids=_cls_id)
def test_cli_nonzero_exit_records_the_reported_failure_message(rows, exit_cls):
    @audited("tkc_versions")
    def command(target=None):
        report_tool_failure("Supervisor 'wcp-01' not found")
        raise exit_cls(1)

    with pytest.raises(exit_cls):
        command()
    row = _only(rows)
    assert row["status"] == "error"
    assert "wcp-01" in row["result"]["error"]


@pytest.mark.parametrize("abort_cls", _exception_classes("Abort"), ids=_cls_id)
@pytest.mark.parametrize("decorator", [audited, guarded], ids=["audited", "guarded"])
def test_cli_abort_is_rejected_whichever_abort_class(rows, decorator, abort_cls):
    @decorator("vm_delete")
    def command(target=None):
        raise abort_cls()

    with pytest.raises(abort_cls):
        command()
    assert _only(rows)["status"] == "rejected"


def test_declined_typer_confirm_is_rejected(rows):
    """The real producer: ``typer.confirm(abort=True)`` answered "n"."""
    import typer

    app = typer.Typer()

    @app.command()
    @guarded("vm_delete", risk_level="critical")
    def delete(target: str = "") -> None:
        typer.confirm("Delete?", abort=True)

    result = CliRunner().invoke(app, [], input="n\n")
    assert result.exit_code != 0
    assert _only(rows)["status"] == "rejected"


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


# ── The failure signal is reset even when the audit write raises (D7) ────────


def _boom(*_a, **_kw):
    raise RuntimeError("audit write exploded")


def test_cli_failure_signal_is_reset_when_audit_call_raises(monkeypatch):
    monkeypatch.setattr("vmware_policy.cli_guard.audit_call", _boom)

    @audited("first")
    def command(target=None):
        report_tool_failure("broke")

    def scenario():
        with pytest.raises(RuntimeError):
            command()
        return _failure_signal.get()

    # Run in a copied context so a leak cannot escape into other tests.
    assert contextvars.copy_context().run(scenario) is None


def test_mcp_failure_signal_is_reset_when_finalize_raises(monkeypatch):
    monkeypatch.setattr("vmware_policy.decorators._finalize", _boom)

    @vmware_tool
    def tool():
        report_tool_failure("broke")
        return {}

    def scenario():
        with pytest.raises(RuntimeError):
            tool()
        return _failure_signal.get()

    assert contextvars.copy_context().run(scenario) is None


def test_async_mcp_failure_signal_is_reset_when_finalize_raises(monkeypatch):
    monkeypatch.setattr("vmware_policy.decorators._finalize", _boom)

    @vmware_tool
    async def tool():
        report_tool_failure("broke")
        return {}

    async def scenario():
        with pytest.raises(RuntimeError):
            await tool()
        return _failure_signal.get()

    assert asyncio.run(scenario()) is None


# ── An interrupted call is not a failure of the pattern (D5) ─────────────────


@pytest.fixture
def breaker_outcomes(monkeypatch):
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
    return outcomes


def test_interrupted_call_is_not_reported_to_the_circuit_breaker(rows, breaker_outcomes):
    @vmware_tool
    def tool():
        raise KeyboardInterrupt()

    with pytest.raises(KeyboardInterrupt):
        tool()
    assert _only(rows)["status"] == "interrupted"
    assert breaker_outcomes == [], "a user cancellation was counted against the pattern"


def test_failed_call_is_still_reported_to_the_circuit_breaker(rows, breaker_outcomes):
    @vmware_tool
    def tool():
        raise SystemExit(1)

    with pytest.raises(SystemExit):
        tool()
    assert breaker_outcomes == [False]


# ── vmware-audit stats colours `interrupted` like `log` does (D6) ────────────


def test_stats_shows_interrupted_in_yellow(tmp_path, monkeypatch):
    from vmware_policy import cli as audit_cli

    engine = AuditEngine(tmp_path / "audit.db")
    engine.log(skill="aiops", tool="vm_migrate", status="interrupted")
    engine.log(skill="aiops", tool="vm_info", status="ok")
    monkeypatch.setattr(audit_cli, "get_engine", lambda: engine)
    console = Console(force_terminal=True, color_system="standard", width=200, record=True)
    monkeypatch.setattr(audit_cli, "console", console)

    result = CliRunner().invoke(audit_cli.app, ["stats"])

    assert result.exit_code == 0, result.output
    rendered = console.export_text(styles=True).splitlines()
    plain = [re.sub(r"\x1b\[[0-9;]*m", "", line).strip() for line in rendered]
    printed = any(p.startswith("interrupted:") for p in plain)
    assert printed, f"stats printed no interrupted row: {plain}"
    interrupted = next(r for r, p in zip(rendered, plain) if p.startswith("interrupted:"))
    ok = next(r for r, p in zip(rendered, plain) if p.startswith("ok:"))
    assert "\x1b[33m" in interrupted, f"interrupted not yellow: {interrupted!r}"
    assert "\x1b[32m" in ok, f"ok not green: {ok!r}"
