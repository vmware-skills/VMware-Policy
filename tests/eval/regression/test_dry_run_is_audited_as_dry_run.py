"""Regression — a dry run is audited as a dry run, not as a write that happened.

Found 2026-09-14. `vmware-audit log` listed `start_resource_maintenance`,
`end_resource_maintenance` and `add_alert_note` as `ok` on the lab — every one of
them a `--dry-run` that sent nothing to Aria. The only trace was
`"dry_run": true` inside the params JSON, which `log` does not show, so the
audit trail read as maintenance windows opened and notes posted that never
existed. Nine such rows were in the operator's audit.db.

Both surfaces now record status ``dry_run`` for a call that completed with
``dry_run=True``: ``@vmware_tool`` (MCP) and ``@guarded`` (CLI). A dry run that
fails is still ``error``; a bypassed policy still says so; and a dry run records
no undo token, because it changed nothing that could be undone.
"""

from __future__ import annotations

import pytest

import vmware_policy.audit as audit_mod
import vmware_policy.policy as policy_mod
from vmware_policy import cli_guard
from vmware_policy.audit import AuditEngine
from vmware_policy.decorators import vmware_tool
from vmware_policy.policy import PolicyResult


@pytest.fixture
def engine(tmp_path):
    eng = AuditEngine(tmp_path / "audit.db")
    audit_mod._engine = eng
    policy_mod._engine = None
    yield eng
    audit_mod._engine = None
    policy_mod._engine = None


def _statuses(eng):
    return [r["status"] for r in reversed(eng.query(limit=20))]


@pytest.mark.unit
def test_mcp_tool_dry_run_is_recorded_as_dry_run(engine):
    @vmware_tool(risk_level="medium")
    def start_resource_maintenance(resource_id: str, dry_run: bool = False) -> dict:
        return {"dry_run": dry_run}

    start_resource_maintenance("r-1", dry_run=True)
    start_resource_maintenance("r-1", dry_run=False)
    start_resource_maintenance("r-1")
    assert _statuses(engine) == ["dry_run", "ok", "ok"]


@pytest.mark.unit
def test_a_failed_dry_run_is_still_an_error(engine):
    @vmware_tool
    def add_alert_note(alert_id: str, dry_run: bool = False) -> dict:
        raise ValueError("alert_id must be a UUID")

    with pytest.raises(ValueError):
        add_alert_note(" ", dry_run=True)
    assert _statuses(engine) == ["error"]


@pytest.mark.unit
def test_a_dry_run_records_no_undo(engine, monkeypatch):
    calls = []

    @vmware_tool(undo=lambda params, result: calls.append(params) or {"tool": "end", "params": {}})
    def start(resource_id: str, dry_run: bool = False) -> dict:
        return {"changed": not dry_run}

    result = start("r-1", dry_run=True)
    assert calls == [], "the undo callable ran for a call that changed nothing"
    assert "_undo_id" not in result


@pytest.fixture
def cli_rows(monkeypatch):
    rows: list[dict] = []
    monkeypatch.setattr(cli_guard, "guard", lambda *a, **k: PolicyResult(allowed=True))
    monkeypatch.setattr(cli_guard, "audit_call", lambda skill, tool, **kw: rows.append(kw))
    return rows


@pytest.mark.unit
def test_cli_dry_run_is_recorded_as_dry_run(cli_rows):
    import typer

    @cli_guard.guarded(risk_level="medium")
    def maintenance_start(resource_id: str, dry_run: bool = False) -> None:
        return None

    @cli_guard.guarded(risk_level="medium")
    def note_add(alert_id: str, dry_run: bool = False) -> None:
        raise typer.Exit(0)  # a preview that returns early

    maintenance_start("r-1", dry_run=True)
    maintenance_start("r-1", dry_run=False)
    with pytest.raises(typer.Exit):
        note_add("a-1", dry_run=True)
    assert [r["status"] for r in cli_rows] == ["dry_run", "ok", "dry_run"]


@pytest.mark.unit
def test_cli_bypassed_dry_run_says_both(cli_rows, monkeypatch):
    monkeypatch.setattr(
        cli_guard, "guard", lambda *a, **k: PolicyResult(allowed=True, rule="policy_disabled")
    )

    @cli_guard.guarded()
    def maintenance_start(resource_id: str, dry_run: bool = False) -> None:
        return None

    maintenance_start("r-1", dry_run=True)
    assert cli_rows[-1]["status"] == "dry_run_bypassed"


@pytest.mark.unit
def test_audit_log_filters_and_shows_dry_runs(engine):
    from typer.testing import CliRunner

    from vmware_policy.cli import app

    @vmware_tool
    def start(resource_id: str, dry_run: bool = False) -> dict:
        return {}

    start("r-1", dry_run=True)
    start("r-2")
    out = CliRunner().invoke(app, ["log", "--status", "dry_run"]).output
    assert "dry_run" in out and "start" in out
    assert len(engine.query(status="dry_run", limit=10)) == 1


# ── confirm=False previews (HLD §7, revised 2026-09-16) ──────────────────────
# The family's gate spells a preview `confirm: bool = False` and answers with a
# top-level `"action": "preview"`. Recognising only `dry_run=True` left every
# such preview audited as `ok` and let it file an undo token for a change that
# never happened.


@pytest.mark.unit
def test_a_confirm_false_preview_is_recorded_as_dry_run(engine):
    @vmware_tool(risk_level="high")
    def delete_thing(name: str, confirm: bool = False) -> dict:
        if not confirm:
            return {"action": "preview", "blast_radius": {"name": name}}
        return {"action": "deleted", "blast_radius": {"name": name}}

    delete_thing("a")
    delete_thing("a", confirm=True)
    assert _statuses(engine) == ["dry_run", "ok"]


@pytest.mark.unit
def test_a_confirm_false_preview_records_no_undo(engine):
    calls = []

    @vmware_tool(undo=lambda params, result: calls.append(params) or {"tool": "undo", "params": {}})
    def power_off(name: str, confirm: bool = False) -> dict:
        return {"action": "preview"} if not confirm else {"action": "powered_off"}

    result = power_off("vm")
    assert calls == [] and "_undo_id" not in result
    power_off("vm", confirm=True)
    assert len(calls) == 1, "a real change must still file its undo token"


@pytest.mark.unit
def test_a_nested_preview_word_is_not_a_preview(engine):
    @vmware_tool
    def listing(name: str) -> dict:
        return {"items": [{"action": "preview"}], "mode": "preview"}

    listing("x")
    assert _statuses(engine) == ["ok"]
