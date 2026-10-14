"""HLD §16 D-14 (audit surface) and D-15 (2.0 tool renames mapped in policy).

D-14: the same tool name is reachable from MCP and the CLI (I-9), so audit rows
were indistinguishable by entry point. Every row now names its surface.

D-15: 170 tools are renamed in 2.0. A deny rule an operator wrote with a
pre-2.0 name must still refuse the renamed tool — including glob rules, whose
meaning would otherwise change silently (``*_delete`` matched ``vm_delete``
but not ``delete_vm``). Over-matching is the accepted direction: a rule that
now also refuses a same-named tool in another skill denies more, never less.
"""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path

import pytest

from vmware_policy import guard as guard_mod
from vmware_policy import renames, surface
from vmware_policy.audit import AuditEngine
from vmware_policy.guard import guard
from vmware_policy.policy import PolicyDenied, PolicyEngine

DESIGN_TABLE = Path(__file__).resolve().parents[2] / "design" / "tool-rename-2.0.json"


# ═══ D-14: surface ═══════════════════════════════════════════════════════════


@pytest.fixture
def engine(tmp_path, monkeypatch):
    eng = AuditEngine(db_path=tmp_path / "audit.db")
    monkeypatch.setattr(guard_mod, "get_engine", lambda: eng)
    return eng


def _rows(eng: AuditEngine) -> list[dict]:
    return eng.query(limit=100)


def test_explicit_surface_is_recorded(engine):
    guard_mod.audit_call("aiops", "delete_vm", surface="cli")
    assert _rows(engine)[0]["surface"] == "cli"


def test_surface_defaults_to_the_process_surface(engine):
    with surface.use_surface("mcp-https"):
        guard_mod.audit_call("aiops", "list_vms")
    assert _rows(engine)[0]["surface"] == "mcp-https"


def test_an_unknown_surface_is_refused_not_recorded(engine):
    with pytest.raises(ValueError):
        guard_mod.audit_call("aiops", "list_vms", surface="carrier-pigeon")


def test_mcp_decorator_records_mcp_stdio_by_default(engine):
    from vmware_policy.decorators import vmware_tool

    @vmware_tool(risk_level="low")
    def list_things() -> dict:
        return {"ok": True}

    list_things()
    assert _rows(engine)[0]["surface"] == "mcp-stdio"


def test_existing_database_gains_the_column_and_keeps_its_rows(tmp_path):
    db = tmp_path / "audit.db"
    conn = sqlite3.connect(db)
    conn.execute(
        "CREATE TABLE audit_log (id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT NOT NULL, "
        "skill TEXT NOT NULL, tool TEXT NOT NULL, params TEXT NOT NULL DEFAULT '{}', "
        "result TEXT NOT NULL DEFAULT '{}', status TEXT NOT NULL DEFAULT 'ok', "
        "duration_ms INTEGER NOT NULL DEFAULT 0, agent TEXT NOT NULL DEFAULT 'unknown', "
        "workflow_id TEXT NOT NULL DEFAULT '', user TEXT NOT NULL DEFAULT 'unknown', "
        "risk_level TEXT NOT NULL DEFAULT 'low')"
    )
    conn.execute("INSERT INTO audit_log (ts, skill, tool) VALUES ('t', 'aiops', 'vm_delete')")
    conn.commit()
    conn.close()

    eng = AuditEngine(db_path=db)
    eng.log(skill="aiops", tool="delete_vm", surface="cli")
    rows = eng.query(limit=10)
    assert {r["tool"]: r["surface"] for r in rows} == {"vm_delete": "", "delete_vm": "cli"}


def test_query_filters_by_surface(engine):
    guard_mod.audit_call("aiops", "delete_vm", surface="cli")
    guard_mod.audit_call("aiops", "delete_vm", surface="mcp-stdio")
    assert [r["surface"] for r in engine.query(surface="cli")] == ["cli"]


# ═══ D-15: renames ═══════════════════════════════════════════════════════════


def test_packaged_table_is_the_design_table():
    """The map policy ships must be the reviewed table, not a hand copy."""
    if not DESIGN_TABLE.exists():
        pytest.skip("design table lives in the family handbook checkout")
    design = {k: v for k, v in json.loads(DESIGN_TABLE.read_text(encoding="utf-8")).items()
              if not k.startswith("_")}
    assert renames.table() == design


def test_old_name_resolves_per_skill():
    assert renames.old_names("aiops", "delete_vm") == ("vm_delete",)
    # The same old name maps differently by skill: aiops renamed its
    # all-datastore scan, storage kept scan_datastore_images.
    assert renames.old_names("aiops", "scan_all_datastore_images") == ("scan_datastore_images",)
    assert renames.old_names("storage", "scan_datastore_images") == ()
    assert renames.old_names("vks", "list_vm_service_snapshots") == ("list_vm_snapshots",)
    assert renames.old_names("nsx_security", "list_dfw_policies") == ()


@pytest.fixture
def rules(tmp_path, monkeypatch):
    def make(text: str) -> PolicyEngine:
        p = tmp_path / "rules.yaml"
        p.write_text(text, encoding="utf-8")
        eng = PolicyEngine(rules_path=p)
        monkeypatch.setattr(guard_mod, "get_policy_engine", lambda: eng)
        return eng
    return make


def test_rule_with_old_name_still_refuses_the_renamed_tool(rules):
    rules('deny:\n  - name: no-delete\n    operations: ["vm_delete"]\n    reason: no\n')
    with pytest.raises(PolicyDenied):
        guard("aiops", "delete_vm")


def test_glob_rule_written_for_old_names_still_matches(rules):
    rules('deny:\n  - name: no-delete\n    operations: ["*_delete"]\n    reason: no\n')
    for skill, tool in [("aiops", "delete_vm"), ("aiops", "delete_cluster")]:
        with pytest.raises(PolicyDenied):
            guard(skill, tool)


def test_rule_with_new_name_matches(rules):
    rules('deny:\n  - name: no-delete\n    operations: ["delete_vm"]\n    reason: no\n')
    with pytest.raises(PolicyDenied):
        guard("aiops", "delete_vm")


def test_unrelated_tools_are_not_caught(rules):
    rules('deny:\n  - name: no-delete\n    operations: ["vm_delete"]\n    reason: no\n')
    assert guard("aiops", "create_vm").allowed
    assert guard("monitor", "list_virtual_machines").allowed


def test_every_old_name_in_the_table_still_refuses_its_new_name(rules):
    """I-14, exhaustively: one rule per old name, for every pair in the table."""
    for server, pairs in renames.table().items():
        skill = server.removeprefix("vmware-").replace("-", "_")
        for old, new in pairs.items():
            rules(f'deny:\n  - name: r\n    operations: ["{old}"]\n    reason: no\n')
            with pytest.raises(PolicyDenied):
                guard(skill, new)


def test_audit_query_by_old_name_finds_new_rows(engine):
    guard_mod.audit_call("aiops", "delete_vm", surface="cli")
    assert [r["tool"] for r in engine.query(tool="vm_delete")] == ["delete_vm"]


def test_cli_write_and_read_rows_say_cli(engine):
    from vmware_policy import audited, guarded

    @guarded("delete_vm", risk_level="high")
    def vm_delete(vm_name: str, target: str | None = None) -> None:
        return None

    @audited("list_vms")
    def vm_list(target: str | None = None) -> None:
        return None

    vm_delete("web-01")
    vm_list()
    assert {r["tool"]: r["surface"] for r in _rows(engine)} == {
        "delete_vm": "cli",
        "list_vms": "cli",
    }
