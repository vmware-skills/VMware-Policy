"""Tests for A2 — audit accountability fields (rationale / approved_by / risk_tier).

SOC2 / 等保 require "who authorized this change, and why". These fields carry
that trail; old audit.db files must migrate in place without losing rows.
"""

from __future__ import annotations

import os
import sqlite3

import pytest

from vmware_policy.audit import AuditEngine
import vmware_policy.audit as audit_mod
import vmware_policy.policy as policy_mod
from vmware_policy.decorators import vmware_tool


@pytest.fixture(autouse=True)
def _fresh_singletons(tmp_path):
    audit_mod._engine = AuditEngine(tmp_path / "a.db")
    policy_mod._engine = None
    yield audit_mod._engine
    audit_mod._engine = None
    policy_mod._engine = None


@pytest.mark.unit
class TestAccountabilityColumns:
    def test_new_db_has_accountability_columns(self, _fresh_singletons, tmp_path):
        conn = sqlite3.connect(str(tmp_path / "a.db"))
        cols = {r[1] for r in conn.execute("PRAGMA table_info(audit_log)")}
        conn.close()
        assert {"rationale", "approved_by", "risk_tier"} <= cols

    def test_log_persists_accountability(self, _fresh_singletons):
        _fresh_singletons.log(
            skill="aiops", tool="vm_delete",
            rationale="decommission per ticket OPS-42",
            approved_by="alice@corp",
            risk_tier="dual",
        )
        row = _fresh_singletons.query(limit=1)[0]
        assert row["rationale"] == "decommission per ticket OPS-42"
        assert row["approved_by"] == "alice@corp"
        assert row["risk_tier"] == "dual"

    def test_decorator_sources_rationale_from_env(self, _fresh_singletons):
        os.environ["VMWARE_AUDIT_RATIONALE"] = "scheduled maintenance"
        os.environ["VMWARE_AUDIT_APPROVED_BY"] = "bob@corp"

        @vmware_tool(risk_level="high")
        def vm_power_off(target: str = "prod") -> str:
            return "off"

        vm_power_off()
        row = _fresh_singletons.query(limit=1)[0]
        assert row["rationale"] == "scheduled maintenance"
        assert row["approved_by"] == "bob@corp"


@pytest.mark.unit
class TestMigration:
    def test_old_db_migrates_in_place(self, tmp_path):
        """A pre-existing audit_log without the new columns gains them and
        keeps its rows."""
        db = tmp_path / "legacy.db"
        conn = sqlite3.connect(str(db))
        conn.execute(
            "CREATE TABLE audit_log ("
            "id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT NOT NULL, "
            "skill TEXT NOT NULL, tool TEXT NOT NULL, params TEXT DEFAULT '{}', "
            "result TEXT DEFAULT '{}', status TEXT DEFAULT 'ok', "
            "duration_ms INTEGER DEFAULT 0, agent TEXT DEFAULT 'unknown', "
            "workflow_id TEXT DEFAULT '', user TEXT DEFAULT 'unknown', "
            "risk_level TEXT DEFAULT 'low')"
        )
        conn.execute(
            "INSERT INTO audit_log (ts, skill, tool) VALUES ('2026-01-01T00:00:00', 's', 't')"
        )
        conn.commit()
        conn.close()

        # Opening with the current engine triggers _migrate.
        engine = AuditEngine(db)
        cols = {r[1] for r in sqlite3.connect(str(db)).execute("PRAGMA table_info(audit_log)")}
        assert {"rationale", "approved_by", "risk_tier"} <= cols

        rows = engine.query(limit=10)
        assert len(rows) == 1  # legacy row preserved
        assert rows[0]["rationale"] == ""  # backfilled with default

        # And new writes work against the migrated table.
        engine.log(skill="s2", tool="t2", rationale="why", approved_by="me")
        assert engine.query(limit=1)[0]["approved_by"] == "me"

    def test_migrate_is_idempotent(self, tmp_path):
        db = tmp_path / "x.db"
        AuditEngine(db)
        AuditEngine(db)  # second open must not raise on ALTER of existing cols
        engine = AuditEngine(db)
        engine.log(skill="s", tool="t")
        assert engine.query(limit=1)[0]["tool"] == "t"
