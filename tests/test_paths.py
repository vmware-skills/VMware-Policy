"""Tests for vmware_policy.paths — OPS_HOME parameterization (direction B).

Proves the harness state dir is relocatable so a non-VMware skill can reuse the
same audit/policy/budget/undo machinery, while defaulting to ~/.vmware for
backward compatibility.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from vmware_policy.audit import AuditEngine
from vmware_policy.paths import ops_home, ops_path


@pytest.mark.unit
class TestOpsHome:
    def test_default_is_vmware_home(self):
        os.environ.pop("OPS_HOME", None)
        assert ops_home() == Path("~/.vmware").expanduser()

    def test_ops_home_override(self, tmp_path):
        os.environ["OPS_HOME"] = str(tmp_path / "alt-home")
        try:
            assert ops_home() == (tmp_path / "alt-home")
            assert ops_path("audit.db") == (tmp_path / "alt-home" / "audit.db")
        finally:
            os.environ.pop("OPS_HOME", None)

    def test_engine_default_path_follows_ops_home(self, tmp_path):
        os.environ["OPS_HOME"] = str(tmp_path / "h")
        try:
            engine = AuditEngine()  # no explicit path → resolves via ops_home()
            assert str(tmp_path / "h") in str(engine._path)
            engine.log(skill="other", tool="vm_list")
            assert engine.query(limit=1)[0]["skill"] == "other"
        finally:
            os.environ.pop("OPS_HOME", None)

    def test_default_db_override_hook_backcompat(self, tmp_path):
        """Monkeypatching audit._DEFAULT_DB still redirects the default DB.

        Downstream skills (e.g. vmware-harden tests) patch this constant; the
        OPS_HOME refactor must not break that override path."""
        import vmware_policy.audit as audit_mod

        saved = audit_mod._DEFAULT_DB
        audit_mod._DEFAULT_DB = tmp_path / "patched.db"
        try:
            engine = AuditEngine()
            assert engine._path == tmp_path / "patched.db"
        finally:
            audit_mod._DEFAULT_DB = saved


@pytest.mark.unit
class TestBudgetEnvAlias:
    def test_ops_prefix_alias_for_budget(self):
        import vmware_policy.budget as bm

        os.environ.pop("VMWARE_RUNAWAY_MAX", None)
        os.environ["OPS_RUNAWAY_MAX"] = "2"
        try:
            bm.reset_budget()
            b = bm.get_budget()
            from vmware_policy.budget import BudgetExceeded

            b.check_and_record("t", {"a": 1})
            b.check_and_record("t", {"a": 1})
            with pytest.raises(BudgetExceeded):
                b.check_and_record("t", {"a": 1})
        finally:
            os.environ.pop("OPS_RUNAWAY_MAX", None)
            bm.reset_budget()
