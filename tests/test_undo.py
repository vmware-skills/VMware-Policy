"""Tests for A1 — undo-token primitive.

A write tool declares its inverse via @vmware_tool(undo=...). On success the
inverse descriptor is recorded and the result gains an _undo_id. Recording only
— execution is vmware-pilot's job.
"""

from __future__ import annotations

import pytest

from vmware_policy.audit import AuditEngine
import vmware_policy.audit as audit_mod
import vmware_policy.policy as policy_mod
import vmware_policy.undo as undo_mod
from vmware_policy.decorators import vmware_tool


@pytest.fixture(autouse=True)
def _fresh(tmp_path):
    audit_mod._engine = AuditEngine(tmp_path / "a.db")
    policy_mod._engine = None
    yield
    audit_mod._engine = None
    policy_mod._engine = None


@pytest.mark.unit
class TestUndoStore:
    def test_record_and_get(self):
        store = undo_mod.get_undo_store()
        uid = store.record(
            skill="aiops", tool="vm_power_off",
            undo_descriptor={"tool": "vm_power_on", "params": {"vm_name": "web-01"}},
            orig_params={"vm_name": "web-01"},
        )
        assert uid
        rec = store.get(uid)
        assert rec["undo_tool"] == "vm_power_on"
        assert "web-01" in rec["undo_params"]
        assert rec["status"] == "recorded"

    def test_descriptor_without_tool_not_recorded(self):
        store = undo_mod.get_undo_store()
        assert store.record(skill="s", tool="t", undo_descriptor={"params": {}}) is None

    def test_mark_status(self):
        store = undo_mod.get_undo_store()
        uid = store.record(skill="s", tool="t", undo_descriptor={"tool": "u"})
        assert store.mark(uid, "applied")
        assert store.get(uid)["status"] == "applied"

    def test_list_filter(self):
        store = undo_mod.get_undo_store()
        store.record(skill="s", tool="t1", undo_descriptor={"tool": "u1"})
        uid2 = store.record(skill="s", tool="t2", undo_descriptor={"tool": "u2"})
        store.mark(uid2, "applied")
        assert len(store.list(status="recorded")) == 1
        assert len(store.list()) == 2


@pytest.mark.unit
class TestUndoThroughDecorator:
    def test_successful_write_records_inverse_and_attaches_id(self):
        @vmware_tool(
            risk_level="medium",
            undo=lambda p, r: {"tool": "vm_power_on", "params": {"vm_name": p["vm_name"]}},
        )
        def vm_power_off(vm_name: str, target: str = "") -> dict:
            return {"vm_name": vm_name, "power": "off"}

        result = vm_power_off(vm_name="web-01")
        assert "_undo_id" in result
        rec = undo_mod.get_undo_store().get(result["_undo_id"])
        assert rec["undo_tool"] == "vm_power_on"
        assert "web-01" in rec["undo_params"]

    def test_undo_returning_none_records_nothing(self):
        @vmware_tool(undo=lambda p, r: None)  # delete-vm has no safe inverse
        def vm_delete(vm_name: str, target: str = "") -> dict:
            return {"deleted": vm_name}

        result = vm_delete(vm_name="scratch")
        assert "_undo_id" not in result
        assert undo_mod.get_undo_store().list() == []

    def test_failed_call_records_no_undo(self):
        @vmware_tool(undo=lambda p, r: {"tool": "vm_power_on", "params": {}})
        def vm_power_off(vm_name: str, target: str = "") -> dict:
            raise RuntimeError("boom")

        with pytest.raises(RuntimeError):
            vm_power_off(vm_name="x")
        assert undo_mod.get_undo_store().list() == []  # undo only on success

    def test_broken_undo_callable_does_not_fail_call(self):
        @vmware_tool(undo=lambda p, r: 1 / 0)  # raises
        def vm_power_off(vm_name: str, target: str = "") -> dict:
            return {"ok": True}

        # The call still succeeds; the undo failure is swallowed.
        assert vm_power_off(vm_name="x") == {"ok": True}

    def test_no_undo_declared_is_noop(self):
        @vmware_tool(risk_level="low")
        def vm_list(target: str = "") -> list:
            return ["a"]

        assert vm_list() == ["a"]
        assert undo_mod.get_undo_store().list() == []
