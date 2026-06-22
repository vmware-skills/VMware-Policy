"""Tests for A3 — graduated-autonomy risk tiers.

Same operation, different approval requirement by environment / resource tag:
a prod-tagged destructive op needs a named approver; the dev equivalent runs
freely. Wires A2 (approved_by) + A3 (tier) into an enforceable gate.
"""

from __future__ import annotations

import os
import textwrap

import pytest

from vmware_policy.audit import AuditEngine
import vmware_policy.audit as audit_mod
import vmware_policy.policy as policy_mod
from vmware_policy.decorators import PolicyDenied, vmware_tool
from vmware_policy.policy import PolicyEngine


_RULES = textwrap.dedent(
    """
    risk_tiers:
      - name: prod-destructive
        environments: [production]
        min_risk_level: high
        tier: dual
        reason: production change control
      - name: tagged-prod
        tags: [prod, pci]
        min_risk_level: high
        tier: review
      - name: staging-high
        environments: [staging]
        min_risk_level: high
        tier: confirm
    """
)


@pytest.fixture
def engine(tmp_path):
    p = tmp_path / "rules.yaml"
    p.write_text(_RULES)
    return PolicyEngine(p)


@pytest.mark.unit
class TestTierResolution:
    def test_prod_high_risk_requires_dual(self, engine):
        d = engine.required_approval_tier("vm_delete", env="production", risk_level="high")
        assert d.tier == "dual"
        assert d.requires_approver

    def test_dev_same_op_is_none(self, engine):
        d = engine.required_approval_tier("vm_delete", env="dev", risk_level="high")
        assert d.tier == "none"
        assert not d.requires_approver

    def test_tag_match_resolves_review(self, engine):
        d = engine.required_approval_tier(
            "vm_delete", env="", risk_level="critical", params={"tags": ["pci"]}
        )
        assert d.tier == "review"

    def test_low_risk_below_threshold_is_none(self, engine):
        d = engine.required_approval_tier("vm_list", env="production", risk_level="low")
        assert d.tier == "none"

    def test_highest_tier_wins_when_multiple_match(self, engine):
        # production + pci tag matches both dual (env) and review (tag) → review.
        d = engine.required_approval_tier(
            "vm_delete", env="production", risk_level="high", params={"tags": ["pci"]}
        )
        assert d.tier == "review"

    def test_no_rules_is_none(self, tmp_path):
        eng = PolicyEngine(tmp_path / "absent.yaml")
        assert eng.required_approval_tier("vm_delete", env="production", risk_level="critical").tier == "none"


@pytest.mark.unit
class TestTierEnforcementThroughDecorator:
    @pytest.fixture(autouse=True)
    def _wire(self, tmp_path):
        audit_mod._engine = AuditEngine(tmp_path / "a.db")
        p = tmp_path / "rules.yaml"
        p.write_text(_RULES)
        policy_mod._engine = PolicyEngine(p)
        yield
        audit_mod._engine = None
        policy_mod._engine = None

    def test_prod_high_risk_denied_without_approver(self):
        @vmware_tool(risk_level="high")
        def vm_delete(target: str = "production") -> str:
            return "deleted"

        with pytest.raises(PolicyDenied) as ei:
            vm_delete()
        assert "approval" in str(ei.value).lower()
        assert "VMWARE_AUDIT_APPROVED_BY" in str(ei.value)

    def test_prod_high_risk_allowed_with_approver(self):
        os.environ["VMWARE_AUDIT_APPROVED_BY"] = "alice@corp"

        @vmware_tool(risk_level="high")
        def vm_delete(target: str = "production") -> str:
            return "deleted"

        assert vm_delete() == "deleted"
        row = audit_mod._engine.query(limit=1)[0]
        assert row["risk_tier"] == "dual"
        assert row["approved_by"] == "alice@corp"

    def test_dev_high_risk_runs_without_approver(self):
        @vmware_tool(risk_level="high")
        def vm_delete(target: str = "dev") -> str:
            return "deleted"

        assert vm_delete() == "deleted"
        assert audit_mod._engine.query(limit=1)[0]["risk_tier"] == "none"

    def test_confirm_tier_does_not_require_approver(self):
        @vmware_tool(risk_level="high")
        def vm_reconfigure(target: str = "staging") -> str:
            return "done"

        # 'confirm' tier is informational at the harness layer — not blocked.
        assert vm_reconfigure() == "done"
        assert audit_mod._engine.query(limit=1)[0]["risk_tier"] == "confirm"
