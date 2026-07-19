"""Writes require the target to declare an environment (fail-closed).

Policy has always been able to say "destructive operations in production need a
second person" — but ``env`` was derived from the *target's name*, so the rule
only fired if an operator happened to name their target the literal string in
the rule. Nobody names a target ``production``; they name it ``vcenter-prod``.
The control was configured and inert, the same failure class as the
leading-wildcard glob bug.

The fix inverts the default: a target declares its environment explicitly, and
an unlabelled target is treated as unknown rather than safe.

    targets:
      prod-vc01:
        host: vc01.corp.local
        environment: production   # <- declares which rules apply

Rolled out in two steps, because the end state refuses operations that work
today. The shipped baseline currently sets ``require_declared_environment:
warn`` — undeclared writes run but log a warning naming the fix. The next major
release ships ``true`` and refuses them. Both behaviours are tested here (the
``baseline`` and ``enforcing`` fixtures), so the enforcing release is a
one-word change to a path already under test rather than a leap.
"""

from __future__ import annotations

import pytest

from vmware_policy.environment import (
    resolve_environment,
    set_environment_resolver,
)
from vmware_policy.policy import PolicyEngine


@pytest.fixture(autouse=True)
def _clear_resolver():
    """Each test starts with no skill resolver registered."""
    set_environment_resolver(None)
    yield
    set_environment_resolver(None)


@pytest.fixture
def baseline(tmp_path):
    """The shipped baseline — currently in its warn-only migration setting."""
    return PolicyEngine(rules_path=tmp_path / "absent.yaml")


@pytest.fixture
def enforcing(tmp_path):
    """The same rules with the requirement switched on, as the next major
    release will ship it. Flipping one word is the whole of that release, so it
    is worth having the enforcing behaviour under test from now."""
    user = tmp_path / "rules.yaml"
    user.write_text(
        "require_declared_environment: true\n"
        "risk_tiers:\n"
        "  - name: prod-destructive\n"
        '    operations: ["*_delete", "delete_*"]\n'
        '    environments: ["production", "prod"]\n'
        "    tier: dual\n"
        "    reason: production change control\n"
    )
    return PolicyEngine(rules_path=user)


# ---------------------------------------------------------------------------
# Resolver registry
# ---------------------------------------------------------------------------


def test_unregistered_resolver_returns_undeclared():
    assert resolve_environment("prod-vc01") == ""


def test_registered_resolver_is_used():
    set_environment_resolver(lambda t: {"prod-vc01": "production"}.get(t))
    assert resolve_environment("prod-vc01") == "production"


def test_unknown_target_is_undeclared():
    set_environment_resolver(lambda t: {"prod-vc01": "production"}.get(t))
    assert resolve_environment("some-other-vc") == ""


def test_resolver_failure_is_undeclared_not_a_crash():
    """A broken config must not take the server down — but it must also not
    silently grant access, so the answer is 'undeclared' (which denies)."""

    def boom(_target: str) -> str:
        raise RuntimeError("config unreadable")

    set_environment_resolver(boom)
    assert resolve_environment("prod-vc01") == ""


def test_blank_declaration_counts_as_undeclared():
    set_environment_resolver(lambda t: "   ")
    assert resolve_environment("prod-vc01") == ""


# ---------------------------------------------------------------------------
# Enforcement: undeclared blocks writes, never reads
# ---------------------------------------------------------------------------


def test_write_against_undeclared_target_warns_but_runs(baseline):
    """Migration window: the shipped setting is warn, so nothing breaks yet."""
    result = baseline.check_allowed("vm_delete", env="", risk_level="critical")
    assert result.allowed is True
    assert result.rule == "undeclared_environment_warning"
    assert "future release will refuse" in result.reason.lower()


def test_write_against_undeclared_target_is_denied_when_enforcing(enforcing):
    result = enforcing.check_allowed("vm_delete", env="", risk_level="critical")
    assert result.allowed is False
    assert result.rule == "undeclared_environment"


def test_enforcing_mode_still_allows_reads(enforcing):
    assert enforcing.check_allowed("vm_info", env="", risk_level="low").allowed


def test_enforcing_mode_allows_declared_targets(enforcing):
    assert enforcing.check_allowed("vm_delete", env="lab", risk_level="critical").allowed


def test_read_against_undeclared_target_is_allowed(baseline):
    """Read-only work must keep working with no config changes at all."""
    for operation in ("list_alerts", "vm_info", "get_alarms"):
        assert baseline.check_allowed(operation, env="", risk_level="low").allowed


def test_denial_names_the_config_key_to_add(enforcing):
    """The error has to be actionable — an operator should not need the docs."""
    reason = enforcing.check_allowed("vm_delete", env="", risk_level="high").reason
    assert "environment" in reason
    assert "config" in reason.lower()


def test_denial_rule_is_identifiable(enforcing):
    result = enforcing.check_allowed("vm_delete", env="", risk_level="high")
    assert "environment" in result.rule


@pytest.mark.parametrize("risk", ["medium", "high", "critical"])
def test_every_write_risk_level_is_gated(enforcing, risk):
    assert enforcing.check_allowed("vm_power_off", env="", risk_level=risk).allowed is False


@pytest.mark.parametrize("risk", ["medium", "high", "critical"])
def test_every_write_risk_level_warns_during_migration(baseline, risk):
    result = baseline.check_allowed("vm_power_off", env="", risk_level=risk)
    assert result.allowed is True
    assert result.rule == "undeclared_environment_warning"


# ---------------------------------------------------------------------------
# Enforcement: declaring an environment unblocks work
# ---------------------------------------------------------------------------


def test_declared_non_production_allows_writes(baseline):
    assert baseline.check_allowed("vm_delete", env="lab", risk_level="critical").allowed


def test_declared_non_production_needs_no_approver(baseline):
    decision = baseline.required_approval_tier("vm_delete", env="lab", risk_level="critical")
    assert decision.requires_approver is False


def test_declared_production_allows_but_requires_two_people(baseline):
    assert baseline.check_allowed("vm_delete", env="production", risk_level="critical").allowed
    decision = baseline.required_approval_tier(
        "vm_delete", env="production", risk_level="critical"
    )
    assert decision.tier == "dual"
    assert decision.requires_approver is True


def test_production_ordinary_write_does_not_need_two_people(baseline):
    """Only irreversible work needs a second person — routine writes do not,
    or the gate becomes noise operators learn to bypass."""
    decision = baseline.required_approval_tier(
        "vm_reconfigure", env="production", risk_level="medium"
    )
    assert decision.requires_approver is False


# ---------------------------------------------------------------------------
# Opting out
# ---------------------------------------------------------------------------


def test_own_rules_file_opts_out_entirely(tmp_path):
    """Writing rules.yaml replaces the baseline — including this requirement."""
    user = tmp_path / "rules.yaml"
    user.write_text("risk_tiers: []\n")
    engine = PolicyEngine(rules_path=user)
    assert engine.check_allowed("vm_delete", env="", risk_level="critical").allowed


def test_requirement_can_be_switched_off_explicitly(tmp_path):
    user = tmp_path / "rules.yaml"
    user.write_text("require_declared_environment: false\n")
    engine = PolicyEngine(rules_path=user)
    result = engine.check_allowed("vm_delete", env="", risk_level="critical")
    assert result.allowed is True
    assert result.rule != "undeclared_environment_warning"
