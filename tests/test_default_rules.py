"""The shipped policy baseline must actually load, and must not break anyone.

Until now the approval engine was fully built and fully inert: it reads only
``~/.vmware/rules.yaml``, and a fresh install has no such file, so
``check_allowed`` short-circuited on ``no_rules`` and ``required_approval_tier``
returned ``none`` for every operation. ``rules_default.yaml`` shipped in the
package as a commented-out template that no engine ever read. Every write tool
on every install — ``vm_delete``, ``delete_segment``, ``cluster_delete`` — ran
with no approval gate at all.

These tests pin the fix and, just as importantly, pin its blast radius:

* the packaged baseline loads when the operator has written no rules;
* a user file still wins completely — the baseline is a fallback, not a merge;
* read-only work is never gated;
* writes require the target to declare an environment (see
  test_declared_environment.py for that half), and once declared, only
  production additionally requires a named approver.
"""

from __future__ import annotations

import textwrap

import pytest

from vmware_policy.policy import DEFAULT_RULES_PATH, PolicyEngine


@pytest.fixture
def no_user_rules(tmp_path):
    """An engine whose user rules file does not exist."""
    return PolicyEngine(rules_path=tmp_path / "absent.yaml")


# ---------------------------------------------------------------------------
# The baseline loads
# ---------------------------------------------------------------------------


def test_packaged_baseline_file_exists():
    assert DEFAULT_RULES_PATH.exists(), "rules_default.yaml must ship with the package"


def test_missing_user_rules_falls_back_to_baseline(no_user_rules):
    """Previously this produced empty rules and a blanket allow."""
    assert no_user_rules.active_rules_source() == "packaged-default"
    assert no_user_rules._rules, "baseline must be non-empty or it is still inert"


def test_baseline_defines_risk_tiers(no_user_rules):
    assert no_user_rules._rules.get("risk_tiers"), "baseline must define risk_tiers"


def test_user_file_wins_entirely(tmp_path):
    """A user file replaces the baseline — no merging, no surprise inheritance."""
    user = tmp_path / "rules.yaml"
    user.write_text("risk_tiers: []\n")
    engine = PolicyEngine(rules_path=user)
    assert engine.active_rules_source() == "user"
    assert engine.required_approval_tier("vm_delete", risk_level="critical").tier == "none"


def test_unreadable_user_file_does_not_silently_fall_back(tmp_path):
    """A corrupt user file must not quietly downgrade to the baseline.

    Falling back would apply rules the operator never wrote while their real
    ones are broken — the wrong kind of surprise for a policy engine.
    """
    user = tmp_path / "rules.yaml"
    user.write_text("risk_tiers: [ unclosed\n")
    engine = PolicyEngine(rules_path=user)
    assert engine.active_rules_source() == "user-invalid"
    assert engine.required_approval_tier("vm_delete", risk_level="critical").tier == "none"


# ---------------------------------------------------------------------------
# Blast radius: the baseline must not block anything that worked before
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "operation",
    ["vm_delete", "cluster_delete", "delete_segment", "vm_power_off", "vm_clone"],
)
def test_baseline_denies_nothing_once_the_environment_is_declared(no_user_rules, operation):
    """The baseline ships no deny rules — declaring an environment is the only
    precondition it adds, and it is not a blanket block."""
    assert no_user_rules.check_allowed(operation, env="lab", risk_level="critical").allowed


@pytest.mark.parametrize(
    "operation",
    ["vm_delete", "cluster_delete", "delete_segment", "delete_dfw_policy"],
)
def test_destructive_ops_outside_production_need_no_approver(no_user_rules, operation):
    """Only production demands a second person; lab and staging stay frictionless
    or the gate becomes noise operators learn to route around."""
    decision = no_user_rules.required_approval_tier(operation, env="lab", risk_level="critical")
    assert decision.requires_approver is False


def test_read_operations_stay_at_tier_none(no_user_rules):
    for operation in ("list_alerts", "vm_info", "get_alarms"):
        assert no_user_rules.required_approval_tier(operation, risk_level="low").tier == "none"


# ---------------------------------------------------------------------------
# The baseline is actually protective where it is meant to be
# ---------------------------------------------------------------------------


def test_writes_are_recorded_at_confirm_tier(no_user_rules):
    """Medium+ writes get a tier so the audit row carries it — without blocking."""
    decision = no_user_rules.required_approval_tier("vm_power_off", risk_level="medium")
    assert decision.tier == "confirm"
    assert decision.requires_approver is False


def test_destructive_op_in_production_requires_two_people(no_user_rules):
    decision = no_user_rules.required_approval_tier(
        "vm_delete", env="production", risk_level="critical"
    )
    assert decision.tier == "dual"
    assert decision.requires_approver is True


def test_highest_matching_tier_wins(no_user_rules):
    """A prod destructive op must not be downgraded by the looser write rule."""
    decision = no_user_rules.required_approval_tier(
        "cluster_delete", env="production", risk_level="critical"
    )
    assert decision.tier == "dual"


def test_non_production_environment_does_not_require_approver(no_user_rules):
    decision = no_user_rules.required_approval_tier(
        "vm_delete", env="staging", risk_level="critical"
    )
    assert decision.requires_approver is False


def test_baseline_rule_carries_a_reason(no_user_rules):
    """Denials must teach, not just refuse."""
    decision = no_user_rules.required_approval_tier(
        "vm_delete", env="production", risk_level="critical"
    )
    assert decision.reason


# ---------------------------------------------------------------------------
# Hot-reload still works across the fallback boundary
# ---------------------------------------------------------------------------


def test_creating_a_user_file_takes_over_from_the_baseline(tmp_path):
    user = tmp_path / "rules.yaml"
    engine = PolicyEngine(rules_path=user)
    assert engine.active_rules_source() == "packaged-default"

    user.write_text(
        textwrap.dedent(
            """
            risk_tiers:
              - name: everything-needs-review
                operations: ["*"]
                tier: review
            """
        )
    )
    decision = engine.required_approval_tier("vm_info", risk_level="low")
    assert decision.tier == "review"
    assert engine.active_rules_source() == "user"


# ---------------------------------------------------------------------------
# Environments match by glob, like operations do
# ---------------------------------------------------------------------------


def test_environment_patterns_support_globs(tmp_path):
    """`env` comes from the tool's `target` parameter — a config target name
    like 'vcenter-prod', never the literal word 'production'. Exact-only
    matching made environment-scoped rules unfireable in practice, the same
    class of silently-inert rule as the leading-wildcard operations bug."""
    user = tmp_path / "rules.yaml"
    user.write_text(
        "risk_tiers:\n"
        "  - name: prod-deletes\n"
        '    operations: ["*_delete"]\n'
        '    environments: ["*-prod", "production"]\n'
        "    tier: dual\n"
    )
    engine = PolicyEngine(rules_path=user)
    for target in ("vcenter-prod", "production"):
        assert engine.required_approval_tier("vm_delete", env=target).tier == "dual", target
    for target in ("vcenter-lab", "staging"):
        assert engine.required_approval_tier("vm_delete", env=target).tier == "none", target


def test_exact_environment_names_still_match(tmp_path):
    user = tmp_path / "rules.yaml"
    user.write_text(
        "risk_tiers:\n"
        "  - name: prod\n"
        '    operations: ["*"]\n'
        '    environments: ["production"]\n'
        "    tier: review\n"
    )
    engine = PolicyEngine(rules_path=user)
    assert engine.required_approval_tier("anything", env="production").tier == "review"
    assert engine.required_approval_tier("anything", env="prod").tier == "none"
