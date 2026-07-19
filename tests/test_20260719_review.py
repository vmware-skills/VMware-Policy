"""Regressions from the 2026-07-19 pre-release review.

Both defects live on the same fault line as the release itself: v1.8.0 is the
first version whose policy rules actually load, so it is the first version in
which an operator sits down and hand-writes ``rules.yaml``. Everything that
reads that file is therefore touching operator-authored input for the first
time, and neither of these paths was validating it.
"""

from __future__ import annotations

import pytest

from vmware_policy.policy import PolicyEngine


@pytest.fixture
def rules(tmp_path):
    def make(text: str) -> PolicyEngine:
        p = tmp_path / "rules.yaml"
        p.write_text(text)
        return PolicyEngine(rules_path=p)

    return make


# ---------------------------------------------------------------------------
# 1. A typo'd min_risk_level must not crash every call in the family
# ---------------------------------------------------------------------------

TYPOS = ["mediun", "MEDIUM", " Medium ", "hgih", "", None, 3]


@pytest.mark.parametrize("bad", ["mediun", "hgih", "critcal"])
def test_typo_in_tier_min_risk_does_not_crash(rules, bad):
    """`_risk_index` guarded the level declared in code; the level an operator
    types into rules.yaml still reached a raw `RISK_LEVELS.index()`. A single
    misspelling took down every tool call in all 12 skills with a bare
    ValueError naming neither the rule nor the file."""
    engine = rules(
        f'risk_tiers:\n  - name: t\n    operations: ["*"]\n'
        f"    min_risk_level: {bad}\n    tier: confirm\n"
    )
    decision = engine.required_approval_tier("vm_delete", env="prod", risk_level="high")
    assert decision.tier == "confirm"


@pytest.mark.parametrize("bad", ["mediun", "hgih", "critcal"])
def test_typo_in_deny_min_risk_does_not_crash(rules, bad):
    """Same fault on the deny path — the gate that refuses operations."""
    engine = rules(
        f'deny:\n  - name: d\n    operations: ["*"]\n'
        f"    min_risk_level: {bad}\n    reason: nope\n"
    )
    assert engine.check_allowed("vm_delete", env="prod", risk_level="high").allowed is False


@pytest.mark.parametrize("spelling", ["MEDIUM", "Medium", " medium ", "MeDiUm"])
def test_min_risk_level_is_case_and_whitespace_insensitive(rules, spelling):
    """`MEDIUM` is not a typo, it is how half of all operators write YAML. It
    must resolve to medium, not fall through to the unknown-value path."""
    engine = rules(
        f'risk_tiers:\n  - name: t\n    operations: ["*"]\n'
        f"    min_risk_level: {spelling}\n    tier: confirm\n"
    )
    # medium threshold: a low-risk call is below it and must not match.
    assert engine.required_approval_tier("vm_read", risk_level="low").tier == "none"
    assert engine.required_approval_tier("vm_delete", risk_level="high").tier == "confirm"


def test_unknown_min_risk_widens_the_rule_rather_than_narrowing_it(rules, caplog):
    """Direction matters. Reusing `_risk_index` here would map the unknown value
    to *critical*, so the rule would fire only on critical calls — a typo would
    silently switch a gate off. Index 0 makes it match everything instead: deny
    more, require a higher tier. `required_approval_tier` keeps the highest
    match, so widening can only raise the bar."""
    engine = rules(
        'risk_tiers:\n  - name: t\n    operations: ["*"]\n'
        "    min_risk_level: mediun\n    tier: confirm\n"
    )
    with caplog.at_level("WARNING"):
        assert engine.required_approval_tier("vm_read", risk_level="low").tier == "confirm"
    assert "mediun" in caplog.text
    assert "min_risk_level" in caplog.text


def test_a_permissive_tier_rule_cannot_downgrade_a_stricter_one(rules):
    """The widening above is only safe because tiers take the maximum. Pin that,
    so a future refactor to first-match-wins cannot turn a typo into an
    auto-approval."""
    engine = rules(
        'risk_tiers:\n'
        '  - name: loose\n    operations: ["*"]\n    min_risk_level: mediun\n    tier: none\n'
        '  - name: strict\n    operations: ["vm_delete"]\n    tier: dual\n'
    )
    assert engine.required_approval_tier("vm_delete", risk_level="high").tier == "dual"


# ---------------------------------------------------------------------------
# 2. `vmware-audit policy` must not report ENFORCED for a disabled switch
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("off_value", ["'false'", '"false"', "'no'", "'off'", "'0'"])
def test_policy_command_reports_off_not_enforced(tmp_path, off_value):
    """The command branched on truthiness while the engine parses three values,
    so the quoted string 'false' — the exact value RELEASE_NOTES tells operators
    was fixed — printed ENFORCED above an 'allowed' verdict for the same call.
    A status command that contradicts itself on one screen is worse than none."""
    from typer.testing import CliRunner

    from vmware_policy.cli import app
    from vmware_policy.policy import reset_policy_engine

    (tmp_path / "rules.yaml").write_text(f"require_declared_environment: {off_value}\n")
    reset_policy_engine()  # the engine is a process-wide singleton bound at first use
    result = CliRunner().invoke(
        app,
        ["policy", "--operation", "vm_delete", "--risk", "high"],
        env={"OPS_HOME": str(tmp_path)},
    )
    out = result.stdout
    assert "ENFORCED" not in out, f"{off_value} is off, but the command claimed ENFORCED"
    assert "OFF" in out, "an explicitly-disabled switch must say so, not stay silent"


def test_policy_command_still_reports_warn_and_enforce(tmp_path):
    """The three-valued rewrite must not lose the other two states."""
    from typer.testing import CliRunner

    from vmware_policy.cli import app
    from vmware_policy.policy import reset_policy_engine

    runner = CliRunner()
    for value, expected in (("warn", "WARN ONLY"), ("true", "ENFORCED")):
        home = tmp_path / value
        home.mkdir()
        (home / "rules.yaml").write_text(f"require_declared_environment: {value}\n")
        reset_policy_engine()  # rebind the singleton to this iteration's rules file
        result = runner.invoke(app, ["policy"], env={"OPS_HOME": str(home)})
        assert expected in result.stdout, f"{value} should report {expected}"
