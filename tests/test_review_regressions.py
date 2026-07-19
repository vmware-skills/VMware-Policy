"""Regressions from the 2026-07-18 pre-release review (Fable code review).

Eight defects, every one confirmed by executable repro before being fixed, and
most of them the same disease this release exists to cure: controls that look
configured and do something else. Each test names the failure it pins.
"""

from __future__ import annotations

import pathlib
import subprocess
import sys

import pytest

from vmware_policy.policy import PolicyEngine
from vmware_policy.readonly import read_only_enabled


@pytest.fixture
def rules(tmp_path):
    def make(text: str) -> PolicyEngine:
        p = tmp_path / "rules.yaml"
        p.write_text(text)
        return PolicyEngine(rules_path=p)

    return make


# ---------------------------------------------------------------------------
# 1. warn mode must not bypass deny rules or the maintenance window
# ---------------------------------------------------------------------------


def test_warn_mode_does_not_bypass_unscoped_deny(rules):
    """An unconditional deny is a hard rule; the migration setting must not
    downgrade it to a log line on exactly the unlabelled targets it protects."""
    engine = rules(
        "require_declared_environment: warn\n"
        "deny:\n"
        "  - name: never-clean-slate\n"
        '    operations: ["vm_clean_slate"]\n'
        "    reason: hard-deny\n"
    )
    result = engine.check_allowed("vm_clean_slate", env="", risk_level="critical")
    assert result.allowed is False
    assert result.rule == "never-clean-slate"


def test_warn_mode_still_warns_when_nothing_denies(rules):
    engine = rules("require_declared_environment: warn\n")
    result = engine.check_allowed("vm_delete", env="", risk_level="critical")
    assert result.allowed is True
    assert result.rule == "undeclared_environment_warning"


# ---------------------------------------------------------------------------
# 2. deny rules: env scoping must match tier semantics (glob + no-empty-match)
# ---------------------------------------------------------------------------


def test_env_scoped_deny_does_not_match_undeclared_targets(rules):
    """env="" means 'environment unknown'. A production-only freeze firing on
    every unlabelled lab target is an availability regression, not a policy."""
    engine = rules(
        "deny:\n"
        "  - name: prod-freeze\n"
        '    operations: ["vm_delete"]\n'
        '    environments: ["production"]\n'
        "    reason: prod frozen\n"
    )
    assert engine.check_allowed("vm_delete", env="", risk_level="critical").allowed


def test_env_scoped_deny_supports_globs_like_tiers_do(rules):
    """The glob upgrade must land in BOTH matchers — a deny written 'prod*'
    that silently never fires is the inert-control failure class itself."""
    engine = rules(
        "deny:\n"
        "  - name: prod-freeze\n"
        '    operations: ["vm_delete"]\n'
        '    environments: ["prod*"]\n'
        "    reason: prod frozen\n"
    )
    assert engine.check_allowed("vm_delete", env="production", risk_level="critical").allowed is False
    assert engine.check_allowed("vm_delete", env="lab", risk_level="critical").allowed is True


# ---------------------------------------------------------------------------
# 3. require_declared_environment: strict parsing, loud on nonsense
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("value", ['"false"', '"off"', '"no"', '"0"'])
def test_quoted_falsy_strings_switch_the_requirement_off(rules, value):
    """YAML-quoted 'false' used to be truthy → the ENFORCE branch: the switch
    did the opposite of its label with zero diagnostics."""
    engine = rules(f"require_declared_environment: {value}\n")
    result = engine.check_allowed("vm_delete", env="", risk_level="critical")
    assert result.allowed is True
    assert result.rule != "undeclared_environment"
    assert result.rule != "undeclared_environment_warning"


def test_unrecognised_requirement_value_fails_closed_and_loud(rules, caplog):
    """A typo ('warm') enforces — the restrictive reading — and says so, matching
    how readonly._parse treats an unparseable switch."""
    engine = rules("require_declared_environment: warm\n")
    with caplog.at_level("WARNING"):
        result = engine.check_allowed("vm_delete", env="", risk_level="critical")
    assert result.allowed is False
    assert any("warm" in r.message for r in caplog.records)


# ---------------------------------------------------------------------------
# 4. unknown risk_level must not raise out of check_allowed
# ---------------------------------------------------------------------------


def test_unknown_risk_level_is_treated_as_critical_not_a_crash(rules):
    """`vmware-audit policy --risk hgih` used to traceback with ValueError.
    Unknown risk reads as the most restrictive level instead."""
    engine = rules("require_declared_environment: true\n")
    result = engine.check_allowed("vm_delete", env="", risk_level="hgih")
    assert result.allowed is False  # treated >= medium → gated
    result = engine.check_allowed("vm_info", env="lab", risk_level="hgih")
    assert result.allowed is True  # nothing else denies it


# ---------------------------------------------------------------------------
# 5. empty-string env var means "unset", not "explicitly off"
# ---------------------------------------------------------------------------


def test_blank_env_var_does_not_override_config_read_only(monkeypatch):
    """'env': {'VMWARE_READ_ONLY': ''} is a template leftover, not a decision.
    It used to read as explicit False and silently defeat read_only: true in
    config — a fail-open path in a fail-closed module."""
    monkeypatch.delenv("VMWARE_ARIA_READ_ONLY", raising=False)
    monkeypatch.setenv("VMWARE_READ_ONLY", "")
    assert read_only_enabled("vmware-aria", config_flag=True) is True
    assert read_only_enabled("vmware-aria", config_flag=False) is False


# ---------------------------------------------------------------------------
# 6. the CLI's policy command must be registered under python -m execution
# ---------------------------------------------------------------------------


def test_policy_command_registers_before_main_guard():
    """The command was appended AFTER `if __name__ == "__main__": app()`, so
    `python -m vmware_policy.cli policy` ran the app before the command
    existed. Pin the module layout: no code after the __main__ guard."""
    src = pathlib.Path("vmware_policy/cli.py").read_text()
    guard = src.index('if __name__ == "__main__"')
    assert "def policy(" in src[:guard], "policy command must be defined before the __main__ guard"
    tail = src[guard:].splitlines()[2:]
    assert not any(line.startswith(("def ", "@app.")) for line in tail), (
        "nothing may be defined after the __main__ guard — it would not exist "
        "under script execution"
    )


def test_policy_command_works_via_module_execution():
    proc = subprocess.run(
        [sys.executable, "-m", "vmware_policy.cli", "policy"],
        capture_output=True, text=True, timeout=60,
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "Rules in force" in proc.stdout


# ---------------------------------------------------------------------------
# 7. pattern engine keys by target NAME; policy scopes by environment
# ---------------------------------------------------------------------------


def test_pattern_engine_receives_target_name_not_environment(tmp_path, monkeypatch):
    """Rate limits and circuit breakers are per-target. Feeding them the
    resolved environment pools every 'production' vCenter into one counter —
    one flaky target trips the breaker for all of them."""
    import vmware_policy.audit as audit_mod
    import vmware_policy.patterns as patterns_mod
    from vmware_policy.audit import AuditEngine
    from vmware_policy.decorators import vmware_tool
    from vmware_policy.environment import set_environment_resolver

    audit_mod._engine = AuditEngine(tmp_path / "a.db")
    set_environment_resolver(lambda t: "production")

    seen: list[str] = []
    real_engine = patterns_mod.get_pattern_engine()
    monkeypatch.setattr(
        real_engine, "match",
        lambda skill, tool, target="", params=None: (seen.append(target), None)[1],
    )

    @vmware_tool(risk_level="low")
    def vm_info(target: str = "") -> str:
        return "ok"

    vm_info(target="prod-vc01")
    audit_mod._engine = None
    set_environment_resolver(None)
    assert seen == ["prod-vc01"], (
        f"pattern engine got {seen} — must be the target name, not the environment"
    )


# ---------------------------------------------------------------------------
# 8. kubeconfig tools are force-classified as writes
# ---------------------------------------------------------------------------


def test_kubeconfig_tools_are_in_force_write():
    """Both VKS kubeconfig tools are [READ] + readOnlyHint:True yet write a
    session-token kubeconfig to a model-supplied local path — the exact shape
    vm_guest_download was excepted for. The exception list drifted within the
    release that introduced it."""
    from vmware_policy.readonly import FORCE_WRITE

    assert "vm_guest_download" in FORCE_WRITE
    assert "get_tkc_kubeconfig" in FORCE_WRITE
    assert "get_supervisor_kubeconfig" in FORCE_WRITE
