"""``@guarded`` routes a CLI command through the shared guard() + audit_call().

Unit tests for the CLI enforcement decorator (HLD §4.1). They assert the two
guarantees a CLI write needs — it is authorized through the same ``guard()`` the
MCP surface uses (I-3) and it emits exactly one audit row with a truthful status
(I-8) — plus that param/target binding matches ``@vmware_tool`` so one deny rule
scopes both surfaces identically.

``guard``/``audit_call`` are patched where ``cli_guard`` looked them up (it does
``from vmware_policy.guard import ...``), so no real ``~/.vmware`` DB is touched.
"""
from __future__ import annotations

import pytest

from vmware_policy import cli_guard
from vmware_policy.policy import PolicyDenied, PolicyResult


@pytest.fixture
def captured(monkeypatch):
    """Capture guard() calls and audit_call() rows; allow everything by default."""
    guard_calls: list[dict] = []
    audit_rows: list[dict] = []

    def fake_guard(skill, tool, params=None, *, risk_level="low", target=""):
        guard_calls.append(
            {"skill": skill, "tool": tool, "params": dict(params or {}),
             "risk_level": risk_level, "target": target}
        )
        return PolicyResult(allowed=True)

    monkeypatch.setattr(cli_guard, "guard", fake_guard)
    monkeypatch.setattr(cli_guard, "audit_call",
                        lambda skill, tool, **kw: audit_rows.append({"tool": tool, **kw}))
    return guard_calls, audit_rows


def test_guard_runs_before_body_then_one_ok_row(captured):
    guard_calls, audit_rows = captured
    ran: list[str] = []

    @cli_guard.guarded(risk_level="high")
    def vm_delete(vm_name, target=None):
        ran.append(vm_name)
        return "deleted"

    assert vm_delete("web-01", target="prod") == "deleted"
    assert ran == ["web-01"]
    assert len(guard_calls) == 1
    g = guard_calls[0]
    assert g["tool"] == "vm_delete" and g["target"] == "prod" and g["risk_level"] == "high"
    assert g["params"]["vm_name"] == "web-01"
    assert len(audit_rows) == 1
    assert audit_rows[0]["tool"] == "vm_delete" and audit_rows[0]["status"] == "ok"


def test_denied_records_denied_and_body_never_runs(captured, monkeypatch):
    _, audit_rows = captured
    ran: list[str] = []

    def deny(*a, **k):
        raise PolicyDenied(PolicyResult(allowed=False, rule="r1", reason="blocked in prod"))

    monkeypatch.setattr(cli_guard, "guard", deny)

    @cli_guard.guarded()
    def vm_delete(vm_name, target=None):
        ran.append(vm_name)
        return "deleted"

    with pytest.raises(PolicyDenied):
        vm_delete("web-01", target="prod")
    assert ran == []  # guard denied before the body
    assert audit_rows[-1]["status"] == "denied"


def test_body_error_audits_error_and_reraises(captured):
    _, audit_rows = captured

    @cli_guard.guarded()
    def vm_delete(vm_name, target=None):
        raise ValueError("boom")

    with pytest.raises(ValueError):
        vm_delete("web-01")
    assert audit_rows[-1]["status"] == "error"


def test_user_abort_records_rejected_not_error(captured):
    _, audit_rows = captured
    from click.exceptions import Abort

    @cli_guard.guarded()
    def vm_delete(vm_name, target=None):
        raise Abort()  # what a declined typer.confirm(abort=True) raises

    with pytest.raises(Abort):
        vm_delete("web-01")
    assert audit_rows[-1]["status"] == "rejected"


def test_clean_typer_exit_is_ok_nonzero_is_error(captured):
    _, audit_rows = captured
    from click.exceptions import Exit

    @cli_guard.guarded()
    def clean(vm_name, target=None):
        raise Exit(0)

    @cli_guard.guarded()
    def failed(vm_name, target=None):
        raise Exit(2)

    with pytest.raises(Exit):
        clean("web-01")
    assert audit_rows[-1]["status"] == "ok"
    with pytest.raises(Exit):
        failed("web-01")
    assert audit_rows[-1]["status"] == "error"


def test_sensitive_params_redacted_before_guard_and_audit(captured):
    guard_calls, audit_rows = captured

    @cli_guard.guarded(sensitive_params=["password"])
    def guest_exec(vm_name, password, target=None):
        return "ok"

    guest_exec("web-01", "hunter2", target="prod")
    assert guard_calls[0]["params"]["password"] == "***"
    assert audit_rows[0]["params"]["password"] == "***"
    assert audit_rows[0]["params"]["vm_name"] == "web-01"  # non-sensitive kept


def test_tool_name_defaults_to_func_name_and_can_override(captured):
    guard_calls, _ = captured

    @cli_guard.guarded()
    def vm_delete(vm_name, target=None):
        return "x"

    @cli_guard.guarded(tool="vm_power_on")
    def power_on_cmd(vm_name, target=None):
        return "x"

    vm_delete("a")
    power_on_cmd("b")
    assert guard_calls[0]["tool"] == "vm_delete"
    assert guard_calls[1]["tool"] == "vm_power_on"


def test_surface_symmetry_with_vmware_tool(monkeypatch):
    """I-3: for the same call, @guarded and @vmware_tool hand guard() the same
    params + target — because both bind through the shared reflection helpers."""
    from vmware_policy import decorators

    seen: list[tuple[dict, str]] = []

    def fake_guard(skill, tool, params=None, *, risk_level="low", target=""):
        seen.append((dict(params or {}), target))
        return PolicyResult(allowed=True)

    for mod in (cli_guard, decorators):
        monkeypatch.setattr(mod, "guard", fake_guard)
        monkeypatch.setattr(mod, "audit_call", lambda *a, **k: None)

    @cli_guard.guarded(risk_level="high")
    def vm_delete(vm_name, target=None):
        return "x"

    @decorators.vmware_tool(risk_level="high")
    def vm_delete_mcp(vm_name, target=None):
        return "x"

    vm_delete("web-01", target="prod")
    vm_delete_mcp("web-01", target="prod")

    assert seen[0][0] == seen[1][0], "params bound differently across surfaces"
    assert seen[0][1] == seen[1][1] == "prod", "target resolved differently"
