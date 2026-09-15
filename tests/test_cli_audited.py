"""``@audited`` and ``@cli_local`` — the CLI read and local counterparts of ``@guarded``.

HLD §4.1 / §8.1 / I-8 / I-9 (amended 2026-09-15). No CLI read wrote
``~/.vmware/audit.db``: a live ``vmware-aria resource list`` left the Aria row
count at 86 while the same read over MCP made it 87. A read that reaches a remote
system must pass the same ``guard()`` as its MCP twin and leave one truthful row;
a command that reaches nothing remote must say so, with a reason.

``guard``/``audit_call`` are patched where ``cli_guard`` looks them up, so no real
``~/.vmware`` database is touched.
"""
from __future__ import annotations

import inspect

import pytest
from click.exceptions import Exit

from vmware_policy import cli_guard
from vmware_policy.policy import PolicyDenied, PolicyResult


@pytest.fixture
def captured(monkeypatch):
    guard_calls: list[dict] = []
    audit_rows: list[dict] = []

    def fake_guard(skill, tool, params=None, *, risk_level="low", target=""):
        guard_calls.append({"tool": tool, "params": dict(params or {}), "risk_level": risk_level, "target": target})
        return PolicyResult(allowed=True)

    monkeypatch.setattr(cli_guard, "guard", fake_guard)
    monkeypatch.setattr(cli_guard, "audit_call", lambda skill, tool, **kw: audit_rows.append({"tool": tool, **kw}))
    return guard_calls, audit_rows


def test_a_read_passes_guard_and_writes_one_ok_row_under_its_mcp_name(captured):
    guard_calls, audit_rows = captured

    @cli_guard.audited("list_resources")
    def resource_list(kind="VirtualMachine", target=None):
        return "rows"

    assert resource_list(kind="HostSystem", target="lab") == "rows"
    assert [(g["tool"], g["risk_level"], g["target"]) for g in guard_calls] == [("list_resources", "low", "lab")]
    assert len(audit_rows) == 1
    row = audit_rows[0]
    assert row["tool"] == "list_resources" and row["status"] == "ok"
    assert row["params"]["kind"] == "HostSystem"


def test_the_tool_name_defaults_to_the_function_name(captured):
    _, audit_rows = captured

    @cli_guard.audited()
    def scan_logs(host=None):
        return None

    scan_logs()
    assert audit_rows[0]["tool"] == "scan_logs"


def test_a_denied_read_never_runs_and_is_recorded_denied(captured, monkeypatch):
    _, audit_rows = captured
    ran: list[str] = []

    def deny(*a, **k):
        raise PolicyDenied(PolicyResult(allowed=False, rule="r1", reason="no reads from prod"))

    monkeypatch.setattr(cli_guard, "guard", deny)

    @cli_guard.audited("list_resources")
    def resource_list(target=None):
        ran.append("x")

    with pytest.raises(PolicyDenied):
        resource_list(target="prod")
    assert ran == []
    assert [r["status"] for r in audit_rows] == ["denied"]


def test_a_failing_read_records_error_and_reraises(captured):
    _, audit_rows = captured

    @cli_guard.audited("get_alarms")
    def health_alarms(target=None):
        raise ConnectionError("vcenter unreachable")

    with pytest.raises(ConnectionError):
        health_alarms()
    assert [r["status"] for r in audit_rows] == ["error"]
    assert "unreachable" in str(audit_rows[0]["result"])


@pytest.mark.parametrize(("code", "status"), [(0, "ok"), (1, "error")])
def test_a_typer_exit_is_recorded_by_its_code(captured, code, status):
    _, audit_rows = captured

    @cli_guard.audited("list_alerts")
    def alert_list():
        raise Exit(code)

    with pytest.raises(Exit):
        alert_list()
    assert [r["status"] for r in audit_rows] == [status]


def test_it_marks_itself_audited_and_not_guarded(captured):
    @cli_guard.audited("list_resources")
    def resource_list():
        return None

    assert resource_list._is_audited is True
    assert resource_list._audited_tool == "list_resources"
    # Guarded means "a write" to every repo's guarded-writes test; a read must not look like one.
    assert not getattr(resource_list, "_is_guarded", False)


def test_credentials_in_parameters_do_not_reach_the_row(monkeypatch):
    """Through the REAL audit_call: the credential-key net lives there, the one
    place every surface passes through, so patching audit_call would test nothing."""
    import vmware_policy.guard as guard_mod

    logged: list[dict] = []
    monkeypatch.setattr(cli_guard, "guard", lambda *a, **k: PolicyResult(allowed=True))
    monkeypatch.setattr(guard_mod, "get_engine", lambda: type("E", (), {"log": lambda self, **kw: logged.append(kw)})())

    # `password` is in the exact-match credential set. Names outside it (say
    # `api_token`) are what sensitive_params is for — the net is exact by design.
    @cli_guard.audited("pais_model_list")
    def model_list(endpoint, password="s3cr3t-password-value"):
        return None

    model_list("https://pais.example")
    assert len(logged) == 1
    assert "s3cr3t-password-value" not in str(logged[0]["params"])
    assert logged[0]["tool"] == "pais_model_list"


def test_the_signature_typer_reads_is_preserved(captured):
    def resource_list(kind: str = "VirtualMachine", limit: int = 50, target: str | None = None) -> None:
        return None

    wrapped = cli_guard.audited("list_resources")(resource_list)
    assert inspect.signature(wrapped) == inspect.signature(resource_list)


def test_cli_local_marks_the_command_and_never_audits(captured):
    guard_calls, audit_rows = captured

    @cli_guard.cli_local("starts the MCP server; its tools audit themselves")
    def mcp():
        return "served"

    assert mcp() == "served"
    assert guard_calls == [] and audit_rows == []
    assert mcp._is_local is True
    assert "MCP server" in mcp._local_reason


@pytest.mark.parametrize("reason", ["", "   "])
def test_cli_local_requires_a_reason(reason):
    with pytest.raises(ValueError, match="reason"):
        cli_guard.cli_local(reason)


def test_both_are_exported_from_the_package():
    import vmware_policy

    assert vmware_policy.audited is cli_guard.audited
    assert vmware_policy.cli_local is cli_guard.cli_local
    assert {"audited", "cli_local"} <= set(vmware_policy.__all__)
