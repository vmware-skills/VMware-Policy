"""The audit sink scrubs credentials from every surface and every column.

Found 2026-09-11 while correcting the Policy docs for ClawHub's scanner — a
probe, not a reading: ``"password": "hunter2"`` landed in an audit row in
plain text. The credential-key net (_redact_credential_keys) was applied to
*results* only; *parameters* were redacted only when a tool remembered to list
them in ``sensitive_params``. A tool that forgets is exactly what the net
exists for (CLAUDE.md 形态 #7), so parameters get it too — in ``audit_call``,
the single sink every surface writes, rather than in each caller.

The same probe found the CLI surface behind the MCP one in two more ways:
a ``VMWARE_POLICY_DISABLED=1`` run was recorded as a plain ``ok`` (the MCP
surface records ``ok_bypassed``), and CLI error text skipped the free-form
credential scrubber the MCP surface runs.

These tests go through the real ``audit_call`` and a real audit.db, and search
the whole row — the existing cli_guard tests patch ``audit_call`` away, which is
how a sink-level leak stayed invisible to them.
"""

from __future__ import annotations

import sqlite3

import pytest

import vmware_policy.audit as audit_mod
import vmware_policy.policy as policy_mod
from vmware_policy import cli_guard
from vmware_policy.audit import AuditEngine
from vmware_policy.decorators import vmware_tool

SECRET = "hunter2-DO-NOT-LOG"


@pytest.fixture
def audit_db(tmp_path):
    db_path = tmp_path / "audit.db"
    audit_mod._engine = AuditEngine(db_path)
    policy_mod._engine = None
    yield db_path
    audit_mod._engine = None
    policy_mod._engine = None


def _rows(db_path) -> list[dict]:
    conn = sqlite3.connect(str(db_path))
    try:
        conn.row_factory = sqlite3.Row
        return [dict(r) for r in conn.execute("SELECT * FROM audit_log ORDER BY id")]
    finally:
        conn.close()


def _row_text(row: dict) -> str:
    return "\n".join(f"{k}={v}" for k, v in row.items())


def test_mcp_undeclared_credential_parameter_is_not_filed(audit_db):
    @vmware_tool(risk_level="low")
    def connect_target(host: str, password: str = "", targets: list | None = None) -> dict:
        return {"connected": True}

    connect_target("vc01.lab", password=SECRET, targets=[{"name": "t", "password": SECRET}])
    (row,) = _rows(audit_db)
    assert SECRET not in _row_text(row), "an undeclared credential parameter reached the audit row"
    assert "vc01.lab" in row["params"], "the non-secret arguments must still be recorded"


def test_cli_undeclared_credential_parameter_is_not_filed(audit_db):
    @cli_guard.guarded(risk_level="low")
    def login(host, password=None, target=None):
        return None

    login("vc01.lab", password=SECRET)
    (row,) = _rows(audit_db)
    assert SECRET not in _row_text(row), "an undeclared credential parameter reached the audit row"
    assert "vc01.lab" in row["params"]


def test_cli_bypass_is_recorded_as_bypassed(audit_db, monkeypatch):
    monkeypatch.setenv("VMWARE_POLICY_DISABLED", "1")

    @cli_guard.guarded(risk_level="high")
    def vm_delete(vm_name, target=None):
        return None

    vm_delete("web-01")
    (row,) = _rows(audit_db)
    assert row["status"] == "ok_bypassed", (
        f"a write run with policy disabled was recorded as {row['status']!r} — "
        "indistinguishable from a normal one"
    )


def test_cli_bypass_absent_keeps_plain_status(audit_db, monkeypatch):
    monkeypatch.delenv("VMWARE_POLICY_DISABLED", raising=False)

    @cli_guard.guarded(risk_level="high")
    def vm_delete(vm_name, target=None):
        return None

    vm_delete("web-01")
    (row,) = _rows(audit_db)
    assert row["status"] == "ok"


def test_cli_error_text_is_scrubbed_like_mcp(audit_db):
    @cli_guard.guarded(risk_level="low")
    def login(host, target=None):
        raise RuntimeError(f"login to {host} failed: password={SECRET} rejected")

    with pytest.raises(RuntimeError):
        login("vc01.lab")
    (row,) = _rows(audit_db)
    assert row["status"] == "error"
    assert SECRET not in _row_text(row), "a credential inside CLI error text reached the audit row"
    assert "vc01.lab" in row["result"], "the error must still say what failed"


# ── Review round, 2026-09-11 ─────────────────────────────────────────────


def test_a_credential_key_holding_a_dict_does_not_crash_the_call(audit_db):
    """`item in frozenset` raised TypeError for an unhashable value, inside the
    decorator's finally: the operation ran, the tool raised anyway, and no audit
    row was written."""

    @vmware_tool(risk_level="low")
    def connect_target(host: str, credentials: dict | None = None) -> dict:
        return {"credentials": {"user": "admin", "password": SECRET}}

    out = connect_target("vc01.lab", credentials={"user": "admin", "password": SECRET})
    assert out["credentials"]["password"] == SECRET, "the caller must still get the real value"
    (row,) = _rows(audit_db)
    assert SECRET not in _row_text(row)


def test_a_credential_inside_a_free_text_parameter_is_scrubbed(audit_db):
    @vmware_tool(risk_level="low")
    def vm_guest_exec(vm_name: str, arguments: str = "") -> dict:
        return {"exit_code": 0}

    vm_guest_exec("web-01", arguments=f"-c 'mysql --password={SECRET} -e select'")
    (row,) = _rows(audit_db)
    assert SECRET not in _row_text(row)
    assert "mysql" in row["params"], "the rest of the argument string must survive"


def test_a_prefixed_credential_parameter_name_is_scrubbed(audit_db):
    @vmware_tool(risk_level="low")
    def rotate(
        host: str, vc_password: str = "", new_password: str = "", token_count: int = 0
    ) -> dict:
        return {"ok": True}

    rotate("vc01.lab", vc_password=SECRET, new_password=SECRET + "2", token_count=5120)
    (row,) = _rows(audit_db)
    assert SECRET not in _row_text(row)
    assert "5120" in row["params"], "token_count is not a credential and must stay readable"
