"""Audit names the network caller, not the process user (HLD §16 D-12).

Storage#18 runs one server for several people; every audit row said the
systemd service user, whoever asked. Over an authenticated transport the SDK
puts the verified token in a context variable; the audit `user` becomes
``token:<name>`` from it. Without one (stdio, CLI) nothing changes.
"""

from __future__ import annotations

import getpass

import pytest

from vmware_policy import caller


@pytest.mark.unit
def test_no_network_caller_means_the_process_user():
    assert caller.current_caller() is None
    assert caller.audit_user() == getpass.getuser()


@pytest.mark.unit
def test_an_authenticated_sdk_request_names_the_token():
    pytest.importorskip("mcp")
    from mcp.server.auth.middleware.auth_context import auth_context_var
    from mcp.server.auth.middleware.bearer_auth import AuthenticatedUser
    from mcp.server.auth.provider import AccessToken

    user = AuthenticatedUser(AccessToken(token="[redacted]", client_id="alice", scopes=[]))
    reset = auth_context_var.set(user)
    try:
        assert caller.current_caller() == "token:alice"
        assert caller.audit_user() == "token:alice"
    finally:
        auth_context_var.reset(reset)
    assert caller.current_caller() is None


@pytest.mark.unit
def test_the_audit_row_records_the_network_caller(tmp_path, monkeypatch):
    pytest.importorskip("mcp")
    from mcp.server.auth.middleware.auth_context import auth_context_var
    from mcp.server.auth.middleware.bearer_auth import AuthenticatedUser
    from mcp.server.auth.provider import AccessToken

    from vmware_policy.audit import AuditEngine

    engine = AuditEngine(db_path=tmp_path / "audit.db")
    reset = auth_context_var.set(
        AuthenticatedUser(AccessToken(token="[redacted]", client_id="bob", scopes=[]))
    )
    try:
        engine.log(skill="storage", tool="list_all_datastores", params={}, result="ok", status="ok")
    finally:
        auth_context_var.reset(reset)
    rows = engine.query(limit=1)
    assert rows[0]["user"] == "token:bob"


@pytest.mark.unit
def test_env_approval_fields_are_not_stamped_on_network_calls(monkeypatch):
    pytest.importorskip("mcp")
    from mcp.server.auth.middleware.auth_context import auth_context_var
    from mcp.server.auth.middleware.bearer_auth import AuthenticatedUser
    from mcp.server.auth.provider import AccessToken

    from vmware_policy.decorators import _CallState

    monkeypatch.setenv("VMWARE_AUDIT_RATIONALE", "server-wide reason")
    monkeypatch.setenv("VMWARE_AUDIT_APPROVED_BY", "ciso")

    def tool(target: str = "") -> dict:
        return {}

    import inspect

    def state():
        return _CallState(tool, (), {}, inspect.signature(tool), set(), "low", 300, None, False)

    assert state().approved_by == "ciso"  # stdio / CLI: unchanged
    reset = auth_context_var.set(
        AuthenticatedUser(AccessToken(token="[redacted]", client_id="bob", scopes=[]))
    )
    try:
        s = state()
        assert s.approved_by == "" and s.rationale == ""
    finally:
        auth_context_var.reset(reset)
