"""HLD §18 D-20/D-24/D-25: token and role commands, and their audit rows."""

from __future__ import annotations

import os

import pytest
from typer.testing import CliRunner

from vmware_policy import tokens
from vmware_policy.cli import app

ROLES = """\
roles:
  ops:
    skills:
      storage: {tools: read, allow_write: [], allow_escape: [], targets: "*"}
    approve: none
"""


@pytest.fixture
def home(tmp_path, monkeypatch):
    import vmware_policy.audit as audit_mod

    monkeypatch.setenv("OPS_HOME", str(tmp_path))
    audit_mod._engine = None
    yield tmp_path
    audit_mod._engine = None


def _rows(home):
    from vmware_policy.audit import AuditEngine

    return AuditEngine(db_path=home / "audit.db").query(skill="policy", limit=50)


def _run(*args):
    return CliRunner().invoke(app, list(args))


@pytest.mark.unit
def test_create_with_builtin_role_and_list_long(home):
    assert _run("roles", "enable").exit_code == 0
    r = _run("token", "create", "bob", "--role", "reader")
    assert r.exit_code == 0, r.output
    assert tokens.roles_enabled(home / "mcp-tokens")
    long = _run("token", "list", "--long")
    assert "bob\treader\t" in long.stdout
    assert _run("token", "list").stdout.split() == ["bob"]


@pytest.mark.unit
def test_an_undefined_role_is_refused(home):
    _run("roles", "enable")
    r = _run("token", "create", "bob", "--role", "nosuch")
    assert r.exit_code == 2 and "not defined" in r.output


@pytest.mark.unit
def test_custom_role_from_roles_yaml(home):
    (home / "roles.yaml").write_text(ROLES, encoding="utf-8")
    os.chmod(home / "roles.yaml", 0o600)
    assert _run("roles", "enable").exit_code == 0
    assert _run("token", "create", "o1", "--role", "ops").exit_code == 0
    assert _run("roles", "check").exit_code == 0


@pytest.mark.unit
def test_enable_moves_legacy_tokens_and_assigns(home):
    assert _run("token", "create", "alice").exit_code == 0
    assert _run("token", "create", "carl").exit_code == 0
    r = _run("roles", "enable", "--assign", "carl=reader")
    assert r.exit_code == 0, r.output
    assert "alice\tadmin" in r.stdout and "carl\treader" in r.stdout
    assert tokens._read(home / "mcp-tokens") == {}
    no_role = _run("token", "create", "dave")
    assert no_role.exit_code == 2 and "--role" in no_role.output


@pytest.mark.unit
def test_set_role_and_check_flags_problems(home):
    _run("roles", "enable")
    _run("token", "create", "bob", "--role", "reader")
    assert _run("token", "set-role", "bob", "admin").exit_code == 0
    (home / "roles.yaml").write_text("roles: [", encoding="utf-8")
    os.chmod(home / "roles.yaml", 0o600)
    r = _run("roles", "check")
    assert r.exit_code == 1 and "role *" in r.stdout


@pytest.mark.unit
def test_privilege_changes_are_audited(home):
    _run("token", "create", "alice")
    _run("roles", "enable")
    _run("token", "create", "bob", "--role", "reader")
    _run("token", "set-role", "bob", "admin")
    _run("token", "revoke", "bob")
    _run("token", "revoke", "nobody")
    rows = _rows(home)
    tools = [r["tool"] for r in rows]
    for t in ("token_create", "roles_enable", "token_set_role", "token_revoke"):
        assert t in tools, (t, tools)
    assert all(r["surface"] == "cli" for r in rows)
    assert any(r["tool"] == "token_revoke" and r["status"] == "error" for r in rows)
    set_role = next(r for r in rows if r["tool"] == "token_set_role")
    assert '"old_role": "reader"' in set_role["params"] and '"role": "admin"' in set_role["params"]
    # secrets never reach the audit log
    assert all("secret" not in r["params"].lower() for r in rows)


@pytest.mark.unit
def test_role_token_before_enable_points_at_enable(home):
    r = _run("token", "create", "bob", "--role", "reader")
    assert r.exit_code == 2 and "roles enable" in r.output
    assert not tokens.roles_enabled(home / "mcp-tokens")
