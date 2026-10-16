"""HLD §18: what the security and integration reviews of 1.24.0 found, pinned."""

from __future__ import annotations

import os

import pytest

pytest.importorskip("mcp")

from tests.test_roles_e2e import (  # noqa: E402,F401
    _configured,
    _list_and_calls,
    _refused,
    _rows,
    enabled,
)
from tests.test_serve import ops_home  # noqa: E402,F401
from vmware_policy import roles, serve, tokens  # noqa: E402
from vmware_policy.tokens import TokenError, TokenStore  # noqa: E402

# ── token files ───────────────────────────────────────────────────────────


@pytest.mark.unit
def test_v2_file_owned_by_someone_else_is_refused(tmp_path, monkeypatch):
    """MEDIUM-1: a planted name:sha256:admin line must not become an admin token."""
    f = tmp_path / "mcp-tokens"
    tokens.enable_roles(f)
    secret = tokens.create_token("bob", f, role="reader")
    monkeypatch.setattr(os, "geteuid", lambda: os.getuid() + 1)
    with pytest.raises(TokenError, match="not by the user running this server"):
        TokenStore(f).identify(secret)


@pytest.mark.unit
def test_v2_file_in_a_directory_others_can_write_is_refused(tmp_path):
    d = tmp_path / "ops"
    d.mkdir()
    f = d / "mcp-tokens"
    tokens.enable_roles(f)
    os.chmod(d, 0o777)
    try:
        with pytest.raises(TokenError, match="writable by other users"):
            TokenStore(f).count()
    finally:
        os.chmod(d, 0o700)


@pytest.mark.unit
def test_a_chmod_alone_is_seen_by_a_running_token_store(tmp_path):
    """LOW-1: (inode, mtime, size) does not change on chmod; the checks must still rerun."""
    f = tmp_path / "mcp-tokens"
    tokens.enable_roles(f)
    tokens.create_token("bob", f, role="reader")
    store = TokenStore(f)
    assert store.count() == 1
    os.chmod(tokens.v2_file(f), 0o644)
    with pytest.raises(TokenError, match="readable by other users"):
        store.count()


@pytest.mark.unit
def test_enable_finishes_a_run_that_stopped_before_emptying_the_legacy_file(tmp_path):
    """LOW-7: v2 written, legacy not yet emptied; re-running completes it."""
    f = tmp_path / "mcp-tokens"
    secret = tokens.create_token("alice", f)
    legacy = tokens._read(f)
    tokens._write_v2(tokens.v2_file(f), {"alice": (legacy["alice"], "admin")})
    assert tokens.enable_roles(f) == {}
    assert tokens._read(f) == {}
    assert TokenStore(f).identify(secret) == "alice"


@pytest.mark.unit
def test_enable_does_not_quietly_make_post_opt_in_legacy_lines_admin(tmp_path):
    f = tmp_path / "mcp-tokens"
    tokens.enable_roles(f)
    tokens._write(f, {"sneaky": tokens._hash("s")})  # an older vmware-audit, after opt-in
    with pytest.raises(TokenError, match="written after roles were enabled"):
        tokens.enable_roles(f)
    assert "sneaky" not in tokens._read_v2(tokens.v2_file(f))


# ── roles.yaml ────────────────────────────────────────────────────────────


@pytest.mark.unit
def test_a_chmod_alone_is_seen_by_a_running_role_file(enabled, ops_home):  # noqa: F811
    rf = roles.RoleFile()
    assert rf.get("ops")[0] is not None
    os.chmod(ops_home / "roles.yaml", 0o644)
    role, why = rf.get("ops")
    assert role is None and why


@pytest.mark.unit
def test_a_server_audits_what_roles_yaml_now_says(enabled, ops_home):  # noqa: F811
    """MEDIUM-4: changing what a role may do leaves a row with the file's digest."""
    rf = roles.RoleFile(audit_reloads=True)
    rf.get("ops")
    (ops_home / "roles.yaml").write_text("roles: [", encoding="utf-8")
    rf.get("ops")
    reloads = [r for r in _rows(ops_home) if r["tool"] == "roles_reload"]
    assert [r["status"] for r in reloads] == ["error", "ok"]  # newest first
    assert '"roles": ["ops"]' in reloads[1]["params"] and '"sha256": "' in reloads[1]["params"]


@pytest.mark.unit
def test_the_cli_reading_roles_yaml_writes_no_reload_rows(enabled, ops_home):  # noqa: F811
    roles.RoleFile().get("ops")
    assert not [r for r in _rows(ops_home) if r["tool"] == "roles_reload"]


# ── the per-call check ────────────────────────────────────────────────────


@pytest.mark.unit
def test_the_role_check_comes_before_argument_checks(enabled, ops_home):  # noqa: F811
    """M2/LOW-6: a role without the tool is refused as a role refusal, with its role."""
    _, results = _list_and_calls(enabled["reader"], [("fetch_file", {"local_path": "/etc/x"})])
    assert _refused(results[0]) and "more than read access" in results[0]["content"][0]["text"]
    row = next(r for r in _rows(ops_home) if r["tool"] == "fetch_file")
    assert row["status"] == "denied" and row["role"] == "reader"


@pytest.mark.unit
def test_role_refusals_count_toward_the_budget(enabled, monkeypatch):  # noqa: F811
    """MEDIUM-4: probing tools a role lacks trips the runaway guard like any burst."""
    from vmware_policy import decorators

    seen = []

    class _Budget:
        def check_and_record(self, tool, params):
            seen.append(tool)

        def add_duration(self, _seconds):
            pass

    monkeypatch.setattr(decorators, "get_budget", lambda: _Budget())
    _list_and_calls(enabled["reader"], [("set_thing", {})])
    assert seen == ["set_thing"]


@pytest.mark.unit
def test_reader_is_held_to_what_a_read_only_composite_reaches(enabled):  # noqa: F811
    """LOW-4: a read tool that runs a write tool is not a read for 'reader'."""
    meta = roles.metadata("storage")
    meta.reaches = {"get_everything": frozenset({"wipe_thing"})}
    _, results = _list_and_calls(enabled["reader"], [("get_everything", {})])
    assert _refused(results[0]) and "can run wipe_thing" in results[0]["content"][0]["text"]


@pytest.mark.unit
def test_a_target_name_with_a_period_does_not_leave_addresses_showing(enabled, monkeypatch):  # noqa: F811
    """LOW-3: the filter cut at the first '. ', so a target named 'prod.' leaked the rest."""
    text = (
        "Base. Configured targets: prod. (vcenter, 10.0.0.1, default); lab (vcenter, "
        "10.9.9.9). Choosing a target: pick one."
    )
    monkeypatch.setattr(roles, "roles_enabled", lambda: True)
    monkeypatch.setattr(roles, "caller_role", lambda: (roles.READER, "reader", ""))
    out = roles.instructions_for_caller(text)
    assert "10.0.0.1" not in out and "10.9.9.9" not in out
    assert out.startswith("Base. Configured targets: not listed") and "Choosing a target" in out
    no_rule = roles.instructions_for_caller("Configured targets: a (vcenter, 10.1.1.1).")
    assert "10.1.1.1" not in no_rule


# ── serve ─────────────────────────────────────────────────────────────────


@pytest.mark.unit
def test_role_files_are_protected_from_host_path_tools(enabled, ops_home):  # noqa: F811
    """MEDIUM-2: with --token-file F, F.v2 is not 'inside' F; it is registered itself."""
    from vmware_policy.hostpaths import protected_roots

    _configured()
    roots = protected_roots()
    for name in ("mcp-tokens.v2", "mcp-tokens.lock", "roles.yaml"):
        assert any(r.endswith(name) for r in roots), (name, roots)


@pytest.mark.unit
def test_roles_enabled_with_no_registry_refuses_to_serve(enabled):  # noqa: F811
    """LOW-9: without the registry, host-path tools would not count as escapes."""
    from tests.test_roles_e2e import _server

    roles.metadata("storage").registry = {}
    with pytest.raises(serve.ServeError, match="registry could not be read"):
        serve.configure(_server(), serve.ServeOptions(skill="storage", transport="http"))


@pytest.mark.unit
def test_a_broken_roles_file_is_not_described_to_the_caller(enabled, ops_home):  # noqa: F811
    """The caller learns where to look; server paths and parser output stay in the log."""
    (ops_home / "roles.yaml").write_text("roles: [", encoding="utf-8")
    _, results = _list_and_calls(enabled["ops"], [("get_thing", {})])
    text = results[0]["content"][0]["text"]
    assert _refused(results[0]) and "roles check" in text
    assert str(ops_home) not in text and "roles.yaml" not in text


@pytest.mark.unit
def test_roles_check_says_what_it_did_not_check(ops_home):  # noqa: F811
    from typer.testing import CliRunner

    from vmware_policy.cli import app

    off = CliRunner().invoke(app, ["roles", "check"])
    assert off.exit_code == 0 and "not enabled" in off.output
    tokens.enable_roles()
    on = CliRunner().invoke(app, ["roles", "check"])
    assert on.exit_code == 0 and "Not checked here" in on.output


@pytest.mark.unit
def test_a_refusal_raised_inside_a_tool_is_audited_with_its_rule(ops_home):  # noqa: F811
    """Pilot's approve refuses by role from inside its body; the row must say which rule."""
    from tests.test_roles_e2e import _tool
    from vmware_policy.policy import PolicyDenied, PolicyResult

    def approve_thing() -> dict:
        raise PolicyDenied(PolicyResult(False, "role:ops", "may not approve"))

    with pytest.raises(PolicyDenied):
        _tool(approve_thing)()
    row = next(r for r in _rows(ops_home) if r["tool"] == "approve_thing")
    assert row["status"] == "denied" and "role:ops" in row["result"]
