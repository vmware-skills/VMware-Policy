"""HLD §18 D-20/D-24: role tokens live in <token file>.v2; opt-in empties the legacy file."""

from __future__ import annotations

import pytest

from vmware_policy import tokens
from vmware_policy.tokens import TokenError, TokenStore


def _old_reader_names(path):
    """What vmware-policy <= 1.23 does: `name, _, digest = line.partition(':')` + regex."""
    import re

    names = []
    if not path.exists():
        return names
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        name, _, digest = line.partition(":")
        if re.fullmatch(r"[0-9a-f]{64}", digest):
            names.append(name)
    return names


def _old_writer_create(path, name):
    """What an old `vmware-audit token create` does: rewrite the legacy file from what it parsed."""
    entries = tokens._read(path)
    entries[name] = tokens._hash("old-secret-" + name)
    tokens._write(path, entries)


def test_without_roles_nothing_changes(tmp_path):
    f = tmp_path / "mcp-tokens"
    secret = tokens.create_token("alice", f)
    assert not tokens.roles_enabled(f)
    store = TokenStore(f)
    assert store.identify(secret) == "alice"
    assert store.role_of("alice") == "admin"
    assert not tokens.v2_file(f).exists()


def test_role_token_goes_to_v2_and_old_code_cannot_see_or_clobber_it(tmp_path):
    f = tmp_path / "mcp-tokens"
    tokens.create_token("legacy", f)
    secret = tokens.create_token("bob", f, role="reader")
    assert "bob" not in _old_reader_names(f)
    _old_writer_create(f, "carol")  # an older CLI on the same host
    store = TokenStore(f)
    assert store.identify(secret) == "bob" and store.role_of("bob") == "reader"


def test_after_enable_old_servers_refuse_everything(tmp_path):
    f = tmp_path / "mcp-tokens"
    tokens.create_token("alice", f)
    tokens.create_token("ops", f)
    moved = tokens.enable_roles(f, {"ops": "reader"})
    assert moved == {"alice": "admin", "ops": "reader"}
    assert _old_reader_names(f) == []  # an older server now has no tokens: 401 for all
    store = TokenStore(f)
    assert store.role_of("alice") == "admin" and store.role_of("ops") == "reader"


def test_enable_keeps_secrets_working(tmp_path):
    f = tmp_path / "mcp-tokens"
    secret = tokens.create_token("alice", f)
    tokens.enable_roles(f)
    assert TokenStore(f).identify(secret) == "alice"


def test_enable_is_idempotent(tmp_path):
    f = tmp_path / "mcp-tokens"
    tokens.create_token("alice", f)
    tokens.enable_roles(f)
    assert tokens.enable_roles(f) == {}
    assert TokenStore(f).role_of("alice") == "admin"


def test_after_enable_a_role_is_required(tmp_path):
    f = tmp_path / "mcp-tokens"
    tokens.enable_roles(f)
    with pytest.raises(TokenError, match="--role"):
        tokens.create_token("dave", f)


def test_legacy_line_written_after_enable_is_refused(tmp_path):
    f = tmp_path / "mcp-tokens"
    tokens.enable_roles(f)
    _old_writer_create(f, "sneaky")
    store = TokenStore(f)
    assert store.identify("old-secret-sneaky") is None
    info = {t.name: t for t in tokens.list_token_info(f)}
    assert not info["sneaky"].usable and "refused" in info["sneaky"].note


def test_name_in_both_files_is_refused(tmp_path):
    f = tmp_path / "mcp-tokens"
    secret = tokens.create_token("alice", f, role="reader")
    # Same name and hash appear in the legacy file too (an old CLI, a hand edit).
    tokens._write(f, {"alice": tokens._hash(secret)})
    assert TokenStore(f).identify(secret) is None


def test_set_role_and_revoke(tmp_path):
    f = tmp_path / "mcp-tokens"
    tokens.create_token("bob", f, role="reader")
    assert tokens.set_role("bob", "admin", f) == "reader"
    store = TokenStore(f)
    assert store.role_of("bob") == "admin"
    tokens.revoke_token("bob", f)
    assert store.role_of("bob") is None


def test_set_role_on_a_legacy_token_points_at_enable(tmp_path):
    f = tmp_path / "mcp-tokens"
    tokens.create_token("alice", f)
    with pytest.raises(TokenError, match="roles enable"):
        tokens.set_role("alice", "reader", f)


@pytest.mark.parametrize("bad", ["a:b", "", "-x"])
def test_role_names_use_the_token_charset(tmp_path, bad):
    with pytest.raises(TokenError):
        tokens.create_token("bob", tmp_path / "t", role=bad)


def test_role_is_read_at_call_time_not_cached(tmp_path):
    f = tmp_path / "mcp-tokens"
    tokens.create_token("bob", f, role="reader")
    store = TokenStore(f)
    assert store.role_of("bob") == "reader"
    tokens.set_role("bob", "admin", f)
    assert store.role_of("bob") == "admin"
