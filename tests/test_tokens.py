"""Bearer tokens for network MCP transports (HLD §16 D-11).

A token is >= 128 random bits, shown once at creation, stored only as a sha256
in an owner-only file, compared in constant time, and re-read when the file
changes so revocation needs no restart.
"""

from __future__ import annotations

import asyncio
import os
import stat
import time

import pytest

from vmware_policy import tokens


@pytest.fixture
def token_file(tmp_path, monkeypatch):
    monkeypatch.setenv("OPS_HOME", str(tmp_path))
    return tokens.token_file()


@pytest.mark.unit
def test_create_returns_the_secret_once_and_stores_only_a_hash(token_file):
    secret = tokens.create_token("alice")

    text = token_file.read_text(encoding="utf-8")
    assert secret not in text
    assert "alice" in text
    assert len(secret) >= 32  # >= 128 bits of entropy, url-safe
    assert stat.S_IMODE(os.stat(token_file).st_mode) == 0o600


@pytest.mark.unit
def test_a_token_name_is_unique_and_closed(token_file):
    tokens.create_token("alice")
    with pytest.raises(tokens.TokenError, match="exists"):
        tokens.create_token("alice")
    with pytest.raises(tokens.TokenError, match="name"):
        tokens.create_token("bad name!")


@pytest.mark.unit
def test_verify_names_the_caller_and_refuses_anything_else(token_file):
    secret = tokens.create_token("alice")
    store = tokens.TokenStore(token_file)

    assert store.identify(secret) == "alice"
    assert store.identify(secret + "x") is None
    assert store.identify("") is None


@pytest.mark.unit
def test_revocation_takes_effect_without_restart(token_file):
    secret = tokens.create_token("alice")
    store = tokens.TokenStore(token_file)
    assert store.identify(secret) == "alice"

    time.sleep(0.01)
    tokens.revoke_token("alice")
    assert store.identify(secret) is None


@pytest.mark.unit
def test_list_shows_names_not_hashes(token_file):
    tokens.create_token("alice")
    tokens.create_token("bob")

    assert tokens.list_tokens() == ["alice", "bob"]


@pytest.mark.unit
def test_revoking_an_unknown_name_is_an_error(token_file):
    with pytest.raises(tokens.TokenError, match="no token"):
        tokens.revoke_token("nobody")


@pytest.mark.unit
def test_a_group_or_world_readable_file_is_refused(token_file):
    tokens.create_token("alice")
    os.chmod(token_file, 0o644)

    with pytest.raises(tokens.TokenError, match="0600"):
        tokens.TokenStore(token_file).identify("anything")


@pytest.mark.unit
def test_the_sdk_verifier_returns_an_access_token_named_for_the_caller(token_file):
    pytest.importorskip("mcp")
    secret = tokens.create_token("alice")
    verifier = tokens.FileTokenVerifier(tokens.TokenStore(token_file))

    access = asyncio.run(verifier.verify_token(secret))
    assert access is not None and access.client_id == "alice"
    assert secret not in repr(access)
    assert asyncio.run(verifier.verify_token("wrong")) is None


@pytest.mark.unit
def test_cli_create_list_revoke(token_file):
    from typer.testing import CliRunner

    from vmware_policy.cli import app

    runner = CliRunner()
    made = runner.invoke(app, ["token", "create", "alice"])
    assert made.exit_code == 0, made.output
    secret = made.stdout.strip().splitlines()[0]
    assert tokens.TokenStore(token_file).identify(secret) == "alice"

    listed = runner.invoke(app, ["token", "list"])
    assert listed.stdout.split() == ["alice"]

    dup = runner.invoke(app, ["token", "create", "alice"])
    assert dup.exit_code == 2

    gone = runner.invoke(app, ["token", "revoke", "alice"])
    assert gone.exit_code == 0
    assert tokens.TokenStore(token_file).identify(secret) is None


@pytest.mark.unit
def test_a_replace_with_the_same_size_and_mtime_is_still_seen(token_file):
    a = tokens.create_token("aaaaa")
    store = tokens.TokenStore(token_file)
    assert store.identify(a) == "aaaaa"
    st = os.stat(token_file)
    tokens.revoke_token("aaaaa")
    b = tokens.create_token("bbbbb")  # same line length -> same file size
    os.utime(token_file, ns=(st.st_atime_ns, st.st_mtime_ns))  # same mtime tick
    assert os.stat(token_file).st_size == st.st_size
    assert store.identify(a) is None
    assert store.identify(b) == "bbbbb"


@pytest.mark.unit
def test_cli_token_commands_take_a_token_file(tmp_path):
    from typer.testing import CliRunner

    from vmware_policy.cli import app

    path = tmp_path / "other-tokens"
    made = CliRunner().invoke(app, ["token", "create", "carol", "--token-file", str(path)])
    assert made.exit_code == 0, made.output
    assert tokens.list_tokens(path) == ["carol"]


@pytest.mark.unit
def test_concurrent_creates_keep_every_token(token_file):
    import threading

    names = [f"user{i}" for i in range(12)]
    threads = [threading.Thread(target=tokens.create_token, args=(n,)) for n in names]
    for t in threads:
        t.start()
    for t in threads:
        t.join(5)
    assert tokens.list_tokens() == sorted(names)
