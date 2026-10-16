"""Deny rules can name network callers (HLD §16 D-12 `clients:`)."""

from __future__ import annotations

import pytest

from vmware_policy import caller as caller_mod
from vmware_policy.policy import PolicyEngine


@pytest.fixture
def engine(tmp_path):
    rules = tmp_path / "rules.yaml"
    rules.write_text(
        "deny:\n"
        "  - name: interns-read-only\n"
        "    operations: ['delete_*', 'power_*']\n"
        "    clients: ['intern-*']\n"
        "    reason: interns may not change anything\n",
        encoding="utf-8",
    )
    return PolicyEngine(rules)


def _as(monkeypatch, who):
    monkeypatch.setattr(caller_mod, "current_caller", lambda: who)


@pytest.mark.unit
def test_a_named_client_is_denied(engine, monkeypatch):
    _as(monkeypatch, "token:intern-ann")
    assert engine.check_allowed("delete_vm", env="").allowed is False


@pytest.mark.unit
def test_other_clients_are_not_matched(engine, monkeypatch):
    _as(monkeypatch, "token:ops-bob")
    assert engine.check_allowed("delete_vm", env="").allowed is True


@pytest.mark.unit
def test_stdio_and_cli_are_not_matched_by_a_client_scoped_rule(engine, monkeypatch):
    _as(monkeypatch, None)
    assert engine.check_allowed("delete_vm", env="").allowed is True


@pytest.mark.unit
def test_a_scalar_clients_value_is_one_name_not_letters(tmp_path, monkeypatch):
    rules = tmp_path / "rules.yaml"
    rules.write_text(
        "deny:\n  - name: no-bob\n    operations: [delete_vm]\n    clients: bob\n", encoding="utf-8"
    )
    engine = PolicyEngine(rules)
    _as(monkeypatch, "token:bob")
    assert engine.check_allowed("delete_vm", env="").allowed is False
    _as(monkeypatch, "token:b")
    assert engine.check_allowed("delete_vm", env="").allowed is True


@pytest.mark.unit
def test_an_unreadable_clients_value_fails_closed(tmp_path, monkeypatch):
    rules = tmp_path / "rules.yaml"
    rules.write_text(
        "deny:\n  - name: odd\n    operations: [delete_vm]\n    clients: {a: 1}\n", encoding="utf-8"
    )
    engine = PolicyEngine(rules)
    _as(monkeypatch, "token:anyone")
    assert engine.check_allowed("delete_vm", env="").allowed is False


@pytest.fixture
def role_engine(tmp_path):
    rules = tmp_path / "rules.yaml"
    rules.write_text(
        "deny:\n"
        "  - name: readers-no-power\n"
        "    operations: ['power_*']\n"
        "    roles: [reader]\n"
        "    reason: readers may not power anything\n",
        encoding="utf-8",
    )
    return PolicyEngine(rules)


def _with_role(monkeypatch, role_name):
    from vmware_policy import roles as roles_mod

    monkeypatch.setattr(roles_mod, "roles_enabled", lambda: role_name is not None)
    monkeypatch.setattr(roles_mod, "caller_role", lambda: (None, role_name or "", ""))


@pytest.mark.unit
def test_a_roles_rule_matches_that_role_only(role_engine, monkeypatch):
    """HLD §18 L6: deny rules can name roles, not only token-name patterns."""
    _with_role(monkeypatch, "reader")
    assert role_engine.check_allowed("power_on_vm", env="").allowed is False
    _with_role(monkeypatch, "admin")
    assert role_engine.check_allowed("power_on_vm", env="").allowed is True


@pytest.mark.unit
def test_a_roles_rule_does_not_match_without_roles(role_engine, monkeypatch):
    _with_role(monkeypatch, None)
    assert role_engine.check_allowed("power_on_vm", env="").allowed is True
