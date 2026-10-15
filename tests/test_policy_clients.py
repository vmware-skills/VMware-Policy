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
