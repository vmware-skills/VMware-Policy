"""The "declares no environment label" warning fires only when it can matter.

guard() resolves every target's environment on every call, and an unlabelled
target logged "Target '' declares no environment label ... Harmless unless you
rely on such rules" once per process. A CLI command is one process, so once
every CLI read went through guard() (HLD I-8, amended 2026-09-15) the line would
have printed on nearly every command for anyone who has no environment-scoped
rule — which is almost everyone, and exactly the case the message calls
harmless. It now fires when an environment-scoped deny rule exists.
"""

from __future__ import annotations

import logging

import pytest

from vmware_policy import guard as guard_mod
from vmware_policy.environment import resolve_environment, set_environment_resolver
from vmware_policy.guard import guard
from vmware_policy.policy import PolicyEngine

UNLABELLED = "declares no environment label"


@pytest.fixture
def rules(tmp_path, monkeypatch):
    def make(text: str) -> PolicyEngine:
        p = tmp_path / "rules.yaml"
        p.write_text(text, encoding="utf-8")
        eng = PolicyEngine(rules_path=p)
        monkeypatch.setattr(guard_mod, "get_policy_engine", lambda: eng)
        return eng

    return make


@pytest.fixture
def unlabelled():
    set_environment_resolver(lambda target: None)


def _warnings(caplog, text: str) -> list[logging.LogRecord]:
    return [r for r in caplog.records if r.levelno >= logging.WARNING and text in r.getMessage()]


def test_no_warning_when_no_rule_is_scoped_by_environment(rules, unlabelled, caplog):
    rules('deny:\n  - name: no-deletes\n    operations: ["vm_delete"]\n    reason: never\n')
    with caplog.at_level(logging.WARNING):
        guard("aria", "list_resources", {}, target="")
    assert _warnings(caplog, UNLABELLED) == []


def test_no_warning_with_an_empty_rule_set(rules, unlabelled, caplog):
    rules("deny: []\n")
    with caplog.at_level(logging.WARNING):
        guard("aria", "list_resources", {}, target="lab")
    assert _warnings(caplog, UNLABELLED) == []


def test_warns_once_when_an_environment_scoped_rule_exists(rules, unlabelled, caplog):
    rules(
        "deny:\n"
        "  - name: prod-freeze\n"
        '    operations: ["vm_delete"]\n'
        '    environments: ["production"]\n'
        "    reason: prod frozen\n"
    )
    with caplog.at_level(logging.WARNING):
        guard("aria", "list_resources", {}, target="lab")
        guard("aria", "get_resource", {}, target="lab")
    assert len(_warnings(caplog, UNLABELLED)) == 1


def test_resolve_environment_called_directly_still_warns(unlabelled, caplog):
    """Back-compatible default for any direct caller."""
    with caplog.at_level(logging.WARNING):
        assert resolve_environment("lab") == ""
    assert len(_warnings(caplog, UNLABELLED)) == 1


def test_a_broken_resolver_is_reported_even_without_scoped_rules(rules, caplog):
    rules("deny: []\n")

    def broken(target):
        raise RuntimeError("config unreadable")

    set_environment_resolver(broken)
    with caplog.at_level(logging.WARNING):
        guard("aria", "list_resources", {}, target="lab")
    assert _warnings(caplog, "Environment resolver failed")
