"""The audit row names the target a call used, also when the caller omitted it.

Found on a real Log Insight (2026-10-17): a tool called without ``target`` ran
against the config's ``default_target``, and its audit row recorded ``target``
as empty — so ``vmware-audit log`` could not say which system had been read.
Every skill that applies roles already declares a resolver that maps an omitted
target to the canonical name the connection uses (HLD §18); the audit row now
asks it and records ``resolved_target``. The parameters the caller sent are
recorded unchanged.
"""

from __future__ import annotations

import json

import pytest

import vmware_policy.audit as audit_mod
import vmware_policy.policy as policy_mod
from vmware_policy import roles
from vmware_policy.audit import AuditEngine
from vmware_policy.decorators import vmware_tool

SKILL = "probeskill"


@pytest.fixture(autouse=True)
def engine(tmp_path):
    eng = AuditEngine(tmp_path / "audit.db")
    audit_mod._engine = eng
    policy_mod._engine = None
    roles._reset_for_tests()
    yield eng
    roles._reset_for_tests()
    audit_mod._engine = None
    policy_mod._engine = None


def _tool(param: str = "target"):
    """A read tool whose module path makes the decorator infer SKILL."""
    if param == "target":
        def read_things(target: str | None = None) -> str:
            return "ok"
    else:
        def read_things(controller: str | None = None) -> str:
            return "ok"
    read_things.__module__ = f"vmware_{SKILL}.mcp_server.tools.things"
    return vmware_tool(read_things)


def _params(engine) -> dict:
    rows = engine.query(limit=5)
    assert len(rows) == 1, rows
    return json.loads(rows[0]["params"])


def test_omitted_target_is_recorded_as_the_resolved_default(engine):
    roles.declare_role_metadata(SKILL, resolver=lambda t: t or "lab-default")
    _tool()()
    params = _params(engine)
    assert params["resolved_target"] == "lab-default"
    # the parameters still say what the caller sent
    assert params["target"] is None


def test_explicit_target_is_recorded_as_passed(engine):
    roles.declare_role_metadata(SKILL, resolver=lambda t: "never-used")
    _tool()(target="vc-prod")
    params = _params(engine)
    assert params["target"] == "vc-prod" and "resolved_target" not in params


def test_resolver_failure_leaves_the_target_empty_not_the_call_broken(engine):
    def boom(_t):
        raise KeyError("no default")

    roles.declare_role_metadata(SKILL, resolver=boom)
    assert _tool()() == "ok"
    assert "resolved_target" not in _params(engine)


def test_skill_without_a_resolver_is_unchanged(engine):
    assert _tool()() == "ok"
    assert "resolved_target" not in _params(engine)


def test_declared_target_param_is_honoured(engine):
    # AVI names its target `controller`; omitted, it resolves like `target`.
    roles.declare_role_metadata(
        SKILL, resolver=lambda t: t or "avi-default", target_param="controller"
    )
    _tool("controller")()
    assert _params(engine)["resolved_target"] == "avi-default"


def test_explicit_declared_target_param_is_recorded(engine):
    roles.declare_role_metadata(
        SKILL, resolver=lambda t: t or "avi-default", target_param="controller"
    )
    _tool("controller")(controller="avi-2")
    params = _params(engine)
    assert params["controller"] == "avi-2" and "resolved_target" not in params
