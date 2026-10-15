"""Every list tool's ``limit`` is validated once, in @vmware_tool (2026-10-15).

Nine repos slice ``results[:limit]`` themselves. ``limit=-1`` silently dropped
the LAST row ("Showing 2 of 3"), ``limit=0`` returned nothing, while the shared
envelope reads both as "unlimited". Five repos already refused ``limit < 1`` on
their own; this makes it the family rule, at the one place every tool passes.
"""

from __future__ import annotations

import pytest

from vmware_policy.decorators import ToolArgumentError, vmware_tool


@vmware_tool(risk_level="low")
def list_things(limit: int | None = None) -> dict:
    rows = ["a", "b", "c"]
    return {"items": rows[:limit] if limit is not None else rows}


@pytest.mark.parametrize("bad", [0, -1, -50, True, "10", 2.5])
def test_a_limit_that_is_not_a_positive_integer_is_refused(bad):
    with pytest.raises(ToolArgumentError) as exc:
        list_things(limit=bad)
    assert "limit" in str(exc.value) and "omit" in str(exc.value)


def test_refusal_is_a_value_error_so_every_repo_shows_its_text():
    assert issubclass(ToolArgumentError, ValueError)


@pytest.mark.parametrize("ok", [None, 1, 2, 500])
def test_valid_limits_pass_through(ok):
    assert list_things(limit=ok)["items"] == (["a", "b", "c"][:ok] if ok else ["a", "b", "c"])


def test_positional_limit_is_checked_too():
    with pytest.raises(ToolArgumentError):
        list_things(-1)


def test_a_tool_without_limit_is_untouched():
    @vmware_tool(risk_level="low")
    def get_thing(name: str) -> str:
        return name

    assert get_thing("x") == "x"


def test_cli_commands_follow_the_same_rule(tmp_path, monkeypatch):
    from vmware_policy import audited
    from vmware_policy import guard as guard_mod
    from vmware_policy.audit import AuditEngine

    eng = AuditEngine(db_path=tmp_path / "audit.db")
    monkeypatch.setattr(guard_mod, "get_engine", lambda: eng)

    @audited("list_vms")
    def vm_list(limit: int | None = None) -> None:
        return None

    with pytest.raises(ToolArgumentError):
        vm_list(limit=-1)
    row = eng.query(limit=1)[0]
    assert row["status"] == "error" and row["surface"] == "cli"
