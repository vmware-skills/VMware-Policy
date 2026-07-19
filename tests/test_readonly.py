"""Read-only mode gate: write tools must not exist in the MCP tool registry.

Motivation (VMware-AIops issue #31, juanpf-ha): operators running local models
(Llama 3.3 70B via Goose) had to hand-write a prompt instruction "work
exclusively in read-only mode and never modify anything" because the family
only declared read-only intent in documentation. A prompt-level promise is not
a guarantee — a weak model can still call a write tool. This gate removes write
tools from the registry entirely, so ``list_tools()`` never offers them and the
model has no hallucination surface.

Design contract asserted here:

* precedence: per-skill env > family env > config flag > default off
* a write tool is anything NOT positively proven read-only
* enumeration failure is fail-closed (raise), never silent pass-through
"""

from dataclasses import dataclass, field
from typing import Optional

import pytest

from vmware_policy.readonly import (
    ReadOnlyGateError,
    apply_read_only_gate,
    read_only_enabled,
)

FAMILY_ENV = "VMWARE_READ_ONLY"
SKILL_ENV = "VMWARE_ARIA_READ_ONLY"


@pytest.fixture(autouse=True)
def _clear_env(monkeypatch):
    """Every test starts with no read-only env vars set."""
    monkeypatch.delenv(FAMILY_ENV, raising=False)
    monkeypatch.delenv(SKILL_ENV, raising=False)


# ---------------------------------------------------------------------------
# Fake FastMCP registry
#
# vmware-policy is a transitive dependency of every skill and deliberately does
# not depend on `mcp`, so these tests pin the gate's *semantics* against a
# stand-in shaped like FastMCP. The real FastMCP API contract (that
# `_tool_manager.list_tools()` and `remove_tool()` still behave as assumed) is
# pinned separately by the integration test in each skill repo.
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class _Annotations:
    readOnlyHint: Optional[bool] = None  # noqa: N815 — mirrors the MCP field name


@dataclass(frozen=True)
class _Tool:
    name: str
    description: str
    annotations: Optional[_Annotations] = None


@dataclass
class _ToolManager:
    tools: dict = field(default_factory=dict)

    def list_tools(self) -> list:
        return list(self.tools.values())


class _FakeMCP:
    """Stand-in exposing the same surface the gate relies on."""

    def __init__(self, tools: list) -> None:
        self._tool_manager = _ToolManager({t.name: t for t in tools})

    def remove_tool(self, name: str) -> None:
        self._tool_manager.tools.pop(name, None)


def _server() -> _FakeMCP:
    """Build a registry covering every marker permutation."""
    return _FakeMCP(
        [
            _Tool("read_annotated", "[READ] Annotated and marked read.", _Annotations(True)),
            _Tool("write_annotated", "[WRITE] Annotated and marked write.", _Annotations(False)),
            _Tool("read_docstring_only", "[READ] No annotations, positively marked read."),
            _Tool("write_docstring_only", "[WRITE] No annotations, marked write."),
            _Tool("unmarked", "No marker of any kind — must be treated as a write."),
            _Tool("contradictory", "[WRITE] Annotation says read but docstring says write.", _Annotations(True)),
            _Tool("vm_guest_download", "[READ] Marked read everywhere, writes a local file.", _Annotations(True)),
        ]
    )


def _names(mcp: _FakeMCP) -> set[str]:
    return {t.name for t in mcp._tool_manager.list_tools()}


# ---------------------------------------------------------------------------
# read_only_enabled — precedence
# ---------------------------------------------------------------------------


def test_default_is_off():
    assert read_only_enabled("vmware-aria") is False


def test_config_flag_enables():
    assert read_only_enabled("vmware-aria", config_flag=True) is True


def test_family_env_enables(monkeypatch):
    monkeypatch.setenv(FAMILY_ENV, "true")
    assert read_only_enabled("vmware-aria") is True


def test_family_env_covers_every_skill(monkeypatch):
    """One env var must put the whole family into read-only mode."""
    monkeypatch.setenv(FAMILY_ENV, "1")
    for skill in ("vmware-aria", "vmware-aiops", "vmware-nsx", "vmware-avi"):
        assert read_only_enabled(skill) is True


def test_skill_env_overrides_family(monkeypatch):
    """Per-skill env wins over the family default, in both directions."""
    monkeypatch.setenv(FAMILY_ENV, "true")
    monkeypatch.setenv(SKILL_ENV, "false")
    assert read_only_enabled("vmware-aria") is False

    monkeypatch.setenv(FAMILY_ENV, "false")
    monkeypatch.setenv(SKILL_ENV, "true")
    assert read_only_enabled("vmware-aria") is True


def test_env_overrides_config_flag(monkeypatch):
    monkeypatch.setenv(FAMILY_ENV, "false")
    assert read_only_enabled("vmware-aria", config_flag=True) is False


@pytest.mark.parametrize("value", ["true", "TRUE", "True", "1", "yes", "on"])
def test_truthy_values(monkeypatch, value):
    monkeypatch.setenv(FAMILY_ENV, value)
    assert read_only_enabled("vmware-aria") is True


@pytest.mark.parametrize("value", ["false", "FALSE", "0", "no", "off", ""])
def test_falsy_values(monkeypatch, value):
    monkeypatch.setenv(FAMILY_ENV, value)
    assert read_only_enabled("vmware-aria") is False


@pytest.mark.parametrize("value", ["ture", "enabled", "maybe"])
def test_unparseable_value_fails_closed(monkeypatch, value):
    """A typo'd switch must not silently leave write tools exposed."""
    monkeypatch.setenv(FAMILY_ENV, value)
    assert read_only_enabled("vmware-aria") is True


def test_skill_name_normalised_to_env_key(monkeypatch):
    """A hyphenated skill name maps to the underscored upper-case env var."""
    monkeypatch.setenv("VMWARE_NSX_SECURITY_READ_ONLY", "true")
    assert read_only_enabled("vmware-nsx-security") is True
    assert read_only_enabled("vmware-nsx") is False


# ---------------------------------------------------------------------------
# apply_read_only_gate — registry filtering
# ---------------------------------------------------------------------------


def test_gate_off_removes_nothing():
    mcp = _server()
    before = _names(mcp)
    removed = apply_read_only_gate(mcp, "vmware-aria", config_flag=False)
    assert removed == []
    assert _names(mcp) == before


def test_gate_on_keeps_positively_marked_read_tools(monkeypatch):
    monkeypatch.setenv(FAMILY_ENV, "true")
    mcp = _server()
    apply_read_only_gate(mcp, "vmware-aria")
    assert _names(mcp) == {"read_annotated", "read_docstring_only"}


def test_gate_on_removes_annotated_write_tool(monkeypatch):
    monkeypatch.setenv(FAMILY_ENV, "true")
    mcp = _server()
    removed = apply_read_only_gate(mcp, "vmware-aria")
    assert "write_annotated" in removed
    assert "write_annotated" not in _names(mcp)


def test_gate_on_removes_docstring_only_write_tool(monkeypatch):
    monkeypatch.setenv(FAMILY_ENV, "true")
    mcp = _server()
    removed = apply_read_only_gate(mcp, "vmware-aria")
    assert "write_docstring_only" in removed


def test_gate_on_removes_unmarked_tool_fail_closed(monkeypatch):
    """An unmarked tool is not provably read-only, so it must be removed."""
    monkeypatch.setenv(FAMILY_ENV, "true")
    mcp = _server()
    removed = apply_read_only_gate(mcp, "vmware-aria")
    assert "unmarked" in removed


def test_gate_on_removes_contradictory_tool_fail_closed(monkeypatch):
    """readOnlyHint=True but [WRITE] docstring — the stricter signal wins."""
    monkeypatch.setenv(FAMILY_ENV, "true")
    mcp = _server()
    removed = apply_read_only_gate(mcp, "vmware-aria")
    assert "contradictory" in removed


def test_gate_returns_sorted_removed_names(monkeypatch):
    monkeypatch.setenv(FAMILY_ENV, "true")
    mcp = _server()
    removed = apply_read_only_gate(mcp, "vmware-aria")
    assert removed == sorted(removed)
    assert removed == [
        "contradictory",
        "unmarked",
        "vm_guest_download",
        "write_annotated",
        "write_docstring_only",
    ]


def test_force_write_override_beats_read_markers(monkeypatch):
    """vm_guest_download is [READ] + readOnlyHint=True on every signal, but it
    writes an operator-controlled local path and takes guest credentials, so the
    override list must still classify it as a write tool."""
    monkeypatch.setenv(FAMILY_ENV, "true")
    mcp = _server()
    removed = apply_read_only_gate(mcp, "vmware-aria")
    assert "vm_guest_download" in removed
    assert "vm_guest_download" not in _names(mcp)


def test_force_write_override_is_inert_when_gate_off():
    mcp = _server()
    apply_read_only_gate(mcp, "vmware-aria", config_flag=False)
    assert "vm_guest_download" in _names(mcp)


def test_gate_is_idempotent(monkeypatch):
    """Applying the gate twice is safe and the second pass removes nothing."""
    monkeypatch.setenv(FAMILY_ENV, "true")
    mcp = _server()
    apply_read_only_gate(mcp, "vmware-aria")
    assert apply_read_only_gate(mcp, "vmware-aria") == []


def test_read_only_server_exposes_no_write_tools(monkeypatch):
    """End-to-end contract: nothing left in the registry may be a write tool."""
    monkeypatch.setenv(FAMILY_ENV, "true")
    mcp = _server()
    apply_read_only_gate(mcp, "vmware-aria")
    for tool in mcp._tool_manager.list_tools():
        assert (tool.description or "").lstrip().startswith("[READ]")
        if tool.annotations is not None:
            assert tool.annotations.readOnlyHint is not False


# ---------------------------------------------------------------------------
# fail-closed on enumeration failure
# ---------------------------------------------------------------------------


def test_unenumerable_registry_raises_when_gate_on(monkeypatch):
    """If we cannot enumerate tools we must refuse to start, not run open."""
    monkeypatch.setenv(FAMILY_ENV, "true")

    class Broken:
        pass

    with pytest.raises(ReadOnlyGateError):
        apply_read_only_gate(Broken(), "vmware-aria")


def test_unenumerable_registry_is_ignored_when_gate_off():
    """With the gate off there is nothing to guarantee, so do not raise."""

    class Broken:
        pass

    assert apply_read_only_gate(Broken(), "vmware-aria", config_flag=False) == []


def test_removal_failure_raises(monkeypatch):
    """A registry that silently keeps a write tool must abort startup."""
    monkeypatch.setenv(FAMILY_ENV, "true")
    mcp = _server()
    monkeypatch.setattr(mcp, "remove_tool", lambda name: None)
    with pytest.raises(ReadOnlyGateError):
        apply_read_only_gate(mcp, "vmware-aria")
