"""Read-only mode: remove write tools from an MCP registry before serving.

Why this exists
---------------
The family has always *documented* which tools mutate state — every tool
carries a ``[READ]``/``[WRITE]`` docstring marker and an MCP ``readOnlyHint``
annotation. Documentation is a promise to a cooperative reader, not a
guarantee. An operator running a local model (VMware-AIops issue #31: Llama
3.3 70B via Goose) had to hand-write the prompt instruction *"work exclusively
in read-only mode and never modify alerts, definitions, reports or
configuration"* — and a weak model can ignore a prompt.

This gate makes the promise structural: when read-only mode is on, write tools
are removed from the registry, so ``list_tools()`` never offers them. The model
cannot call what it cannot see, and no prompt discipline is required.

Contract
--------
A tool that survives the gate does not modify remote infrastructure state.
Tools that only write to the skill's own local store (e.g. vmware-harden's
DuckDB twin) are still exposed — that store is a cache of observations, not
managed infrastructure.

Signals, in priority order
--------------------------
1. ``FORCE_WRITE`` — tools whose markers under-report their real effect.
2. ``[WRITE]`` docstring prefix.
3. ``readOnlyHint=False`` annotation.
4. ``[READ]`` docstring prefix.
5. ``readOnlyHint=True`` annotation.
6. Nothing conclusive → treated as a write tool.

The docstring marker outranks the annotation because it has 100% coverage
across the family, while vmware-harden and vmware-debug build their tools
through a ``build_server()`` factory that passes no annotations at all.

Fail-closed everywhere
----------------------
If read-only mode is requested but cannot be *proven* — the registry cannot be
enumerated, or a removal does not take effect — startup aborts with
:class:`ReadOnlyGateError`. An unparseable switch value (``VMWARE_READ_ONLY=ture``)
does not abort; it resolves to *on* with a warning, so a typo locks the deployment
down rather than leaving it open. A read-only mode that silently degrades to
read-write is worse than none, because operators stop checking.
"""

from __future__ import annotations

import logging
import os
from typing import Any, NamedTuple

_log = logging.getLogger("vmware_policy.readonly")

#: Family-wide switch — one variable puts every VMware skill into read-only mode.
FAMILY_ENV = "VMWARE_READ_ONLY"

_TRUTHY = frozenset({"1", "true", "yes", "on"})
_FALSY = frozenset({"0", "false", "no", "off"})

#: Tools whose ``[READ]`` marker under-reports their real side effects.
#:
#: ``vm_guest_download`` reads from the guest OS — read-only with respect to
#: vCenter, which is why all three of its signals say read — but it writes to an
#: operator-supplied ``local_path`` and accepts guest credentials. Both are
#: side effects a locked-down deployment should opt into explicitly rather than
#: receive by default.
FORCE_WRITE: frozenset[str] = frozenset(
    {
        # AIops: reads from the guest OS, but writes to an operator-supplied
        # local path and takes guest credentials.
        "vm_guest_download",
        # VKS: both kubeconfig tools materialise a session-token credential
        # file at a model-supplied local path — the same shape as
        # vm_guest_download (read-only upstream, write-effecting locally).
        # Found by the 2026-07-18 review: the list drifted within the release
        # that introduced it (踩坑 #21, reproduced inside one commit).
        "get_supervisor_kubeconfig",
        "get_tkc_kubeconfig",
    }
)


class ReadOnlyGateError(RuntimeError):
    """Read-only mode was requested but could not be guaranteed."""


# ---------------------------------------------------------------------------
# Switch resolution
# ---------------------------------------------------------------------------


def _skill_env_key(skill: str) -> str:
    """Map a skill name to its per-skill env var (``vmware-nsx-security`` →
    ``VMWARE_NSX_SECURITY_READ_ONLY``)."""
    stem = skill.strip().upper().replace("-", "_")
    if not stem.startswith("VMWARE_"):
        stem = f"VMWARE_{stem}"
    return f"{stem}_READ_ONLY"


def _parse(value: str | None, source: str) -> bool | None:
    """Parse a switch value. ``None`` means "not set"; unparseable means on.

    A blank string also means "not set": ``"env": {"VMWARE_READ_ONLY": ""}`` is
    a template leftover, not a decision, and treating it as an explicit *off*
    let it override ``read_only: true`` in config — a fail-open path in a
    module whose contract is fail-closed (2026-07-18 review).
    """
    if value is None:
        return None
    normalised = value.strip().lower()
    if not normalised:
        return None
    if normalised in _TRUTHY:
        return True
    if normalised in _FALSY:
        return False
    _log.warning(
        "%s has unrecognised value %r — enabling read-only mode (fail-closed). "
        "Use one of: true, false, 1, 0, yes, no, on, off.",
        source,
        value,
    )
    return True


def read_only_enabled(skill: str, config_flag: bool | None = None) -> bool:
    """Return whether ``skill`` should run in read-only mode.

    Precedence: per-skill env var > family env var > ``config_flag`` > off.
    The env vars come first so an operator can lock a deployment down from the
    MCP client's ``env`` block without editing any config file.
    """
    for key in (_skill_env_key(skill), FAMILY_ENV):
        parsed = _parse(os.environ.get(key), key)
        if parsed is not None:
            return parsed
    return bool(config_flag)


class ReadOnlyStatus(NamedTuple):
    """Where a skill's read-only setting resolved from, for `doctor` to report.

    ``enabled`` is the same answer :func:`read_only_enabled` gives. The rest
    exists because "is my lockdown actually on?" had no answer outside the MCP
    server's start-up log — an operator who set the switch could not confirm it
    took, which is a poor property for a control whose whole promise is
    fail-closed.
    """

    enabled: bool
    source: str  # env var name, "config", or "default"
    raw: str  # the value as written, "" when unset
    recognised: bool  # False when the value was a typo that fell through to on


def read_only_status(skill: str, config_flag: bool | None = None) -> ReadOnlyStatus:
    """Resolve read-only mode *and* report where the answer came from.

    Kept here rather than in each skill's ``doctor.py`` so the precedence chain
    has one implementation. Ten copies of "build the env var name, walk the
    chain" is ten chances to drift from the gate that actually enforces it —
    and a doctor that disagrees with the gate is worse than no doctor.
    """
    for key in (_skill_env_key(skill), FAMILY_ENV):
        raw = os.environ.get(key)
        if raw is None or not raw.strip():
            continue
        normalised = raw.strip().lower()
        if normalised in _TRUTHY:
            return ReadOnlyStatus(True, key, raw, True)
        if normalised in _FALSY:
            return ReadOnlyStatus(False, key, raw, True)
        # Unparseable resolves to on, deliberately. Surface the raw value: this
        # is the one path where a deployment locks itself down over a typo.
        return ReadOnlyStatus(True, key, raw, False)
    if config_flag is not None:
        return ReadOnlyStatus(bool(config_flag), "config", str(config_flag), True)
    return ReadOnlyStatus(False, "default", "", True)


# ---------------------------------------------------------------------------
# Registry filtering
# ---------------------------------------------------------------------------


def _enumerate(mcp: Any) -> list[Any]:
    """Return the registered tools, or raise if the registry is unreadable.

    Uses FastMCP's synchronous ``_tool_manager.list_tools()`` because the gate
    runs at import time, where there is no event loop to await the public async
    ``list_tools()``. The private access is deliberate and pinned by tests: if
    an mcp upgrade moves it, the suite goes red rather than the gate silently
    passing everything through.
    """
    lister = getattr(getattr(mcp, "_tool_manager", None), "list_tools", None)
    if lister is None or not callable(getattr(mcp, "remove_tool", None)):
        raise ReadOnlyGateError(
            "Read-only mode is on but this MCP server does not expose the "
            "expected FastMCP tool registry (_tool_manager.list_tools / "
            "remove_tool), so write tools cannot be proven absent. Refusing to "
            "start. Check the installed 'mcp' package version."
        )
    try:
        return list(lister())
    except Exception as exc:  # noqa: BLE001 — re-raised as a gate failure
        raise ReadOnlyGateError(
            f"Read-only mode is on but the MCP tool registry could not be "
            f"enumerated ({type(exc).__name__}), so write tools cannot be "
            f"proven absent. Refusing to start."
        ) from exc


def _is_write_tool(tool: Any) -> bool:
    """Classify one registered tool. Anything not provably read-only is a write."""
    if getattr(tool, "name", "") in FORCE_WRITE:
        return True

    description = (getattr(tool, "description", "") or "").lstrip()
    annotations = getattr(tool, "annotations", None)
    hint = getattr(annotations, "readOnlyHint", None) if annotations is not None else None

    if description.startswith("[WRITE]"):
        return True
    if hint is False:
        return True
    if description.startswith("[READ]"):
        return False
    if hint is True:
        return False
    return True


def apply_read_only_gate(
    mcp: Any, skill: str, config_flag: bool | None = None
) -> list[str]:
    """Remove every write tool from ``mcp`` when read-only mode is on.

    Call this once, after all tool modules have registered and before the
    server runs. Returns the sorted names of the removed tools (empty when the
    mode is off), so the caller can log what was withheld.

    Idempotent: a second call finds nothing left to remove.
    """
    if not read_only_enabled(skill, config_flag):
        return []

    removed = sorted(
        tool.name for tool in _enumerate(mcp) if _is_write_tool(tool)
    )
    for name in removed:
        mcp.remove_tool(name)

    survivors = {tool.name for tool in _enumerate(mcp)}
    still_present = sorted(set(removed) & survivors)
    if still_present:
        raise ReadOnlyGateError(
            f"Read-only mode is on but these write tools survived removal: "
            f"{', '.join(still_present)}. Refusing to start."
        )

    if removed:
        _log.warning(
            "Read-only mode active for %s — withheld %d write tool(s): %s",
            skill,
            len(removed),
            ", ".join(removed),
        )
    return removed
