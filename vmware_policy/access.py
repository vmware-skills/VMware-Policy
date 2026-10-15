"""Access self-diagnosis for vSphere skills (HLD §17 D-17).

``vsphere_access_info`` answers "which account is this server using, and may it
do what tool X needs?" by asking vCenter (or ESXi) about the *current session*
— ``AuthorizationManager.HasPrivilegeOnEntities`` needs only System.View, so
every account can ask about itself.

The answer is about the **root folder**. Permissions also propagate from, or
are granted on, specific objects (a cluster, a folder, one VM), so a privilege
that is not granted at the root may still be granted where the tool acts:
``not_granted_at_root`` is never reported as "no access". A lookup that fails
is ``undetermined`` with the error's class name (not its text, which can carry
host names), and is never read as granted.

``requirements`` is the skill's table ``{tool name: [privilege ids]}``; an empty
list means the tool needs no platform privilege (it reads local state). The
family gate checks that every registered tool has an entry and that every
privilege id is one vSphere defines.
"""

from __future__ import annotations

import difflib
from collections.abc import Mapping, Sequence
from typing import Any

GRANTED = "granted_at_root"
NOT_GRANTED = "not_granted_at_root"
UNDETERMINED = "undetermined"
NO_PRIVILEGE = "no_platform_privilege_needed"

_MEANING = {
    GRANTED: (
        "The account holds every privilege this tool needs on the root folder, so on every object."
    ),
    NOT_GRANTED: (
        "The account lacks these privileges on the root folder. They may still be granted on "
        "specific objects (a cluster, folder or VM); the tool works there and fails elsewhere "
        "with NoPermission."
    ),
    UNDETERMINED: (
        "The platform did not answer, so access is unknown; it is not assumed either way."
    ),
    NO_PRIVILEGE: "This tool reads local state only and needs no privilege on the platform.",
}


def _unknown_tool(tool: str, requirements: Mapping[str, Sequence[str]]) -> ValueError:
    close = difflib.get_close_matches(tool, list(requirements), n=3, cutoff=0.5)
    hint = f" Did you mean {', '.join(close)}?" if close else ""
    return ValueError(
        f"No tool named {tool!r} on this server.{hint} Omit 'tool' to see every tool's status."
    )


def _privilege_states(
    si: Any, session_key: str, privileges: list[str]
) -> tuple[dict[str, str], str | None]:
    if not privileges:
        return {}, None
    am = si.content.authorizationManager
    try:
        answer = am.HasPrivilegeOnEntities(
            entity=[si.content.rootFolder], sessionId=session_key, privId=privileges
        )
        seen = {a.privId: bool(a.isGranted) for a in answer[0].privAvailability}
    except Exception as exc:  # the class name only: the text can name hosts
        return {
            p: UNDETERMINED for p in privileges
        }, f"HasPrivilegeOnEntities failed ({type(exc).__name__})"
    states = {
        p: (GRANTED if seen[p] else NOT_GRANTED) if p in seen else UNDETERMINED for p in privileges
    }
    missing = [p for p, s in states.items() if s == UNDETERMINED]
    reason = f"vCenter returned no answer for {', '.join(missing)}" if missing else None
    return states, reason


def _verdict(required: Sequence[str], states: Mapping[str, str]) -> str:
    if not required:
        return NO_PRIVILEGE
    values = [states.get(p, UNDETERMINED) for p in required]
    if UNDETERMINED in values:
        return UNDETERMINED
    if all(v == GRANTED for v in values):
        return GRANTED
    return NOT_GRANTED


def _direct_permissions(si: Any, user: str) -> tuple[list[dict[str, Any]] | None, str]:
    am = si.content.authorizationManager
    note = (
        "Permissions granted to the account by name. Permissions it gets through a group are not "
        "listed here; the privilege check above includes them."
    )
    try:
        roles = {r.roleId: r.name for r in am.roleList}
        perms = [p for p in am.RetrieveAllPermissions() if str(p.principal).lower() == user.lower()]
    except Exception as exc:
        return (
            None,
            f"Could not read permissions ({type(exc).__name__}); "
            "the privilege check still applies.",
        )
    listed = [
        {
            "role": roles.get(p.roleId, str(p.roleId)),
            "on": getattr(p.entity, "name", None) or str(p.entity),
            "propagate": bool(p.propagate),
        }
        for p in perms
    ]
    return listed, note


def vsphere_access_info(
    si: Any,
    *,
    target: str,
    requirements: Mapping[str, Sequence[str]],
    tool: str | None = None,
) -> dict[str, Any]:
    """Who this server acts as on ``target``, and whether it holds what ``tool`` needs.

    Without ``tool``, every tool in ``requirements`` is summarized.
    """
    if tool is not None and tool not in requirements:
        raise _unknown_tool(tool, requirements)
    wanted = sorted(
        {
            p
            for p in (
                requirements[tool]
                if tool is not None
                else [x for v in requirements.values() for x in v]
            )
        }
    )
    try:
        session = si.content.sessionManager.currentSession
    except Exception:
        session = None
    out: dict[str, Any] = {
        "target": target,
        "account": getattr(session, "userName", None) if session else None,
        "checked_on": "root folder (permissions on specific objects are not covered)",
    }
    if session is None:
        states = {p: UNDETERMINED for p in wanted}
        reason: str | None = (
            "No current session on the target, so its privileges could not be asked."
        )
    else:
        states, reason = _privilege_states(si, session.key, wanted)
    out["privileges"] = states
    if reason:
        out["reason"] = reason

    if tool is not None:
        required = list(requirements[tool])
        verdict = _verdict(required, states)
        info: dict[str, Any] = {
            "name": tool,
            "requires": required,
            "verdict": verdict,
            "meaning": _MEANING[verdict],
        }
        if verdict == NOT_GRANTED:
            info["missing_at_root"] = [p for p in required if states.get(p) == NOT_GRANTED]
        if verdict == UNDETERMINED:
            info["reason"] = reason or "No answer for this tool's privileges."
        out["tool"] = info
    else:
        by: dict[str, list[str]] = {GRANTED: [], NOT_GRANTED: [], UNDETERMINED: []}
        for name in sorted(requirements):
            v = _verdict(requirements[name], states)
            by[GRANTED if v == NO_PRIVILEGE else v].append(name)
        out["tools_granted_at_root"] = by[GRANTED]
        out["tools_not_granted_at_root"] = by[NOT_GRANTED]
        out["tools_undetermined"] = by[UNDETERMINED]
        out["meaning"] = _MEANING[NOT_GRANTED] if by[NOT_GRANTED] else _MEANING[GRANTED]

    if session is not None and out["account"]:
        out["direct_permissions"], out["direct_permissions_note"] = _direct_permissions(
            si, out["account"]
        )
    return out
