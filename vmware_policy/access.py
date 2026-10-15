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

``requirements`` is the skill's table ``{tool name: [privilege ids]}``. An empty
list means the tool needs no vSphere privilege (it reads local state, or calls
another API with its own credentials). ``None`` means access is decided by a
permission this check cannot see (a Supervisor namespace role, say): the tool
is always ``undetermined``. Never list only a tool's read privileges when it
also needs one the table cannot name — that reads as "granted" for an account
that will be refused. The
family gate checks that every registered tool has an entry and that every
privilege id is one vSphere defines.
"""

from __future__ import annotations

import difflib
from collections.abc import Mapping, Sequence
from typing import Any

from vmware_policy.sanitize import sanitize

GRANTED = "granted_at_root"
NOT_GRANTED = "not_granted_at_root"
UNDETERMINED = "undetermined"
NO_PRIVILEGE = "no_platform_privilege_needed"

_MEANING = {
    GRANTED: (
        "The account holds every privilege this tool needs on the root folder. A permission set "
        "directly on a specific object (for example NoAccess on a folder) still overrides it there."
    ),
    NOT_GRANTED: (
        "The account lacks these privileges on the root folder. They may still be granted on "
        "specific objects (a cluster, folder or VM); the tool works there and fails elsewhere "
        "with NoPermission."
    ),
    UNDETERMINED: (
        "The platform did not answer, so access is unknown; it is not assumed either way."
    ),
    NO_PRIVILEGE: (
        "This tool needs no vSphere privilege: it reads local state, or calls another API with "
        "its own credentials."
    ),
}


def _clean(text: Any) -> str:
    """Platform text (names an operator can set) goes to an agent: sanitize it."""
    return sanitize(str(text), 200)


def unknown_tool_message(
    tool: str | None, requirements: Mapping[str, Sequence[str] | None]
) -> str | None:
    """The teaching error for a tool name this server lacks, or None. Needs no connection.

    Skills call it before connecting, so a typo costs no login and is not
    reported as a connection problem.
    """
    if tool is None or tool in requirements:
        return None
    return str(_unknown_tool(tool, requirements))


def _unknown_tool(tool: str, requirements: Mapping[str, Sequence[str] | None]) -> ValueError:
    close = difflib.get_close_matches(tool, list(requirements), n=3, cutoff=0.5)
    hint = f" Did you mean {', '.join(close)}?" if close else ""
    return ValueError(
        f"No tool named {tool!r} on this server.{hint} Omit 'tool' to see every tool's status."
    )


_PROBE = "System.View"  # defined on every vCenter and ESXi


def _ask(si: Any, session_key: str, privileges: list[str]) -> dict[str, bool]:
    answer = si.content.authorizationManager.HasPrivilegeOnEntities(
        entity=[si.content.rootFolder], sessionId=session_key, privId=privileges
    )
    return {a.privId: bool(a.isGranted) for a in answer[0].privAvailability}


def _privilege_states(
    si: Any, session_key: str, privileges: list[str]
) -> tuple[dict[str, str], str | None]:
    """Ask in one batch; if the batch fails, ask per privilege.

    A host that does not define one id (ESXi lacks vCenter-only privileges) may
    refuse the whole batch; asking one at a time keeps the others answered and
    marks only the ids that fail as undetermined.
    """
    if not privileges:
        return {}, None
    failed: dict[str, str] = {}
    try:
        seen = _ask(si, session_key, privileges)
    except Exception as batch_exc:
        seen = {}
        try:
            # Every host defines System.View. If even it cannot be asked, the
            # link or the session is the problem: asking each id would only
            # repeat the same failure once per privilege.
            _ask(si, session_key, [_PROBE])
        except Exception:
            failed = {p: type(batch_exc).__name__ for p in privileges}
        else:
            for p in privileges:
                try:
                    seen.update(_ask(si, session_key, [p]))
                except Exception as exc:  # the class name only: the text can name hosts
                    failed[p] = type(exc).__name__
    states = {
        p: (GRANTED if seen[p] else NOT_GRANTED) if p in seen else UNDETERMINED for p in privileges
    }
    parts = []
    if failed:
        names = ", ".join(f"{p} ({c})" for p, c in sorted(failed.items()))
        parts.append(f"the target could not check {names}")
    unanswered = [p for p, s in states.items() if s == UNDETERMINED and p not in failed]
    if unanswered:
        parts.append(f"no answer for {', '.join(unanswered)}")
    reason = "HasPrivilegeOnEntities: " + "; ".join(parts) if parts else None
    return states, reason


def login_has_no_session(si: Any) -> bool:
    """True when a login succeeded but vCenter shows no session for it.

    That is what an account with no vSphere role looks like (AIops#47): the
    login is accepted, ``currentSession`` reads ``None``, and every inventory
    call then fails with NotAuthenticated. Called right after connecting, so an
    expired session is not the explanation. If the property cannot be read the
    answer is unknown, and unknown is not a verdict: ``False``.
    """
    try:
        return si.content.sessionManager.currentSession is None
    except Exception:
        return False


def no_role_message(target: str, cli: str) -> str:
    """The teaching error for :func:`login_has_no_session`, shared by the vSphere skills."""
    return (
        f"Logged in to target '{target}', but vCenter shows no session for this account, "
        "so it cannot read anything: the account most likely has no vSphere role. Assign one "
        "(Read-Only or higher) to the account on the vCenter root folder (Administration > "
        f"Access Control > Global Permissions), then run '{cli} doctor'. Changing the password "
        "will not help."
    )


OUTSIDE_REASON = (
    "This tool is decided by a permission this check cannot see (for example a Supervisor "
    "namespace role), so access is unknown here; it is not assumed either way."
)


def _verdict(required: Sequence[str] | None, states: Mapping[str, str]) -> str:
    if required is None:
        return UNDETERMINED
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
    return [
        {
            "role": _clean(roles.get(p.roleId, str(p.roleId))),
            "on": _clean(_entity_label(p.entity)),
            "propagate": bool(p.propagate),
        }
        for p in perms
    ], note


def _entity_label(entity: Any) -> str:
    """The object's name, or its managed-object id when the name cannot be read.

    Reading ``name`` is a round trip and can raise (NoPermission on an object the
    account may not see, e.g. a NoAccess grant); its text names hosts, so only
    the local moId is used then.
    """
    try:
        name = entity.name
    except Exception:
        name = None
    return name or str(getattr(entity, "_moId", None) or "unknown object")


def vsphere_access_info(
    si: Any,
    *,
    target: str,
    requirements: Mapping[str, Sequence[str] | None],
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
                (requirements[tool] or [])
                if tool is not None
                else [x for v in requirements.values() for x in (v or [])]
            )
        }
    )
    try:
        session = si.content.sessionManager.currentSession
    except Exception:
        session = None
    user = getattr(session, "userName", None) if session else None
    out: dict[str, Any] = {
        "target": target,
        "account": _clean(user) if user else None,
        "checked_on": "root folder (permissions on specific objects are not covered)",
    }
    if session is None:
        states = {p: UNDETERMINED for p in wanted}
        reason: str | None = (
            "vCenter shows no session for this login, so its privileges could not be asked. "
            "If the login itself succeeded, the account most likely has no vSphere role: "
            "assign one (Read-Only or higher) on the vCenter root folder. Otherwise the "
            "session expired; retry."
        )
    else:
        states, reason = _privilege_states(si, session.key, wanted)
    out["privileges"] = states
    if reason:
        out["reason"] = reason

    if tool is not None:
        entry = requirements[tool]
        required = None if entry is None else list(entry)
        verdict = _verdict(required, states)
        info: dict[str, Any] = {
            "name": tool,
            "requires": required,
            "verdict": verdict,
            "meaning": _MEANING[verdict],
        }
        if verdict == NOT_GRANTED:
            info["missing_at_root"] = [p for p in required or [] if states.get(p) == NOT_GRANTED]
        if verdict == UNDETERMINED:
            info["reason"] = (
                OUTSIDE_REASON
                if required is None
                else reason or "No answer for this tool's privileges."
            )
        out["tool"] = info
    else:
        by: dict[str, list[str]] = {
            GRANTED: [],
            NOT_GRANTED: [],
            UNDETERMINED: [],
            NO_PRIVILEGE: [],
        }
        for name in sorted(requirements):
            by[_verdict(requirements[name], states)].append(name)
        out["tools_granted_at_root"] = by[GRANTED]
        out["tools_not_granted_at_root"] = by[NOT_GRANTED]
        out["tools_undetermined"] = by[UNDETERMINED]
        out["tools_no_privilege_needed"] = by[NO_PRIVILEGE]
        if by[UNDETERMINED]:
            out["meaning"] = _MEANING[UNDETERMINED]
        elif by[NOT_GRANTED]:
            out["meaning"] = _MEANING[NOT_GRANTED]
        elif by[GRANTED]:
            out["meaning"] = _MEANING[GRANTED]
        else:
            out["meaning"] = _MEANING[NO_PRIVILEGE]

    if session is not None and user:
        out["direct_permissions"], out["direct_permissions_note"] = _direct_permissions(si, user)
    return out
