"""Roles for network callers (HLD §18).

A role decides which tools and targets a bearer token may use **on one endpoint**.
Every caller still acts with the endpoint's vCenter account; RBAC stays the platform
boundary (D-19). Roles exist only after an operator opts in (``vmware-audit roles
enable``, D-24); until then nothing here changes behaviour.

Pieces:

* ``roles.yaml`` — custom role definitions, every key required ("all" is spelled
  ``"*"``) so a file truncated mid-edit cannot widen a role (D-20).
* Skill metadata — each skill declares which tools escape a role, which tools reach
  other tools (plans, batch, TTL), each tool's target scope, and how to resolve its
  default target (D-21/D-22). A skill that has not declared gets ``admin`` only.
* The registry snapshot — every tool of this process and whether it only reads,
  taken by ``serve()`` before exposure is applied (validation needs hidden tools too).
* :func:`decide` — the one check, called from ``@vmware_tool``'s pre-check.
"""

from __future__ import annotations

import fnmatch
import hashlib
import os
import re
import threading
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from vmware_policy.paths import ops_path

#: Built-in roles. ``reader``: tools whose readOnlyHint is exactly true, minus escape
#: tools, every skill, every target. ``admin``: everything the process exposes.
BUILTIN = ("reader", "admin")
APPROVE_MODES = ("none", "any", "others")
TOOLS_MODES = ("read", "*")
TARGET_SCOPES = ("one", "all", "none")
_ROLE_KEYS = frozenset({"skills", "approve"})
_GRANT_KEYS = frozenset({"tools", "allow_write", "allow_escape", "targets"})
_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
_NETWORK_SURFACES = ("mcp-https", "mcp-http-loopback")


class RoleError(ValueError):
    """``roles.yaml`` cannot be used; custom-role tokens are refused until it is fixed."""


@dataclass(frozen=True)
class SkillGrant:
    tools: str  # "read" | "*"
    allow_write: frozenset[str]
    allow_escape: frozenset[str]
    targets: tuple[str, ...] | None  # None = "*"


@dataclass(frozen=True)
class Role:
    name: str
    approve: str
    #: None for the built-ins: they apply to every skill.
    skills: Mapping[str, SkillGrant] | None = None


ADMIN = Role("admin", approve="any")
READER = Role("reader", approve="none")


@dataclass(frozen=True)
class Decision:
    allowed: bool
    role: str
    rule: str = ""
    reason: str = ""


# ── roles.yaml ──────────────────────────────────────────────────────────


def canonical_skill(name: str) -> str:
    """``nsx-security`` / ``vmware-nsx-security`` / ``nsx_security`` → ``nsx_security``."""
    name = name.strip().lower()
    if name.startswith("vmware-") or name.startswith("vmware_"):
        name = name[len("vmware-") :]
    return name.replace("-", "_")


def _str_list(value: Any, where: str) -> frozenset[str]:
    if not isinstance(value, list) or not all(isinstance(v, str) and v for v in value):
        raise RoleError(f"{where} must be a list of names ([] for none), got {value!r}")
    return frozenset(value)


def _grant(value: Any, where: str) -> SkillGrant:
    if not isinstance(value, dict):
        raise RoleError(f"{where} must be a mapping with keys {sorted(_GRANT_KEYS)}")
    missing, extra = _GRANT_KEYS - value.keys(), value.keys() - _GRANT_KEYS
    if missing or extra:
        raise RoleError(
            f"{where}: every key is required and no others are allowed "
            f"(missing {sorted(missing)}, unknown {sorted(extra)}); spell 'all' as \"*\""
        )
    if value["tools"] not in TOOLS_MODES:
        raise RoleError(f"{where}.tools must be 'read' or \"*\", got {value['tools']!r}")
    targets = value["targets"]
    if targets == "*":
        scoped: tuple[str, ...] | None = None
    else:
        scoped = tuple(sorted(_str_list(targets, f"{where}.targets")))
        if not scoped:
            raise RoleError(f'{where}.targets is empty; list target names or use "*"')
    return SkillGrant(
        tools=value["tools"],
        allow_write=_str_list(value["allow_write"], f"{where}.allow_write"),
        allow_escape=_str_list(value["allow_escape"], f"{where}.allow_escape"),
        targets=scoped,
    )


def parse_roles(text: str) -> tuple[dict[str, Role], dict[str, str]]:
    """``(roles, problems)``. A role with a problem is absent from ``roles``.

    Raises RoleError when the file as a whole cannot be read.
    """
    try:
        data = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        raise RoleError(f"roles.yaml is not valid YAML: {exc}") from exc
    if not isinstance(data, dict) or set(data) != {"roles"} or not isinstance(data["roles"], dict):
        raise RoleError("roles.yaml must contain exactly one top-level key, 'roles', a mapping")
    roles: dict[str, Role] = {}
    problems: dict[str, str] = {}
    for name, body in data["roles"].items():
        try:
            if not isinstance(name, str) or not _NAME.match(name):
                raise RoleError(f"role name {name!r}: use 1-64 letters, digits, '.', '_' or '-'")
            if name in BUILTIN:
                raise RoleError(f"role name {name!r} is built in and cannot be redefined")
            if not isinstance(body, dict) or body.keys() != _ROLE_KEYS:
                raise RoleError(f"role {name!r} needs exactly the keys {sorted(_ROLE_KEYS)}")
            if body["approve"] not in APPROVE_MODES:
                raise RoleError(f"role {name!r}: approve must be one of {APPROVE_MODES}")
            skills = body["skills"]
            if not isinstance(skills, dict) or not skills:
                raise RoleError(f"role {name!r}: skills must be a non-empty mapping")
            grants: dict[str, SkillGrant] = {}
            for skill, grant in skills.items():
                key = canonical_skill(str(skill))
                if key in grants:
                    raise RoleError(f"role {name!r}: skill {skill!r} is listed twice")
                grants[key] = _grant(grant, f"role {name!r} skills.{skill}")
            roles[name] = Role(name, approve=body["approve"], skills=grants)
        except RoleError as exc:
            problems[str(name)] = str(exc)
    return roles, problems


def roles_file() -> Path:
    return ops_path("roles.yaml")


def check_owned_private(path: Path) -> str | None:
    """None when ``path`` is ours and owner-only; otherwise why it must not be trusted."""
    from vmware_policy.fsperms import check_secret_file

    check = check_secret_file(path)
    if check.verdict != "ok":
        return check.message
    try:
        owner = path.stat().st_uid
    except OSError as exc:
        return f"cannot stat {path}: {exc}"
    if hasattr(os, "geteuid") and owner != os.geteuid():
        return f"{path} is owned by uid {owner}, not by the user running this server"
    return None


class RoleFile:
    """``roles.yaml``, re-read when it changes; a broken file refuses every custom role."""

    def __init__(self, path: Path | None = None, *, audit_reloads: bool = False) -> None:
        self._path = path or roles_file()
        self._lock = threading.Lock()
        self._audit_reloads = audit_reloads  # servers only; the CLI reads it on every command
        self._stamp: tuple[int, ...] | None = None
        self._roles: dict[str, Role] = {}
        self._problems: dict[str, str] = {}
        self._broken: str | None = None

    @property
    def path(self) -> Path:
        return self._path

    def exists(self) -> bool:
        return self._path.exists()

    def _stat(self) -> tuple[int, ...] | None:
        try:
            st = self._path.stat()
        except FileNotFoundError:
            return None
        # Mode and owner too: a chmod/chown changes nothing else, and the ownership
        # check runs only on a re-read (review LOW-1).
        return (st.st_ino, st.st_mtime_ns, st.st_size, st.st_mode, st.st_uid)

    def _refresh(self) -> None:
        stamp = self._stat()
        if stamp == self._stamp and stamp is not None:
            return
        roles: dict[str, Role] = {}
        problems: dict[str, str] = {}
        broken: str | None = None
        text = ""
        if stamp is not None:
            broken = check_owned_private(self._path)
            if broken is None:
                try:
                    text = self._path.read_text(encoding="utf-8")
                    if self._stat() != stamp:
                        # Edited in place while we read: a cut-short glob could widen a
                        # role. Refuse custom roles this call; the next one re-reads (LOW-2).
                        broken = f"{self._path} changed while it was being read"
                        stamp = (*stamp[:-1], -1)  # never equal to a real stamp
                    else:
                        roles, problems = parse_roles(text)
                except (RoleError, OSError) as exc:
                    broken = str(exc)
        # Replace the whole set at once: a reader never sees half a file.
        self._roles, self._problems, self._broken, self._stamp = roles, problems, broken, stamp
        if self._audit_reloads:
            self._audit_reload(text, roles, problems, broken)

    def _audit_reload(
        self, text: str, roles: dict[str, Role], problems: dict[str, str], broken: str | None
    ) -> None:
        """What the server now enforces, as an audit row (HLD §18 D-25, review MEDIUM-4)."""
        from vmware_policy.guard import audit_call

        params = {
            "path": str(self._path),
            "sha256": hashlib.sha256(text.encode("utf-8")).hexdigest() if text else "",
            "roles": sorted(roles),
            "refused_roles": sorted(problems),
        }
        audit_call(
            "policy",
            "roles_reload",
            params=params,
            status="error" if broken else "ok",
            result={"error": broken} if broken else {"ok": True},
        )

    def get(self, name: str) -> tuple[Role | None, str]:
        """``(role, "")`` or ``(None, why it cannot be used)``."""
        if name == "admin":
            return ADMIN, ""
        if name == "reader":
            return READER, ""
        with self._lock:
            self._refresh()
            if self._stamp is None:
                return None, f"role {name!r} is not defined: {self._path} does not exist"
            if self._broken:
                return None, f"{self._path} cannot be used: {self._broken}"
            if name in self._problems:
                return None, self._problems[name]
            role = self._roles.get(name)
            return (role, "") if role else (None, f"role {name!r} is not defined in {self._path}")

    def names(self) -> list[str]:
        with self._lock:
            self._refresh()
            return sorted(self._roles)

    def problems(self) -> dict[str, str]:
        with self._lock:
            self._refresh()
            if self._broken:
                return {"*": self._broken}
            return dict(self._problems)


# ── skill metadata and this process's registry ───────────────────────────


@dataclass
class SkillMeta:
    version: int
    escapes: frozenset[str]
    reaches: Mapping[str, frozenset[str]]
    target_scope: Mapping[str, str]
    resolver: Callable[[str | None], str] | None
    #: The argument that names a target ("target"; AVI calls it "controller").
    target_param: str = "target"
    #: Scope of a tool with no tag and no target argument: "all" (default, fail closed)
    #: or "one" for a skill whose untargeted tools act on its default target (AVI).
    untagged_scope: str = "all"
    #: Every tool of the server and whether its readOnlyHint is exactly True.
    registry: dict[str, bool] = field(default_factory=dict)
    #: Tools that take a ``target`` argument (scope ``one`` unless declared otherwise).
    target_params: frozenset[str] = frozenset()
    #: Tools with a host-path parameter: escape tools while a file root is set.
    host_path_tools: frozenset[str] = frozenset()

    def all_escapes(self) -> frozenset[str]:
        from vmware_policy.hostpaths import FILE_ROOT_ENV

        if os.environ.get(FILE_ROOT_ENV, "").strip():
            return self.escapes | self.host_path_tools
        return self.escapes

    def scope_of(self, tool: str) -> str:
        if tool in self.target_scope:
            return self.target_scope[tool]
        return "one" if tool in self.target_params else self.untagged_scope


_META: dict[str, SkillMeta] = {}
_META_LOCK = threading.Lock()


def declare_role_metadata(
    skill: str,
    *,
    version: int = 1,
    escapes: Iterable[str] = (),
    reaches: Mapping[str, Iterable[str]] | None = None,
    target_scope: Mapping[str, str] | None = None,
    resolver: Callable[[str | None], str] | None = None,
    target_param: str = "target",
    untagged_scope: str = "all",
) -> None:
    """A skill states what policy cannot infer (HLD §18 D-21/D-22).

    ``escapes``: tools that give their holder more than its role (credentials, guest
    code, host files, arbitrary API paths). ``reaches``: for each composite or
    deferred tool, every tool it can end up running. ``target_scope``: ``one`` /
    ``all`` / ``none`` per tool; an untagged tool counts as ``all``. ``resolver``:
    maps a ``target`` argument (or None) to the canonical target name the
    connection will use. ``target_param``: the argument that names a target.
    """
    if version != 1:
        raise ValueError(f"role metadata version {version} is not supported (expected 1)")
    if untagged_scope not in ("one", "all"):
        raise ValueError(f"untagged_scope must be 'one' or 'all', got {untagged_scope!r}")
    scopes = dict(target_scope or {})
    bad = {t: s for t, s in scopes.items() if s not in TARGET_SCOPES}
    if bad:
        raise ValueError(f"target_scope values must be one of {TARGET_SCOPES}: {bad}")
    key = canonical_skill(skill)
    with _META_LOCK:
        old = _META.get(key)
        _META[key] = SkillMeta(
            version=version,
            escapes=frozenset(escapes),
            reaches={t: frozenset(r) for t, r in (reaches or {}).items()},
            target_scope=scopes,
            resolver=resolver,
            target_param=target_param,
            untagged_scope=untagged_scope,
            registry=old.registry if old else {},
            target_params=old.target_params if old else frozenset(),
            host_path_tools=old.host_path_tools if old else frozenset(),
        )


def register_registry(
    skill: str,
    tools: Mapping[str, bool],
    *,
    target_params: Iterable[str] = (),
    host_path_tools: Iterable[str] = (),
) -> None:
    """Record every tool of this server and whether it only reads (before exposure).

    ``target_params``: tools whose schema has a ``target`` argument.
    ``host_path_tools``: tools with a host-path parameter (``hostpaths.HOST_PATH_PARAMS``).
    """
    key = canonical_skill(skill)
    with _META_LOCK:
        meta = _META.get(key)
        if meta is None:
            # Undeclared skill: keep the registry so `role check` can name its tools,
            # but `declared` stays false (version 0) — only admin works for it.
            meta = SkillMeta(0, frozenset(), {}, {}, None)
            _META[key] = meta
        meta.registry = dict(tools)
        meta.target_params = frozenset(target_params)
        meta.host_path_tools = frozenset(host_path_tools)


def metadata(skill: str) -> SkillMeta | None:
    return _META.get(canonical_skill(skill))


def _reset_for_tests() -> None:
    with _META_LOCK:
        _META.clear()


# ── the decision ──────────────────────────────────────────────────────────


def _names(skill: str, tool: str) -> set[str]:
    from vmware_policy import renames

    return {tool, *renames.other_names(skill, tool)}


def _granted(grant: SkillGrant, meta: SkillMeta, skill: str, tool: str) -> str | None:
    """None when ``grant`` allows ``tool`` itself (targets aside); else why not."""
    names = _names(skill, tool)
    if tool in meta.all_escapes():
        if names & grant.allow_escape:
            return None
        return (
            f"{tool} gives its holder more than a role (credentials, guest code or host "
            "files); list it under allow_escape"
        )
    if names & grant.allow_write:
        return None
    read_only = meta.registry.get(tool) is True
    if grant.tools == "*" or (grant.tools == "read" and read_only):
        return None
    return f"{tool} changes the platform and is not in allow_write"


def _reader_refuses(meta: SkillMeta, tool: str) -> str | None:
    if tool in meta.all_escapes():
        return f"{tool} gives its holder more than read access"
    return None if meta.registry.get(tool) is True else f"{tool} changes the platform"


def _tool_allowed(role: Role, meta: SkillMeta, skill: str, tool: str) -> str | None:
    if role is ADMIN:
        return None
    if role is READER:
        why = _reader_refuses(meta, tool)
        if why:
            return why
        # A read-only composite is held to what it reaches, as for custom roles (LOW-4).
        for reached in sorted(meta.reaches.get(tool, ())):
            why = _reader_refuses(meta, reached)
            if why:
                return f"{tool} can run {reached}: {why}"
        return None
    grant = (role.skills or {}).get(skill)
    if grant is None:
        return f"the role does not include skill {skill!r}"
    why = _granted(grant, meta, skill, tool)
    if why:
        return why
    # A composite allows only what every tool it can reach allows (D-22).
    for reached in sorted(meta.reaches.get(tool, ())):
        why = _granted(grant, meta, skill, reached)
        if why:
            return f"{tool} can run {reached}: {why}"
    return None


def _target_allowed(
    role: Role, meta: SkillMeta, skill: str, tool: str, params: Mapping[str, Any]
) -> str | None:
    if role is ADMIN or role is READER:
        return None
    grant = (role.skills or {}).get(skill)
    if grant is None or grant.targets is None:
        return None
    scope = meta.scope_of(tool)
    if scope == "none":
        return None
    if scope == "all":
        return f"{tool} reads every target; this role is limited to {', '.join(grant.targets)}"
    if meta.resolver is None:
        return "this skill cannot name its default target, so a target-limited role cannot use it"
    raw = params.get(meta.target_param)
    try:
        name = meta.resolver(str(raw) if raw else None)
    except Exception as exc:  # noqa: BLE001 — an unknown target is a refusal, not a crash
        return f"target {raw!r} cannot be resolved ({type(exc).__name__})"
    if not any(fnmatch.fnmatchcase(name, pattern) for pattern in grant.targets):
        return f"target {name!r} is outside this role ({', '.join(grant.targets)})"
    return None


def decide(role: Role, skill: str, tool: str, params: Mapping[str, Any]) -> Decision:
    """May ``role`` run ``tool`` of ``skill`` with ``params``?"""
    skill = canonical_skill(skill)
    if role is ADMIN:
        return Decision(True, role.name)
    meta = metadata(skill)
    if meta is None or meta.version == 0:
        return Decision(
            False,
            role.name,
            "role:no-metadata",
            f"vmware-{skill.replace('_', '-')} has not declared role metadata (an older release?), "
            f"so only the 'admin' role may use it. Upgrade the skill or use an admin token.",
        )
    why = _tool_allowed(role, meta, skill, tool) or _target_allowed(role, meta, skill, tool, params)
    if why:
        return Decision(
            False, role.name, f"role:{role.name}", f"Role {role.name!r} may not call {tool}: {why}."
        )
    return Decision(True, role.name)


def visible(role: Role, skill: str, tool: str) -> bool:
    """Whether ``tools/list`` should show ``tool`` to ``role`` (targets are checked per call)."""
    skill = canonical_skill(skill)
    if role is ADMIN:
        return True
    meta = metadata(skill)
    if meta is None or meta.version == 0:
        return False
    return _tool_allowed(role, meta, skill, tool) is None


def is_network_process() -> bool:
    from vmware_policy import surface

    return surface.process_surface() in _NETWORK_SURFACES


# ── this process's token store, and the per-call entry point ──────────────

_STORE: Any = None  # vmware_policy.tokens.TokenStore, bound by serve.configure
_ROLE_FILE: RoleFile | None = None


def bind(store: Any, role_file: RoleFile | None = None) -> None:
    """Called by ``serve.configure`` for a network transport."""
    global _STORE, _ROLE_FILE
    _STORE = store
    _ROLE_FILE = role_file or RoleFile(audit_reloads=True)


def unbind() -> None:
    global _STORE, _ROLE_FILE
    _STORE, _ROLE_FILE = None, None


def roles_enabled() -> bool:
    return _STORE is not None and _STORE.roles_enabled()


def _unknown_names(role: Role, skill: str) -> list[str]:
    """Names in this skill's section that are no tool of this server (D-20, R2-Ma)."""
    from vmware_policy import renames

    meta = metadata(skill)
    grant = (role.skills or {}).get(skill)
    if grant is None or meta is None or not meta.registry:
        return []
    known = set(meta.registry)
    for tool in meta.registry:
        known.update(renames.other_names(skill, tool))
    return sorted((grant.allow_write | grant.allow_escape) - known)


def caller_role() -> tuple[Role | None, str, str]:
    """``(role, role_name, why_not)`` for the current network caller."""
    from vmware_policy.caller import current_caller

    caller = current_caller()
    if not caller or not caller.startswith("token:"):
        return None, "", "no authenticated caller"
    if _STORE is None or _ROLE_FILE is None:
        return None, "", "roles are not bound to a token store in this process"
    name = caller[len("token:") :]
    role_name = _STORE.role_of(name)
    if role_name is None:
        return None, "", f"token {name!r} is not (or no longer) accepted"
    role, why = _ROLE_FILE.get(role_name)
    return role, role_name, why


def check_call(skill: str, tool: str, params: Mapping[str, Any]) -> Decision | None:
    """The role check for one call; None when roles do not apply to this process.

    Network process only (keyed on the process surface, review R2-Hb/H3): a call
    without an authenticated caller is refused there, never treated as an operator.
    """
    if not is_network_process():
        return None
    from vmware_policy.caller import current_caller

    if current_caller() is None:
        return Decision(
            False,
            "",
            "role:no-caller",
            "This server serves the network and the call carries no authenticated caller "
            "(a thread the tool started, or an internal path); refused.",
        )
    if not roles_enabled():
        return Decision(True, "")
    role, role_name, why = caller_role()
    if role is None:
        return Decision(
            False, role_name, "role:invalid", f"Role {role_name!r} cannot be used: {why}."
        )
    unknown = _unknown_names(role, canonical_skill(skill))
    if unknown:
        return Decision(
            False,
            role_name,
            "role:invalid",
            f"Role {role_name!r} names tools this server does not have: {', '.join(unknown)}.",
        )
    return decide(role, skill, tool, params)


def filter_tools(skill: str, tools: list[Any]) -> list[Any]:
    """``tools/list`` for the current caller (R2-Md: unfiltered before opt-in)."""
    if not roles_enabled():
        return tools
    role, _name, _why = caller_role()
    if role is None:
        return []
    return [t for t in tools if visible(role, skill, getattr(t, "name", ""))]


_TARGETS_START = "Configured targets:"
#: What every skill writes right after the target list. Cutting up to it, not to the
#: first period, keeps a target named ``prod.`` from leaving the rest of the list
#: showing (review LOW-3); without it the rest of the text goes, which hides too
#: much rather than too little.
_TARGETS_END = " Choosing a target:"
_TARGETS_HIDDEN = (
    "Configured targets: not listed for this role (each result names the target that "
    "answered; ask an operator which targets your role may use)."
)


def instructions_for_caller(text: str | None) -> str | None:
    """Server instructions for the current caller (HLD §18 D-21(5)).

    The skills list every target with its address. Once roles are enabled, only
    ``admin`` sees that list; other roles get one line instead.
    """
    if not text or not roles_enabled():
        return text
    role, _name, _why = caller_role()
    if role is ADMIN:
        return text
    return _hide_targets(text)


def _hide_targets(text: str) -> str:
    start = text.find(_TARGETS_START)
    if start < 0:
        return text
    end = text.find(_TARGETS_END, start)
    rest = text[end:] if end >= 0 else ""
    return text[:start] + _TARGETS_HIDDEN + rest
