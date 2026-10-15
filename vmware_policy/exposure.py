"""Which tools an MCP server offers, chosen once at startup (HLD §17 D-16).

``expose="all"`` (default) changes nothing. ``expose="read"`` keeps only tools
annotated ``readOnlyHint: true``; ``allow_write`` keeps chosen write tools on
top. A tool with no annotation, or a hint that is not exactly ``True``, counts
as a write: unknown is never read as safe.

This shrinks what a client is offered. It is **not authorization** — whether a
call may change the platform is the account's RBAC (§5), and deny rules still
apply to whatever is exposed.

The server object is duck-typed on the SDK's two public methods,
``list_tools()`` (async) and ``remove_tool(name)``, so this module does not
import the SDK and does not reach into its registry.
"""

from __future__ import annotations

import asyncio
import os
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from typing import Any

from vmware_policy import renames

#: The closed set of exposure modes.
EXPOSE_MODES = ("all", "read")


class ExposureError(ValueError):
    """The exposure setting cannot be applied; the server must not start."""


@dataclass(frozen=True)
class ExposureResult:
    """What :func:`restrict_tools` did."""

    expose: str
    kept_write: tuple[str, ...]
    removed: tuple[str, ...]

    def describe(self) -> str:
        """One line for stderr at startup."""
        if self.expose == "all":
            return "Tool exposure: all tools (default)."
        kept = ", ".join(self.kept_write) or "none"
        return (
            f"Tool exposure: read tools only, plus write tools: {kept} "
            f"({len(self.removed)} hidden). This limits what clients are offered; "
            f"it is not authorization — the account's permissions still decide."
        )


def _env_key(skill: str, suffix: str) -> str:
    return f"VMWARE_{skill.upper().replace('-', '_')}_MCP_{suffix}"


def _split(value: str | Sequence[str] | None) -> tuple[str, ...]:
    if value is None:
        return ()
    items: Iterable[str] = value.split(",") if isinstance(value, str) else value
    return tuple(name.strip() for name in items if name and name.strip())


def settings(
    skill: str,
    expose: str | None = None,
    allow_write: str | Sequence[str] | None = None,
) -> tuple[str, tuple[str, ...]]:
    """``(expose, allow_write)`` from the flags if any is given, else the environment.

    ``skill`` is the policy key (``storage``, ``nsx_security``); the variables
    are ``VMWARE_<SKILL>_MCP_EXPOSE`` and ``VMWARE_<SKILL>_MCP_ALLOW_WRITE``.
    One source decides the whole setting: once any flag is given the
    environment is not read at all, so ``--expose read`` cannot pick up a
    leftover ``ALLOW_WRITE`` from the shell or a client ``env`` block. An empty
    environment value, or a blank flag, counts as unset.
    """
    # A blank flag counts as not given: a templated `--allow-write ${WRITES}`
    # with WRITES empty must not switch the source and drop EXPOSE=read.
    if expose is not None and not expose.strip():
        expose = None
    if allow_write is not None and not _split(allow_write):
        allow_write = None
    if expose is None and allow_write is None:
        expose = os.environ.get(_env_key(skill, "EXPOSE")) or None
        allow_write = os.environ.get(_env_key(skill, "ALLOW_WRITE")) or None
    return (expose if expose is not None else "all"), _split(allow_write)


def _is_read(tool: Any) -> bool:
    annotations = getattr(tool, "annotations", None)
    return getattr(annotations, "readOnlyHint", None) is True


def _canonical(skill: str, name: str, names: set[str]) -> str | None:
    """``name`` as this server calls it, accepting a pre-2.0 name; None if unknown."""
    if name in names:
        return name
    new = renames.table().get("vmware-" + skill.replace("_", "-"), {}).get(name)
    return new if new in names else None


def _plan(
    tools: Sequence[Any], skill: str, expose: str, allow_write: Sequence[str]
) -> ExposureResult:
    if expose not in EXPOSE_MODES:
        raise ExposureError(
            f"Unknown tool exposure {expose!r}. Use one of: {', '.join(EXPOSE_MODES)} "
            f"(set with '--expose' or {_env_key(skill, 'EXPOSE')})."
        )
    if expose == "all":
        if allow_write:
            raise ExposureError(
                "allow_write only applies with expose=read (with expose=all every tool is "
                "already offered). Add '--expose read' next to '--allow-write' (flags and "
                "environment are not mixed), or with no flags set "
                f"{_env_key(skill, 'EXPOSE')}=read; or remove the allow_write list."
            )
        return ExposureResult("all", (), ())

    by_name = {tool.name: tool for tool in tools}
    writes = sorted(name for name, tool in by_name.items() if not _is_read(tool))
    kept: list[str] = []
    for requested in allow_write:
        name = _canonical(skill, requested, set(by_name))
        if name is None:
            raise ExposureError(
                f"allow_write names {requested!r}, which is not a tool of this server. "
                f"Write tools here: {', '.join(writes) or 'none'}."
            )
        if _is_read(by_name[name]):
            raise ExposureError(
                f"allow_write names {requested!r}, which is a read tool — read tools are "
                "already offered with expose=read. List only write tools."
            )
        if name not in kept:
            kept.append(name)
    removed = tuple(name for name in writes if name not in kept)
    return ExposureResult("read", tuple(kept), removed)


async def arestrict_tools(
    server: Any,
    *,
    skill: str,
    expose: str = "all",
    allow_write: Sequence[str] = (),
) -> ExposureResult:
    """Async form of :func:`restrict_tools`, for launchers already inside an event loop."""
    names = _split(allow_write)
    if expose != "read":
        # "all" (and every refusal of a bad value) is decided without the
        # server: the default must not depend on, or touch, anything it serves.
        return _plan((), skill, expose, names)
    result = _plan(await server.list_tools(), skill, expose, names)
    for name in result.removed:
        server.remove_tool(name)
    return result


def restrict_tools(
    server: Any,
    *,
    skill: str,
    expose: str = "all",
    allow_write: Sequence[str] = (),
) -> ExposureResult:
    """Apply an exposure to ``server`` before it serves; raise ExposureError if it cannot.

    Nothing is removed unless the whole setting is valid. Call it after every
    tool is registered and before ``run``.
    """
    if expose != "read":
        return _plan((), skill, expose, _split(allow_write))
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return asyncio.run(
            arestrict_tools(server, skill=skill, expose=expose, allow_write=allow_write)
        )
    raise ExposureError(
        "restrict_tools was called inside a running event loop; use "
        "'await vmware_policy.exposure.arestrict_tools(...)' there instead."
    )


def apply_or_exit(
    server: Any,
    *,
    skill: str,
    expose: str | None = None,
    allow_write: str | Sequence[str] | None = None,
) -> ExposureResult:
    """What a server's ``main()`` calls before ``run``: resolve, apply, report — or exit 2.

    ``expose`` / ``allow_write`` come from the ``mcp`` command's flags (None when
    not given), falling back to the environment. A setting that cannot be
    applied stops the process with exit code 2 and the reason on stderr, so a
    server never starts offering more than its operator asked for.
    """
    import sys

    mode, names = settings(skill, expose, allow_write)
    try:
        result = restrict_tools(server, skill=skill, expose=mode, allow_write=names)
    except ExposureError as exc:
        print(f"vmware-{skill.replace('_', '-')} MCP server not started: {exc}", file=sys.stderr)
        raise SystemExit(2) from exc
    if result.expose != "all":
        print(result.describe(), file=sys.stderr)
    return result
