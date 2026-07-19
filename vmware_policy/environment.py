"""Resolve a target name to the environment its config declares.

Policy rules scope by environment ("destructive work in production needs two
people"). The engine used to receive the *target's name* for that — so the rule
only fired when an operator happened to name their target the exact string in
the rule. Real target names are ``prod-vc01`` and ``vcenter-lab``, never the
literal word ``production``, so environment-scoped rules were configured and
inert.

Environment is now an explicit declaration in each skill's config::

    targets:
      prod-vc01:
        host: vc01.corp.local
        environment: production

vmware-policy cannot read those files itself — every skill has its own config
schema and loader — so each skill registers a lookup at server start:

    from vmware_policy import set_environment_resolver
    set_environment_resolver(lambda target: _config().environment_for(target))

An unregistered resolver, an unknown target, a blank declaration, and a
resolver that raises all produce the same answer: ``""``, meaning *undeclared*.
Undeclared is treated as unknown rather than safe — the policy baseline refuses
writes against it. A skill that forgets to register a resolver therefore fails
closed and loudly, which is the intended direction for a control whose previous
failure mode was silence.
"""

from __future__ import annotations

import logging
import os
import threading
from pathlib import Path
from typing import Any, Callable, Optional

_log = logging.getLogger("vmware_policy.environment")

#: Maps a target name to its declared environment, or None when it has none.
EnvironmentResolver = Callable[[str], Optional[str]]

_resolver: Optional[EnvironmentResolver] = None
_lock = threading.Lock()

#: Emitted once per target so a misconfigured estate does not flood the log.
_warned: set[str] = set()


def set_environment_resolver(resolver: Optional[EnvironmentResolver]) -> None:
    """Register (or clear, with ``None``) the target → environment lookup.

    Call once at MCP server start-up. Later calls replace the previous resolver,
    which is what tests want and what a re-imported server does.
    """
    global _resolver  # noqa: PLW0603
    with _lock:
        if resolver is not None and _resolver is not None and resolver is not _resolver:
            # Two skills' servers imported into one process: the second
            # registration silently takes over environment resolution for both,
            # so the first skill's targets resolve against the wrong config and
            # its environment-scoped rules quietly stop applying. Under the
            # warn-only migration setting that would be invisible. Each skill
            # normally runs as its own stdio process, so this is an embedder
            # scenario — but it must be loud if it happens.
            _log.warning(
                "Environment resolver replaced (%s -> %s). Environment "
                "resolution is process-global: if two skills are loaded in one "
                "process, the last registration wins for both, and rules scoped "
                "by environment may stop applying to the first. An in-process "
                "dispatcher must re-register the target skill's resolver around "
                "each delegated call.",
                getattr(_resolver, "__qualname__", _resolver),
                getattr(resolver, "__qualname__", resolver),
            )
        _resolver = resolver
        _warned.clear()


def resolve_environment(target: str) -> str:
    """Return the environment ``target`` declares, or ``""`` if it declares none.

    An empty ``target`` is passed to the resolver rather than short-circuited:
    most tools take ``target`` as optional and fall back to the config's
    ``default_target``, so the skill's resolver is the only thing that knows
    which target an omitted argument actually means. Short-circuiting here would
    refuse every "use my default vCenter" call even when that target declares an
    environment perfectly well.

    Never raises. Every failure path answers ``""`` so the caller's fail-closed
    policy decides what that means, rather than an exception escaping into a
    tool call.
    """
    resolver = _resolver
    if resolver is None:
        _warn_once(
            target,
            "No environment resolver registered — every target reads as "
            "undeclared. The MCP server should call set_environment_resolver() "
            "at start-up.",
        )
        return ""

    try:
        declared = resolver(target)
    except Exception:  # noqa: BLE001 — a broken config must not break the call
        _log.warning("Environment resolver failed for target %r", target, exc_info=True)
        return ""

    if not declared or not str(declared).strip():
        _warn_once(
            target,
            f"Target {target!r} declares no environment, so environment-scoped "
            f"policy cannot apply to it and the declared-environment rule "
            f"gates state-changing operations (currently a warning; a future "
            f"release refuses them). Add 'environment: <name>' to its config "
            f"entry.",
        )
        return ""
    return str(declared).strip()


def _warn_once(target: str, message: str) -> None:
    if target in _warned:
        return
    _warned.add(target)
    _log.warning("%s", message)


def mtime_cached_loader(env_var: str, default_path: Any, loader: Callable[[Any], Any]) -> Callable[[], Any]:
    """Wrap a config loader so it re-parses only when the file actually changed.

    The environment resolver runs on *every* tool call, and a resolver that
    calls ``load_config()`` directly pays a full YAML parse each time — a
    50-call triage session performed 50 parses to answer a question whose
    answer changes essentially never (2026-07-18 review). This trades that for
    one ``os.stat`` per call, the same technique ``PolicyEngine._maybe_reload``
    already uses, and preserves the hot-reload contract exactly: an edit to the
    file is picked up on the next call.

    Args:
        env_var: Name of the per-skill config-path override variable
            (e.g. ``VMWARE_ARIA_CONFIG``), re-read on every call so the
            override keeps working mid-process.
        default_path: Path used when the variable is unset.
        loader: ``loader(path) -> config``; called only on first use and
            whenever the effective path or its mtime changes.

    The returned callable re-raises whatever ``loader`` raises — callers keep
    their own except-means-undeclared handling.
    """
    state: dict[str, Any] = {"path": None, "mtime": None, "value": None, "loaded": False}

    def cached() -> Any:
        raw = os.environ.get(env_var)
        path = Path(raw) if raw else Path(default_path)
        try:
            mtime: Optional[float] = path.stat().st_mtime
        except OSError:
            mtime = None
        if not state["loaded"] or state["path"] != path or state["mtime"] != mtime:
            state["value"] = loader(path if raw else None)
            state["path"] = path
            state["mtime"] = mtime
            state["loaded"] = True
        return state["value"]

    return cached
