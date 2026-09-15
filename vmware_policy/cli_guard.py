"""``@guarded`` — the CLI counterpart to ``@vmware_tool`` (HLD §4.1).

A CLI command that changes remote state routes through the SAME shared
``guard()`` + ``audit_call()`` as the MCP surface, so ``vmware-aiops vm delete``
run through Bash is authorized and recorded exactly like the ``vm_delete`` MCP
tool — invariants I-1 (no unguarded write door), I-3 (surface-symmetric policy)
and I-8 (every write audited, one store). The interactive double-confirm stays
layered on top as the surface-specific confirmation (HLD §7).

Leaner than ``@vmware_tool`` on purpose: no budget / pattern / undo machinery
(those are agent-loop concerns), just the two guarantees a CLI write needs —
optional policy authorization and one un-bypassable audit row in
``~/.vmware/audit.db``.

Param binding, redaction and skill inference are imported from ``decorators`` so
the two surfaces bind ``(tool, params, target)`` from a call **identically**: I-3
is a property of sharing the code, not of two implementations agreeing by
inspection. (These are internal helpers today; if a third surface ever needs
them they should move to a small shared reflection module.)
"""
from __future__ import annotations

import inspect
import os
import time
from contextlib import contextmanager
from functools import wraps
from typing import Any, Callable

from vmware_policy.audit import detect_agent
from vmware_policy.decorators import (
    _bind_params,
    _failure_signal,
    _infer_skill,
    _redact,
    _redact_credential_keys,
    _redact_secrets_text,
    audited_status,
)
from vmware_policy.guard import audit_call, guard
from vmware_policy.policy import PolicyDenied
from vmware_policy.sanitize import sanitize

# ``@guarded`` only ever wraps a Typer command, so click (Typer's engine) is
# present wherever it runs. Soft-import it anyway: vmware_policy is also a pure
# MCP dependency, and importing click there must not become mandatory. An empty
# tuple makes ``except ()`` a no-op, so the classification below degrades to
# "any non-return exit is an error" when click is genuinely absent.
try:  # pragma: no cover - exercised via the CLI, not the MCP path
    from click.exceptions import Abort as _Abort
    from click.exceptions import Exit as _Exit

    _ABORT: tuple[type[BaseException], ...] = (_Abort,)
    _EXIT: tuple[type[BaseException], ...] = (_Exit,)
except ImportError:  # pragma: no cover
    _ABORT = ()
    _EXIT = ()


@contextmanager
def _config_override(skill: str, config: Any):
    """Point the skill's environment resolver at the command's ``--config``.

    Every skill's resolver reads ``VMWARE_<SKILL>_CONFIG`` (falling back to its
    default file) on each call. A CLI command run with ``--config other.yaml``
    acts on that file's targets, so its environment labels are the ones a deny
    rule must see; without this the resolver judged the default file instead and
    a production target in ``--config prod.yaml`` matched no environment rule
    (review, 2026-09-11). Scoped to the guard() call; the previous value, or its
    absence, is restored.
    """
    if not config:
        yield
        return
    var = f"VMWARE_{skill.upper().replace('-', '_')}_CONFIG"
    previous = os.environ.get(var)
    os.environ[var] = str(config)
    try:
        yield
    finally:
        if previous is None:
            os.environ.pop(var, None)
        else:
            os.environ[var] = previous


def guarded(
    tool: str | None = None,
    *,
    risk_level: str = "low",
    sensitive_params: list[str] | None = None,
) -> Callable:
    """Authorize + audit a CLI command through the shared enforcement core.

    Apply it **beneath** the skill's error-translation decorator so a
    :class:`PolicyDenied` becomes a teaching message rather than a traceback::

        @vm_app.command("delete")
        @cli_errors
        @guarded(risk_level="critical")
        def vm_delete(vm_name: str, target: TargetOption = None, ...):
            ...

    Args:
        tool: Operation name recorded in the audit row and matched by deny rules.
            Defaults to the wrapped function's ``__name__`` — keep it equal to the
            matching MCP tool name so one deny rule scopes both surfaces at once.
        risk_level: 'low' | 'medium' | 'high' | 'critical'; feeds the
            maintenance-window rule.
        sensitive_params: Parameter names to redact before the audit row.
    """
    def decorator(func: Callable) -> Callable:
        wrapper = _enforced(func, tool, risk_level, sensitive_params)
        wrapper._is_guarded = True
        wrapper._risk_level = risk_level
        wrapper._guarded_tool = wrapper._enforced_tool
        return wrapper

    return decorator


def audited(
    tool: str | None = None,
    *,
    risk_level: str = "low",
    sensitive_params: list[str] | None = None,
) -> Callable:
    """Authorize + audit a CLI command that reads a remote system or sends data out.

    The read counterpart of :func:`guarded` (HLD §4.1, §8.1, I-8, amended
    2026-09-15): the same ``guard()`` as the MCP read tools — a deny rule on
    ``list_resources`` stops ``resource list`` too — and one row in
    ``~/.vmware/audit.db`` with a truthful status. No confirmation layer: reads
    change nothing.

    It marks the command ``_is_audited``, never ``_is_guarded``. Every skill's
    guarded-writes test treats a guarded command as a write that must map to an
    MCP write tool; a read wearing that marker would break them for the wrong
    reason.

    Args:
        tool: The MCP twin's tool name where the command has one, so one deny rule
            and one audit query cover both surfaces. Defaults to the function name.
        risk_level: Normally ``'low'``; feeds the maintenance-window rule.
        sensitive_params: Parameter names to redact before the audit row.
    """

    def decorator(func: Callable) -> Callable:
        wrapper = _enforced(func, tool, risk_level, sensitive_params)
        wrapper._is_audited = True
        wrapper._risk_level = risk_level
        wrapper._audited_tool = wrapper._enforced_tool
        return wrapper

    return decorator


def cli_local(reason: str) -> Callable:
    """Mark a CLI command that reaches nothing remote (HLD I-9).

    Setup, help, version, local files, starting the MCP server (whose tools audit
    themselves). It writes no audit row and changes nothing about the call; it
    exists so that every command states its kind and an exemption is a decision
    with a reason in the code, which ``family_smoke`` can check exactly.

    Raises:
        ValueError: when ``reason`` is empty — an exemption nobody can explain is
            the omission this marker replaces.
    """
    if not isinstance(reason, str) or not reason.strip():
        raise ValueError(
            "cli_local needs a reason saying why the command reaches nothing remote, "
            'e.g. @cli_local("writes the local config file").'
        )

    def decorator(func: Callable) -> Callable:
        func._is_local = True
        func._local_reason = reason.strip()
        return func

    return decorator


def _enforced(
    func: Callable, tool: str | None, risk_level: str, sensitive_params: list[str] | None
) -> Callable:
    """The one wrapper behind @guarded and @audited: guard(), run, one audit row."""
    sensitive = set(sensitive_params or [])
    signature = inspect.signature(func)
    tool_name = tool or func.__name__
    skill = _infer_skill(func)

    @wraps(func)
    def wrapper(*args: Any, **kwargs: Any) -> Any:
        params = _bind_params(signature, args, kwargs)
        safe = _redact(params, sensitive)
        raw_target = params.get("target", params.get("env", ""))
        target = str(raw_target) if raw_target else ""
        start = time.time()
        status = "ok"
        result: Any = None
        bypassed = False
        # Fresh failure signal per invocation, restored after the audit row:
        # `report_tool_failure` marks THIS command failed, never the next one.
        token = _failure_signal.set(None)
        try:
            # Same authorization gate as @vmware_tool (I-3). A no-op unless the
            # operator wrote deny / maintenance rules; raises PolicyDenied.
            with _config_override(skill, params.get("config")):
                decision = guard(skill, tool_name, safe, risk_level=risk_level, target=target)
            # VMWARE_POLICY_DISABLED=1 must show in the row, as it does on the
            # MCP surface — a bypassed write recorded as plain "ok" is
            # indistinguishable from a normal one.
            bypassed = getattr(decision, "rule", "") == "policy_disabled"
            result = func(*args, **kwargs)
            # A command that printed its failure and returned (VKS `tkc versions`,
            # the AIops CLI twins) says so with report_tool_failure — HLD I-5,
            # extended 2026-09-15. Without this the row read `ok`.
            reported = _failure_signal.get()
            if reported is not None:
                status = "error"
                result = {"error": sanitize(_redact_secrets_text(reported), 500)}
            return result
        except PolicyDenied as exc:
            status = "denied"
            result = {"error": exc.result.reason, "rule": exc.result.rule}
            raise
        except _ABORT:
            # The operator declined the double-confirm — a deliberate refusal,
            # not a failure. Record it truthfully; the write never ran.
            status = "rejected"
            raise
        except _EXIT as exc:
            # typer.Exit(0) is a clean early return; a non-zero code is a
            # failure the command chose to signal itself.
            failed = getattr(exc, "exit_code", 0) != 0 or _failure_signal.get() is not None
            status = "error" if failed else "ok"
            if _failure_signal.get() is not None:
                result = {"error": sanitize(_redact_secrets_text(_failure_signal.get()), 500)}
            raise
        except Exception as exc:
            status = "error"
            # The same free-form credential scrubber the MCP surface runs.
            result = {"error": sanitize(_redact_secrets_text(str(exc)), 500)}
            raise
        except SystemExit as exc:
            # Not an Exception, so it used to fall through as "ok". vmware-avi's
            # ops raise SystemExit(1) for "not found"; doctor exits non-zero on
            # a failed probe. A clean SystemExit(0) stays ok.
            if exc.code not in (0, None):
                status = "error"
                result = {"error": sanitize(_redact_secrets_text(f"SystemExit({exc.code})"), 500)}
            raise
        except BaseException as exc:
            # Ctrl+C mid-command: the remote side may still be working.
            status = "interrupted"
            result = {"error": f"command interrupted ({type(exc).__name__})"}
            raise
        finally:
            # One audit row per invocation, to the single sink (I-8). Never
            # raises — audit_call swallows its own errors.
            audit_call(
                skill,
                tool_name,
                # Same credential-key net as @vmware_tool: both surfaces
                # write the one audit sink, so scrubbing only one of them
                # would leave the leak reachable from the other (I-3/I-8,
                # and CLAUDE.md 形态 #7). There is no ``sensitive_result``
                # counterpart here because a Typer command returns None and
                # prints instead — add one the day a CLI command returns a
                # credential, not before.
                params=safe,
                result=_redact_credential_keys(result),
                # A completed --dry-run records "dry_run", not "ok".
                status=audited_status(status, params, bypassed=bypassed),
                duration_ms=int((time.time() - start) * 1000),
                agent=detect_agent(),
                risk_level=risk_level,
                rationale=os.environ.get("VMWARE_AUDIT_RATIONALE", ""),
                approved_by=os.environ.get("VMWARE_AUDIT_APPROVED_BY", ""),
            )
            _failure_signal.reset(token)

    wrapper._enforced_tool = tool_name
    return wrapper
