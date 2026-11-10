"""The ``@vmware_tool`` decorator — mandatory wrapper for all VMware MCP tool functions.

Responsibilities:
  1. Pre-check: evaluate policy rules (deny, maintenance window)
  2. Execute: run the actual tool function
  3. Post-log: write audit record to ``~/.vmware/audit.db``, with credentials
     scrubbed out of both the arguments and the return value
  4. Metadata: attach risk_level, idempotent, timeout, sensitive_params

Usage::

    from vmware_policy import vmware_tool

    @vmware_tool(risk_level="high", sensitive_params=["password"])
    def delete_segment(name: str, env: str) -> dict:
        ...

Registration enforcement::

    # In your MCP server startup
    for tool in tools:
        assert getattr(tool, "_is_vmware_tool", False), f"{tool.__name__} missing @vmware_tool"
"""

from __future__ import annotations

import inspect
import logging
import os
import time
from functools import wraps
from typing import Any

from vmware_policy import frame as _frame
from vmware_policy.audit import detect_agent
from vmware_policy.budget import BudgetExceeded, get_budget
from vmware_policy.guard import audit_call, guard
from vmware_policy.skills import skill_name
from vmware_policy.patterns import PatternMatch, get_pattern_engine
from vmware_policy.policy import PolicyDenied, PolicyResult
from vmware_policy.sanitize import sanitize

_log = logging.getLogger("vmware-policy.decorators")

# PolicyDenied moved to policy.py (beside PolicyResult) so guard.py can raise it
# without importing this module (which imports guard). The import above binds it
# into this namespace, so `from vmware_policy.decorators import PolicyDenied` and
# the package __init__ keep working.


# ── Returned failures ─────────────────────────────────────────────────────

#: Set by ``report_tool_failure`` for the innermost in-flight tool call. The
#: wrapper rebinds it per call and restores the previous binding afterwards, so
#: an inner tool's failure cannot mark its caller failed — skills delegate
#: in-process (vmware-aiops runs vmware-monitor's library) and an outer tool
#: that catches and recovers is still a successful call.
from vmware_policy._failure import (  # noqa: F401 — compatibility/runtime export
    _failure_signal, _returned_failure, _says_it_failed,
    report_tool_failure as report_tool_failure,
)


def vmware_tool(
    fn: Any = None,
    *,
    risk_level: str = "low",
    idempotent: bool = False,
    timeout_seconds: int = 300,
    sensitive_params: list[str] | None = None,
    sensitive_result: bool = False,
    undo: Any = None,
) -> Any:
    """Decorator for all VMware MCP tool functions.

    Can be used with or without arguments::

        @vmware_tool
        def list_segments(...): ...

        @vmware_tool(risk_level="critical", sensitive_params=["password"])
        def delete_vm(...): ...

    Args:
        risk_level: One of 'low', 'medium', 'high', 'critical'.
        idempotent: Whether the operation can be safely retried on failure.
        timeout_seconds: Maximum execution time before warning — exceeding it
            logs a warning (no hard cancellation).
        sensitive_params: Parameter names to redact in audit logs.
        sensitive_result: The tool's return value *is* a credential — a
            kubeconfig, a bearer token, a password. The audit row then records
            the call (who, when, which arguments, whether it succeeded) but
            files the result as ``"[redacted: return value declared
            sensitive]"``. The caller still receives the real value; only the
            audit copy is redacted. See :func:`_redact_credential_keys` for the
            net that catches a tool which forgets to declare.
        undo: Optional callable ``(params, result) -> dict | None`` returning an
            inverse descriptor ``{"tool", "params", "skill"?, "note"?}``. On a
            successful call the inverse is recorded to ~/.vmware/undo.db and the
            result dict gains an ``_undo_id``. Return None for "no safe inverse".
            Recording only — execution is vmware-pilot's job.
    """
    _sensitive = set(sensitive_params or [])

    def decorator(func: Any) -> Any:
        # Cache the signature at decoration time so positional args can be
        # mapped to parameter names on every call (audit + env scoping).
        signature = inspect.signature(func)

        if inspect.iscoroutinefunction(func):
            # ── Async tools get an async wrapper with identical audit /
            # policy / circuit-breaker semantics (a sync wrapper would return
            # an un-awaited coroutine and audit it as "ok").
            @wraps(func)
            async def wrapper(*args: Any, **kwargs: Any) -> Any:
                state = _CallState(
                    func,
                    args,
                    kwargs,
                    signature,
                    _sensitive,
                    risk_level,
                    timeout_seconds,
                    undo,
                    sensitive_result,
                )
                # Fresh binding per call, restored below: a nested tool's
                # `report_tool_failure` must not mark its caller failed, and a
                # signal must not survive into the next call on this task.
                token = _failure_signal.set(None)
                # The MCP request's failure mark (vmware_policy.frame): only the
                # outermost tool call of a request may set it.
                frame_sink, frame_token = _frame.claim()
                try:
                    _role_check(state)
                    _check_common_arguments(state.raw_params)
                    _pre_check(state)
                    return _annotate_result(state, await func(*args, **kwargs))
                except (PolicyDenied, BudgetExceeded) as exc:
                    # `_pre_check` sets the status before raising, so a denial of
                    # *this* call is already recorded. One arriving from inside
                    # the body — a nested @vmware_tool call policy refused,
                    # propagating outward — left the default "ok", so the
                    # orchestrating call audited as a success it never was.
                    if state.status == "ok":
                        state.status = (
                            "denied" if isinstance(exc, PolicyDenied) else "budget_exceeded"
                        )
                        if isinstance(exc, PolicyDenied):
                            # The rule too, so a tool's own refusal (Pilot's
                            # approve, by role) filters like the others.
                            state.result = {"error": exc.result.reason, "rule": exc.result.rule}
                    raise
                except Exception as exc:
                    _capture_error(state, exc)
                    raise
                except BaseException as exc:
                    # SystemExit / KeyboardInterrupt / a cancelled call: not an
                    # Exception, and until 2026-09-15 recorded as "ok".
                    _capture_abnormal_exit(state, exc)
                    raise
                finally:
                    # Nested, so the signal is restored even if auditing raises:
                    # a leaked binding would mark the next call on this task failed.
                    try:
                        _finalize(state)
                    finally:
                        if state.status == "error":
                            _frame.mark_failed(frame_sink)
                        _frame.release(frame_token)
                        _failure_signal.reset(token)
        else:

            @wraps(func)
            def wrapper(*args: Any, **kwargs: Any) -> Any:
                state = _CallState(
                    func,
                    args,
                    kwargs,
                    signature,
                    _sensitive,
                    risk_level,
                    timeout_seconds,
                    undo,
                    sensitive_result,
                )
                # Fresh binding per call, restored below: a nested tool's
                # `report_tool_failure` must not mark its caller failed, and a
                # signal must not survive into the next call on this task.
                token = _failure_signal.set(None)
                # The MCP request's failure mark (vmware_policy.frame): only the
                # outermost tool call of a request may set it.
                frame_sink, frame_token = _frame.claim()
                try:
                    _role_check(state)
                    _check_common_arguments(state.raw_params)
                    _pre_check(state)
                    return _annotate_result(state, func(*args, **kwargs))
                except (PolicyDenied, BudgetExceeded) as exc:
                    # `_pre_check` sets the status before raising, so a denial of
                    # *this* call is already recorded. One arriving from inside
                    # the body — a nested @vmware_tool call policy refused,
                    # propagating outward — left the default "ok", so the
                    # orchestrating call audited as a success it never was.
                    if state.status == "ok":
                        state.status = (
                            "denied" if isinstance(exc, PolicyDenied) else "budget_exceeded"
                        )
                        if isinstance(exc, PolicyDenied):
                            # The rule too, so a tool's own refusal (Pilot's
                            # approve, by role) filters like the others.
                            state.result = {"error": exc.result.reason, "rule": exc.result.rule}
                    raise
                except Exception as exc:
                    _capture_error(state, exc)
                    raise
                except BaseException as exc:
                    # SystemExit / KeyboardInterrupt / a cancelled call: not an
                    # Exception, and until 2026-09-15 recorded as "ok".
                    _capture_abnormal_exit(state, exc)
                    raise
                finally:
                    # Nested, so the signal is restored even if auditing raises:
                    # a leaked binding would mark the next call on this task failed.
                    try:
                        _finalize(state)
                    finally:
                        if state.status == "error":
                            _frame.mark_failed(frame_sink)
                        _frame.release(frame_token)
                        _failure_signal.reset(token)

        # ── Attach metadata for harness / introspection ───────────
        wrapper._is_vmware_tool = True
        wrapper._risk_level = risk_level
        wrapper._idempotent = idempotent
        wrapper._timeout_seconds = timeout_seconds
        wrapper._sensitive_params = list(_sensitive)
        wrapper._sensitive_result = sensitive_result
        return wrapper

    # Support @vmware_tool and @vmware_tool(...)
    if fn is not None:
        return decorator(fn)
    return decorator


# ── Internal helpers ──────────────────────────────────────────────────


class _CallState:
    """Per-call context shared by the sync and async wrapper bodies.

    Built once per invocation; the helper functions (`_pre_check`,
    `_annotate_result`, `_capture_error`, `_finalize`) read and mutate it so
    both wrappers keep identical audit / policy / circuit-breaker semantics.
    """

    __slots__ = (
        "skill",
        "tool_name",
        "agent",
        "start",
        "status",
        "result",
        "policy_result",
        "pattern_match",
        "safe_params",
        "target",
        "resolved_target",
        "risk_level",
        "timeout_seconds",
        "rationale",
        "approved_by",
        "undo",
        "sensitive_result",
        "raw_params",
        "previewed",
        "role",
    )

    def __init__(
        self,
        func: Any,
        args: tuple[Any, ...],
        kwargs: dict[str, Any],
        signature: inspect.Signature,
        sensitive: set[str],
        risk_level: str,
        timeout_seconds: int,
        undo: Any = None,
        sensitive_result: bool = False,
    ) -> None:
        self.undo = undo
        self.sensitive_result = sensitive_result
        self.skill = _infer_skill(func)
        self.tool_name = func.__name__
        self.agent = detect_agent()
        self.start = time.time()
        self.status = "ok"
        self.result: Any = None
        # Decided from the real result: ``result`` may hold the redaction sentinel.
        self.previewed = False
        self.policy_result: PolicyResult | None = None
        self.pattern_match: PatternMatch | None = None
        self.risk_level = risk_level
        self.timeout_seconds = timeout_seconds
        # The caller's role at call time (HLD §18 D-22); '' when roles do not apply.
        self.role = ""

        # Map positional args to parameter names so they appear in the audit
        # log and participate in env scoping (previously only kwargs did).
        params = _bind_params(signature, args, kwargs)
        # The real arguments, for the runaway breaker's digest only (never
        # audited, never logged); safe_params is what the audit row gets.
        self.raw_params = params
        self.safe_params = _redact(params, sensitive)
        # Keep the target name: the pattern engine's rate limits and circuit
        # breakers are keyed per-TARGET (feeding them the environment pooled
        # every 'production' vCenter into one counter — one flaky target tripped
        # the breaker for all of them, 2026-07-18 review). The environment itself
        # is resolved inside guard() for policy scoping, so it is not stored here.
        self.target, self.resolved_target = _call_target(
            self.skill, self.tool_name, params, frozenset(signature.parameters)
        )

        # Accountability trail (SOC2 / 等保: who authorized this, and why).
        # Self-attested audit enrichment, not authorization (HLD §8.3): sourced
        # from env so an approval workflow / pilot can inject context without
        # changing every tool signature.
        # Not for network callers (HLD §16 D-12): the server's environment is
        # one value shared by every caller, so stamping it on their rows would
        # attribute one person's rationale or approval to everyone.
        from vmware_policy.caller import current_caller

        network = current_caller() is not None
        self.rationale = "" if network else os.environ.get("VMWARE_AUDIT_RATIONALE", "")
        self.approved_by = "" if network else os.environ.get("VMWARE_AUDIT_APPROVED_BY", "")


def _call_target(
    skill: str, tool: str, params: dict[str, Any], arg_names: frozenset[str] = frozenset()
) -> tuple[str, str]:
    """``(target, resolved_target)`` for a call.

    ``target`` is unchanged from before: the ``target`` (or ``env``) argument as
    passed, or ``""``. It keys the per-target breakers and reaches guard(), and
    the CLI binds it the same way (I-3), so it must not move.

    ``resolved_target`` is for the audit row only: when a tool that acts on ONE
    target (role scope ``one``, HLD §18) is called without its target argument,
    the name the connection will use, from the skill's role resolver. Found on a
    real Log Insight (2026-10-17): such calls ran on the default target and were
    audited as ``"target": null``, so the audit log could not say which appliance
    had been read. Tools that read every target or none get nothing — naming the
    default there would claim a system that was not the one used (review MED-1).
    A missing resolver, or one that fails (no default configured), gives ``""``.

    "Acts on one target" follows the role check's ``scope_of``, except that
    "takes the target argument" is read from the tool's own signature: the
    server's tool registry (``target_params``) is only recorded for a network
    transport, and stdio is where most calls run.
    """
    raw = params.get("target", params.get("env", ""))
    target = str(raw) if raw else ""
    try:
        from vmware_policy import roles

        meta = roles.metadata(skill)
    except Exception:  # noqa: BLE001 — roles are optional; never break a call
        meta = None
    if meta is None or meta.resolver is None:
        return target, ""
    # The role check's scope_of(), with the tool's own signature standing in for
    # the network-only registry: tagged scope first, then "takes the target
    # argument", then the skill's untagged default (AVI: "one").
    scope = meta.target_scope.get(tool) or (
        "one" if meta.target_param in arg_names else meta.untagged_scope
    )
    if scope != "one":
        return target, ""
    if params.get(meta.target_param):
        return target, ""
    try:
        name = meta.resolver(None)
    except Exception:  # noqa: BLE001 — an unresolvable default is the tool's error to report
        return target, ""
    return target, str(name) if name else ""


def _audit_params(state: _CallState) -> dict[str, Any]:
    """The parameters as passed, plus ``resolved_target`` when one was resolved."""
    if not state.resolved_target:
        return state.safe_params
    return {**state.safe_params, "resolved_target": state.resolved_target}


def _bind_params(
    signature: inspect.Signature, args: tuple[Any, ...], kwargs: dict[str, Any]
) -> dict[str, Any]:
    """Build a full name→value param dict from positional + keyword args.

    Falls back to kwargs-only if binding fails (the actual call will raise
    the matching TypeError; audit should not mask it with its own).
    """
    try:
        bound = signature.bind_partial(*args, **kwargs)
        # Apply declared defaults so env scoping and risk-tier matching see the
        # effective target/tags even when the caller relied on a default value
        # (bind_partial alone only captures explicitly-passed arguments).
        bound.apply_defaults()
    except TypeError:
        return dict(kwargs)
    params: dict[str, Any] = {}
    for name, value in bound.arguments.items():
        kind = signature.parameters[name].kind
        if kind == inspect.Parameter.VAR_KEYWORD:
            params.update(value)
        elif kind == inspect.Parameter.VAR_POSITIONAL:
            params[name] = list(value)
        else:
            params[name] = value
    return params


class ToolArgumentError(ValueError):
    """An argument no tool in the family accepts, refused before the tool runs.

    A ``ValueError`` so code that catches ``ValueError`` around a call still
    sees it. It is raised by the decorator, outside the tool body, so on MCP it
    reaches the client as a tool error (``isError``) rather than through a
    repo's ``{"error": ...}`` envelope; the CLI guard prints it and exits 2.
    """


def _check_common_arguments(params: dict[str, Any], *, cli: bool = False) -> None:
    """Family-wide argument rules, checked once instead of in every tool.

    ``limit`` (2026-10-15): nine repos slice ``results[:limit]`` themselves, so
    ``limit=-1`` silently dropped the last row and ``limit=0`` returned nothing,
    while the shared envelope reads both as "unlimited". ``None`` (omitted)
    means the tool's own default — every row for some tools, a page for
    others — so the message says "default", not "every row". Over MCP the
    schema coerces first (``true`` → 1, ``"5"`` → 5), so the bool/str refusal
    only fires for direct Python calls.

    Host paths (HLD §18 step 0): a parameter named in
    ``hostpaths.HOST_PATH_PARAMS`` names a file on this server, and may not
    resolve into its configuration, tokens or audit log.
    """
    from vmware_policy.hostpaths import HOST_PATH_PARAMS, check_host_path

    for name in HOST_PATH_PARAMS.intersection(params):
        check_host_path(params[name])
    if "limit" not in params:
        return
    limit = params["limit"]
    if limit is None:
        return
    if isinstance(limit, bool) or not isinstance(limit, int) or limit < 1:
        name, what = ("--limit", "command") if cli else ("limit", "tool")
        raise ToolArgumentError(
            f"{name} must be a positive integer (1 or more), got {limit!r}. "
            f"Omit {name} to use this {what}'s default."
        )


def _role_check(state: _CallState) -> None:
    """Roles first (HLD §18 D-21(1)): which tools and targets this caller's token may use.

    Before the argument checks, so every refusal row carries the caller's role and a
    role without the tool learns nothing from a tool's argument rules (review M2).
    A refusal is also recorded in the per-caller budget, so repeating the same refused
    call trips the runaway guard (D-25). Probing different tools or targets does not:
    on a network server only the identical-call guard applies (review L-3). None when
    roles do not apply (stdio, CLI).
    """
    from vmware_policy import roles

    decision = roles.check_call(state.skill, state.tool_name, state.raw_params)
    if decision is None:
        return
    state.role = decision.role
    if decision.allowed:
        return
    state.status = "denied"
    state.result = {"error": decision.reason, "rule": decision.rule}
    try:
        get_budget().check_and_record(state.tool_name, state.raw_params)
    except BudgetExceeded as exc:
        state.status = "budget_exceeded"
        state.result = {"error": exc.reason, "rule": exc.rule}
        raise
    raise PolicyDenied(PolicyResult(False, decision.rule, decision.reason))


def _pre_check(state: _CallState) -> None:
    """Policy pre-check + L5 auto-remediation pattern consult.

    Raises PolicyDenied when policy denies the call. Pattern engine failures
    never block the call (fail-open by design — a broken pattern file must
    not take down every MCP tool).
    """
    # Authorize through the shared guard so the CLI and MCP surfaces apply the
    # exact same policy (HLD §4, I-3). guard() is a no-op unless the operator
    # wrote deny / maintenance rules. Approval tiers were removed in v1.8.7:
    # read/write authorization is the vCenter account's job (RBAC), not a
    # per-call gate (HLD §5/§9). Preserve the denied-call audit shape by
    # recording the reason/rule before re-raising.
    try:
        state.policy_result = guard(
            state.skill,
            state.tool_name,
            state.safe_params,
            risk_level=state.risk_level,
            target=state.target,
        )
    except PolicyDenied as exc:
        state.status = "denied"
        state.result = {"error": exc.result.reason, "rule": exc.result.rule}
        raise

    # Budget / runaway guard — only for calls policy already allowed, so denied
    # calls do not count. A trip raises BudgetExceeded (a hard stop); record the
    # denial on state so _finalize audits it.
    try:
        get_budget().check_and_record(state.tool_name, state.raw_params)
    except BudgetExceeded as exc:
        state.status = "budget_exceeded"
        state.result = {"error": exc.reason, "rule": exc.rule}
        raise

    try:
        state.pattern_match = get_pattern_engine().match(
            skill=state.skill, tool=state.tool_name, target=state.target
        )
    except Exception:  # noqa: BLE001 — fail-open by design
        state.pattern_match = None


def _annotate_result(state: _CallState, result: Any) -> Any:
    """Record the result, surface pattern context, and record an undo token.

    Runs on every path that returns a value — which is not the same as the
    success path. A tool can fail and still return: the family's error wrappers
    catch the exception and hand back an error payload, so the function returns
    normally and nothing here would otherwise notice. That gap made the audit
    row say ``ok`` for a failed operation, recorded an undo token for a change
    that never happened, and fed ``success=True`` to the circuit breaker, which
    is why layer three of CLAUDE.md's recovery model never tripped for most of
    the family. Detecting the returned failure first restores all three.

    A tool that declared ``sensitive_result`` contributes only the sentinel to
    the audit row — the credential itself never lands on ``state``, so no later
    step can carry it into a column the redaction does not cover. The caller
    still receives the real object, and ``_record_undo`` below still sees it.
    """
    state.result = _REDACTED_DECLARED if state.sensitive_result else result
    state.previewed = _is_preview_result(result)
    if _returned_failure(result) or _failure_signal.get() is not None:
        state.status = "error"
    if state.pattern_match and state.pattern_match.armed and isinstance(result, dict):
        result.setdefault("_pattern_id", state.pattern_match.pattern.pattern_id)
        result.setdefault("_pattern_armed", True)
    _record_undo(state, result)
    return result


def _is_dry_run(params: dict[str, Any]) -> bool:
    """True when the call was a preview: its ``dry_run`` parameter is literally True.

    A dry run changes nothing, so it is audited as ``dry_run`` rather than ``ok``
    and records no undo token. Found 2026-09-14: nine ``--dry-run`` maintenance
    and alert-note calls sat in an operator's audit trail as plain ``ok``, which
    reads as windows opened and notes posted that never existed.
    """
    return params.get("dry_run") is True


def _is_preview_result(result: Any) -> bool:
    """True when the tool answered with the family's preview shape.

    HLD §7 (revised 2026-09-16): gated tools take ``confirm: bool = False`` and a
    bare call returns ``{"action": "preview", ...}``. Only the top-level key
    counts; a row inside a listing that happens to say "preview" is data.
    """
    return isinstance(result, dict) and result.get("action") == "preview"


def audited_status(
    status: str, params: dict[str, Any], *, bypassed: bool = False, previewed: bool = False,
) -> str:
    """The status an audit row records for a call that ended in ``status``.

    One place for both surfaces (``@vmware_tool`` and ``@guarded``): a completed
    dry run becomes ``dry_run``, and a policy bypass appends ``_bypassed``.
    """
    preview = previewed or _is_dry_run(params)
    recorded = "dry_run" if status == "ok" and preview else status
    return f"{recorded}_bypassed" if bypassed else recorded


def _record_undo(state: _CallState, result: Any) -> None:
    """Compute and persist the inverse descriptor for a successful write.

    Best-effort: a broken undo callable or store must never fail the call.
    Attaches ``_undo_id`` to dict results so the agent / pilot can reference it.

    Skipped once the call is known to have failed: an undo token asserts that a
    change happened and can be reversed, and offering to reverse a write that
    never landed is worse than offering nothing.
    """
    if (
        state.undo is None
        or state.status != "ok"
        or _is_dry_run(state.safe_params)
        or _is_preview_result(result)
    ):
        return
    try:
        descriptor = state.undo(state.safe_params, result)
    except Exception:  # noqa: BLE001 — undo computation must not fail the call
        _log.warning("undo callable for %s.%s raised", state.skill, state.tool_name, exc_info=True)
        return
    if not descriptor:
        return
    try:
        from vmware_policy.undo import get_undo_store

        undo_id = get_undo_store().record(
            skill=state.skill,
            tool=state.tool_name,
            undo_descriptor=descriptor,
            orig_params=state.safe_params,
        )
        if undo_id and isinstance(result, dict):
            result.setdefault("_undo_id", undo_id)
    except Exception:  # noqa: BLE001 — recording is best-effort
        _log.warning("failed to record undo for %s.%s", state.skill, state.tool_name, exc_info=True)


def _capture_error(state: _CallState, exc: Exception) -> None:
    """Record a failure without persisting a stack or internal file paths."""
    state.status = "error"
    state.result = {
        "error": sanitize(_redact_secrets_text(str(exc)), 500),
        "exception_type": type(exc).__name__,
    }


def _capture_abnormal_exit(state: _CallState, exc: BaseException) -> None:
    """Record a call that ended by a ``BaseException`` that is not an ``Exception``.

    HLD §8.2 / I-5 (extended 2026-09-15): a call that did not return normally is
    never ``ok``. ``SystemExit`` with a non-zero or message code is a failure the
    code chose to signal — vmware-avi's ops raise ``SystemExit(1)`` for "not
    found". ``SystemExit(0)`` / ``SystemExit(None)`` is a clean exit.
    ``KeyboardInterrupt`` and ``asyncio.CancelledError`` (a client that gave up)
    are ``interrupted``: a long write may still be running on the far side, so the
    row must not claim either success or a plain failure.
    """
    if isinstance(exc, SystemExit):
        if exc.code in (0, None):
            return
        state.status = "error"
        state.result = {"error": sanitize(_redact_secrets_text(f"SystemExit({exc.code})"), 500)}
        return
    state.status = "interrupted"
    state.result = {"error": f"call interrupted ({type(exc).__name__})"}


def _finalize(state: _CallState) -> None:
    """Audit + circuit-breaker bookkeeping. Runs in the wrapper's finally."""
    duration = int((time.time() - state.start) * 1000)

    # Accumulate wall-time toward the cumulative time budget (best-effort).
    try:
        get_budget().add_duration(time.time() - state.start)
    except Exception:  # noqa: BLE001 — bookkeeping must never fail the call
        pass

    # timeout_seconds is advisory: exceeding it logs a warning, no hard
    # cancellation (cancelling mid-flight vSphere/NSX calls is worse).
    if state.timeout_seconds and duration > state.timeout_seconds * 1000:
        _log.warning(
            "%s.%s took %dms — exceeded timeout_seconds=%d (advisory, not cancelled)",
            state.skill,
            state.tool_name,
            duration,
            state.timeout_seconds,
        )

    bypassed = bool(state.policy_result and state.policy_result.rule == "policy_disabled")
    final_status = audited_status(
        state.status, state.safe_params, bypassed=bypassed, previewed=state.previewed,
    )

    # Update circuit-breaker state for armed patterns. An interrupted call is
    # skipped: a user cancelling (or a client giving up) says nothing about
    # whether the pattern works, and counting it as a failure could trip the
    # breaker on a remediation that was succeeding.
    if state.pattern_match and state.pattern_match.armed and state.status != "interrupted":
        try:
            get_pattern_engine().report_outcome(
                pattern_id=state.pattern_match.pattern.pattern_id,
                target=state.target,
                success=(state.status == "ok"),
            )
        except Exception:  # noqa: BLE001 — never let bookkeeping fail the call
            pass

    pattern_id = state.pattern_match.pattern.pattern_id if state.pattern_match else ""
    pattern_armed = bool(state.pattern_match and state.pattern_match.armed)

    # Single audit sink for every surface (I-8). risk_tier is gone with the
    # approval tiers; `user` is left to AuditEngine.log, which fills the OS user.
    audit_call(
        state.skill,
        state.tool_name,
        params=_audit_params(state),
        result=_with_pattern_context(
            _redact_credential_keys(state.result), pattern_id, pattern_armed
        ),
        status=final_status,
        duration_ms=duration,
        agent=state.agent,
        risk_level=state.risk_level,
        rationale=state.rationale,
        approved_by=state.approved_by,
        role=state.role,
    )


def _infer_skill(func: Any) -> str:
    """Infer skill name from the function's module path.

    ``vmware_aiops.ops.vm_lifecycle`` → ``aiops``
    ``mcp_server.server`` → try the parent package → ``unknown``
    """
    return skill_name(getattr(func, "__module__", "") or "")


from vmware_policy._redaction import (
    _redact as _redact,
    _redact_value as _redact_value,
    _is_credential_key as _is_credential_key,
    _scrub_text_values as _scrub_text_values,
    _redact_credential_keys as _redact_credential_keys,
    _redact_secrets_text as _redact_secrets_text,
    _REDACTED_DECLARED as _REDACTED_DECLARED,
    _REDACTED_KEY as _REDACTED_KEY,
    _CREDENTIAL_KEYS as _CREDENTIAL_KEYS,
    _ALREADY_REDACTED as _ALREADY_REDACTED,
    _CREDENTIAL_TAILS as _CREDENTIAL_TAILS,
    _SECRET_WORDS as _SECRET_WORDS,
    _TOKEN_START as _TOKEN_START,
    _KEY_PREFIX as _KEY_PREFIX,
    _VALUE as _VALUE,
    _STATUS_WORDS as _STATUS_WORDS,
    _AUTH_SCHEMES as _AUTH_SCHEMES,
    _NOT_A_SCHEME as _NOT_A_SCHEME,
)


def _with_pattern_context(result: Any, pattern_id: str, armed: bool) -> Any:
    """Attach pattern metadata to an audit row's result field.

    Only mutates dict results; non-dict results (errors, primitives) are
    returned unchanged so the audit log preserves them faithfully.
    """
    if not pattern_id:
        return result
    if isinstance(result, dict):
        annotated = dict(result)
        annotated.setdefault("_pattern_id", pattern_id)
        annotated.setdefault("_pattern_armed", armed)
        return annotated
    return result
