"""The ``@vmware_tool`` decorator — mandatory wrapper for all VMware MCP tool functions.

Responsibilities:
  1. Pre-check: evaluate policy rules (deny, maintenance window)
  2. Execute: run the actual tool function
  3. Post-log: write audit record to ``~/.vmware/audit.db``
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
import re
import time
import traceback
from functools import wraps
from typing import Any

from vmware_policy.audit import detect_agent, get_engine
from vmware_policy.patterns import PatternMatch, get_pattern_engine
from vmware_policy.policy import PolicyResult, get_policy_engine
from vmware_policy.sanitize import sanitize

_log = logging.getLogger("vmware-policy.decorators")


class PolicyDenied(Exception):
    """Raised when an operation is denied by policy."""

    def __init__(self, result: PolicyResult) -> None:
        self.result = result
        super().__init__(result.reason)


def vmware_tool(
    fn: Any = None,
    *,
    risk_level: str = "low",
    idempotent: bool = False,
    timeout_seconds: int = 300,
    sensitive_params: list[str] | None = None,
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
                    func, args, kwargs, signature, _sensitive, risk_level, timeout_seconds
                )
                try:
                    _pre_check(state)
                    return _annotate_result(state, await func(*args, **kwargs))
                except PolicyDenied:
                    raise
                except Exception as exc:
                    _capture_error(state, exc)
                    raise
                finally:
                    _finalize(state)
        else:
            @wraps(func)
            def wrapper(*args: Any, **kwargs: Any) -> Any:
                state = _CallState(
                    func, args, kwargs, signature, _sensitive, risk_level, timeout_seconds
                )
                try:
                    _pre_check(state)
                    return _annotate_result(state, func(*args, **kwargs))
                except PolicyDenied:
                    raise
                except Exception as exc:
                    _capture_error(state, exc)
                    raise
                finally:
                    _finalize(state)

        # ── Attach metadata for harness / introspection ───────────
        wrapper._is_vmware_tool = True
        wrapper._risk_level = risk_level
        wrapper._idempotent = idempotent
        wrapper._timeout_seconds = timeout_seconds
        wrapper._sensitive_params = list(_sensitive)
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
        "skill", "tool_name", "agent", "start", "status", "result",
        "policy_result", "pattern_match", "audit", "policy",
        "safe_params", "env", "risk_level", "timeout_seconds",
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
    ) -> None:
        self.skill = _infer_skill(func)
        self.tool_name = func.__name__
        self.agent = detect_agent()
        self.start = time.time()
        self.status = "ok"
        self.result: Any = None
        self.policy_result: PolicyResult | None = None
        self.pattern_match: PatternMatch | None = None
        self.risk_level = risk_level
        self.timeout_seconds = timeout_seconds
        self.audit = get_engine()
        self.policy = get_policy_engine()

        # Map positional args to parameter names so they appear in the audit
        # log and participate in env scoping (previously only kwargs did).
        params = _bind_params(signature, args, kwargs)
        self.safe_params = _redact(params, sensitive)
        env = params.get("target", params.get("env", ""))
        self.env = str(env) if env else ""


def _bind_params(
    signature: inspect.Signature, args: tuple[Any, ...], kwargs: dict[str, Any]
) -> dict[str, Any]:
    """Build a full name→value param dict from positional + keyword args.

    Falls back to kwargs-only if binding fails (the actual call will raise
    the matching TypeError; audit should not mask it with its own).
    """
    try:
        bound = signature.bind_partial(*args, **kwargs)
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


def _pre_check(state: _CallState) -> None:
    """Policy pre-check + L5 auto-remediation pattern consult.

    Raises PolicyDenied when policy denies the call. Pattern engine failures
    never block the call (fail-open by design — a broken pattern file must
    not take down every MCP tool).
    """
    state.policy_result = state.policy.check_allowed(
        state.tool_name,
        env=state.env,
        risk_level=state.risk_level,
        params=state.safe_params,
    )
    if not state.policy_result.allowed:
        state.status = "denied"
        state.result = {
            "error": state.policy_result.reason,
            "rule": state.policy_result.rule,
        }
        raise PolicyDenied(state.policy_result)

    try:
        state.pattern_match = get_pattern_engine().match(
            skill=state.skill, tool=state.tool_name, target=state.env
        )
    except Exception:  # noqa: BLE001 — fail-open by design
        state.pattern_match = None


def _annotate_result(state: _CallState, result: Any) -> Any:
    """Record the result and surface pattern context to the caller."""
    state.result = result
    if (
        state.pattern_match
        and state.pattern_match.armed
        and isinstance(result, dict)
    ):
        result.setdefault("_pattern_id", state.pattern_match.pattern.pattern_id)
        result.setdefault("_pattern_armed", True)
    return result


def _capture_error(state: _CallState, exc: Exception) -> None:
    """Record a failed call. Exception text and tracebacks can carry
    connection strings, credentials, internal paths — sanitize before
    persisting to the audit row."""
    state.status = "error"
    state.result = {
        "error": sanitize(_redact_secrets_text(str(exc)), 500),
        "traceback": sanitize(
            _redact_secrets_text(traceback.format_exc()[-500:]), 500
        ),
    }


def _finalize(state: _CallState) -> None:
    """Audit + circuit-breaker bookkeeping. Runs in the wrapper's finally."""
    duration = int((time.time() - state.start) * 1000)

    # timeout_seconds is advisory: exceeding it logs a warning, no hard
    # cancellation (cancelling mid-flight vSphere/NSX calls is worse).
    if state.timeout_seconds and duration > state.timeout_seconds * 1000:
        _log.warning(
            "%s.%s took %dms — exceeded timeout_seconds=%d (advisory, not cancelled)",
            state.skill, state.tool_name, duration, state.timeout_seconds,
        )

    bypassed = state.policy_result and state.policy_result.rule == "policy_disabled"
    final_status = f"{state.status}_bypassed" if bypassed else state.status

    # Update circuit-breaker state for armed patterns
    if state.pattern_match and state.pattern_match.armed:
        try:
            get_pattern_engine().report_outcome(
                pattern_id=state.pattern_match.pattern.pattern_id,
                target=state.env,
                success=(state.status == "ok"),
            )
        except Exception:  # noqa: BLE001 — never let bookkeeping fail the call
            pass

    pattern_id = state.pattern_match.pattern.pattern_id if state.pattern_match else ""
    pattern_armed = bool(state.pattern_match and state.pattern_match.armed)

    state.audit.log(
        skill=state.skill,
        tool=state.tool_name,
        params=state.safe_params,
        result=_with_pattern_context(state.result, pattern_id, pattern_armed),
        status=final_status,
        duration_ms=duration,
        agent=state.agent,
        user="",
        risk_level=state.risk_level,
    )


def _infer_skill(func: Any) -> str:
    """Infer skill name from the function's module path.

    ``vmware_aiops.ops.vm_lifecycle`` → ``aiops``
    ``mcp_server.server`` → try the parent package → ``unknown``
    """
    module = getattr(func, "__module__", "") or ""
    parts = module.split(".")
    for part in parts:
        if part.startswith("vmware_"):
            return part.replace("vmware_", "", 1)
    return "unknown"


def _redact(params: dict[str, Any], sensitive: set[str]) -> dict[str, Any]:
    """Return a copy of params with sensitive values replaced by '***'.

    Recurses into nested dicts AND lists/tuples so credentials buried inside
    collections (e.g. ``{"targets": [{"password": "x"}]}``) are redacted too.
    """
    if not sensitive:
        return params
    result: dict[str, Any] = {}
    for k, v in params.items():
        if k in sensitive:
            result[k] = "***"
        else:
            result[k] = _redact_value(v, sensitive)
    return result


def _redact_value(value: Any, sensitive: set[str]) -> Any:
    """Recursively redact sensitive keys inside dicts, lists, and tuples."""
    if isinstance(value, dict):
        return _redact(value, sensitive)
    if isinstance(value, (list, tuple)):
        return type(value)(_redact_value(item, sensitive) for item in value)
    return value


# Matches ``key=value`` / ``key: value`` / ``key"="value`` for common secret
# keys in free-form exception text. Value runs until whitespace, quote, comma,
# or '@' (to keep host:port that often follows a credential in DSNs).
_SECRET_TEXT_RE = re.compile(
    r"(?i)\b(password|passwd|pwd|token|secret|api[_-]?key|authorization|bearer)"
    r"(\s*[=:]\s*|\s+)"
    r"['\"]?[^\s'\",@]+",
)


def _redact_secrets_text(text: str) -> str:
    """Redact ``password=...`` / ``token: ...`` style secrets in free-form text."""
    return _SECRET_TEXT_RE.sub(r"\1\2***", text)


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
