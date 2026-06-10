"""The ``@vmware_tool`` decorator — mandatory wrapper for all VMware MCP tool functions.

Responsibilities:
  1. Pre-check: evaluate policy rules (deny, maintenance window, limits)
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

import re
import time
import traceback
from functools import wraps
from typing import Any

from vmware_policy.audit import AuditEngine, detect_agent, get_engine
from vmware_policy.patterns import PatternMatch, get_pattern_engine
from vmware_policy.policy import PolicyEngine, PolicyResult, get_policy_engine
from vmware_policy.sanitize import sanitize


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
        timeout_seconds: Maximum execution time before warning.
        sensitive_params: Parameter names to redact in audit logs.
    """
    _sensitive = set(sensitive_params or [])

    def decorator(func: Any) -> Any:
        @wraps(func)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            skill = _infer_skill(func)
            tool_name = func.__name__
            agent = detect_agent()
            start = time.time()
            status = "ok"
            result: Any = None
            policy_result: PolicyResult | None = None
            pattern_match: PatternMatch | None = None
            audit = get_engine()
            policy = get_policy_engine()

            # ── Redact sensitive params for logging ───────────────
            safe_params = _redact(kwargs, _sensitive)

            try:
                # ── Policy pre-check ──────────────────────────────
                env = kwargs.get("target", kwargs.get("env", ""))
                policy_result = policy.check_allowed(
                    tool_name,
                    env=str(env) if env else "",
                    risk_level=risk_level,
                    params=safe_params,
                )

                if not policy_result.allowed:
                    status = "denied"
                    result = {"error": policy_result.reason, "rule": policy_result.rule}
                    raise PolicyDenied(policy_result)

                # ── L5 auto-remediation pattern check ─────────────
                # Patterns are signed YAMLs in ~/.vmware/auto-remediation-patterns/.
                # Matching attaches pattern_id to the audit row and may signal
                # the caller that double-confirm can be skipped. Rate-limit and
                # circuit-breaker enforcement happens inside the engine. Failure
                # to consult the engine never blocks the call (fail-open).
                try:
                    pattern_match = get_pattern_engine().match(
                        skill=skill, tool=tool_name,
                        target=str(env) if env else "",
                    )
                except Exception:  # noqa: BLE001 — fail-open by design
                    pattern_match = None

                # ── Execute ───────────────────────────────────────
                result = func(*args, **kwargs)
                # If the result is a dict and a pattern is armed, surface
                # the pattern_id so callers can elide UI-level confirmation.
                if pattern_match and pattern_match.armed and isinstance(result, dict):
                    result.setdefault("_pattern_id", pattern_match.pattern.pattern_id)
                    result.setdefault("_pattern_armed", True)
                return result

            except PolicyDenied:
                raise

            except Exception as exc:
                status = "error"
                # Sanitize before persisting — exception text and tracebacks can
                # carry connection strings, credentials, internal paths, host:port.
                result = {
                    "error": sanitize(_redact_secrets_text(str(exc)), 500),
                    "traceback": sanitize(
                        _redact_secrets_text(traceback.format_exc()[-500:]), 500
                    ),
                }
                raise

            finally:
                duration = int((time.time() - start) * 1000)
                bypassed = policy_result and policy_result.rule == "policy_disabled"
                final_status = f"{status}_bypassed" if bypassed else status

                # Update circuit-breaker state for armed patterns
                if pattern_match and pattern_match.armed:
                    try:
                        get_pattern_engine().report_outcome(
                            pattern_id=pattern_match.pattern.pattern_id,
                            target=str(env) if env else "",
                            success=(status == "ok"),
                        )
                    except Exception:  # noqa: BLE001 — never let bookkeeping fail the call
                        pass

                # Annotate audit row with pattern context when present
                pattern_id = pattern_match.pattern.pattern_id if pattern_match else ""
                pattern_armed = bool(pattern_match and pattern_match.armed)

                audit.log(
                    skill=skill,
                    tool=tool_name,
                    params=safe_params,
                    result=_with_pattern_context(result, pattern_id, pattern_armed),
                    status=final_status,
                    duration_ms=duration,
                    agent=agent,
                    user="",
                    risk_level=risk_level,
                )

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
