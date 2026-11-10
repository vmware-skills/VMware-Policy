"""Nested-call failure signals, isolated per execution context."""

from __future__ import annotations

import contextvars
from typing import Any

_failure_signal: contextvars.ContextVar[str | None] = contextvars.ContextVar(
    "vmware_policy_tool_failure", default=None
)


def report_tool_failure(message: str) -> None:
    """Declare that the in-flight tool call failed, though it will *return*.

    Most tools signal failure by raising, which the wrapper already records. A
    tool that instead returns an error payload looks identical to a successful
    one, so it must say so explicitly::

        try:
            ...
        except Exception as exc:
            report_tool_failure(str(exc))
            return f"Error: {msg}"

    Dict-shaped payloads carrying a truthy ``error`` key are detected without
    this call — that is the family's own documented envelope, so reading it is
    following a convention rather than guessing. String returns are *not*
    sniffed: skills that hand back console text can legitimately emit output
    beginning with "Error:" as data, and marking those calls failed would be the
    same lie in the opposite direction. Such skills call this instead.

    No-op outside a tool call.
    """
    _failure_signal.set(message)


def _returned_failure(result: Any) -> bool:
    """True if ``result`` is the family's documented error envelope.

    Narrow on purpose. ``{"error": <truthy>}`` and a one-element list of the
    same are exactly what the family's error wrappers produce. A falsy ``error``
    key is a result reporting that nothing went wrong, and a multi-element list
    is a batch that returned partial results — a successful call either way.

    **Where the boundary is, and why it is not narrower.** A survey of every
    error-keyed dict in the family found 122 of 130 caught-error payloads are
    exactly ``{error, hint}`` — so requiring ``hint`` looks tempting. It would
    also stop detecting ~25 genuine failures that carry no hint: the plan guards
    in vmware-aiops (``{"error": "Plan 'x' not found"}``) and vmware-pilot's
    terminal-state refusals (``{"error": ..., "state": ..., "workflow_id": ...}``).
    Under-detecting reintroduces the bug this function exists to fix, in the
    other direction, so the rule stays keyed on ``error`` alone.

    The cost is that a *successful* call whose result happens to describe some
    other object's failure reads as a failed call. That ambiguity belongs to the
    payload, not to this rule: ``{"state": "error", "error": ...}`` cannot tell a
    model whether the call failed or the thing it polled did, either. Such
    payloads name the field for what it is (``task_error``) rather than being
    special-cased here.
    """
    if isinstance(result, dict):
        return _says_it_failed(result)
    if isinstance(result, list) and len(result) == 1 and isinstance(result[0], dict):
        return _says_it_failed(result[0])
    return False


def _says_it_failed(result: dict[str, Any]) -> bool:
    """True if a result states, in its own words, that *this call* failed.

    Two shapes only: ``{"error": <truthy>}``, the family's documented envelope,
    and ``outcome == "failed"`` (vmware-pilot workflows, added 2026-09-15 after a
    family survey found them audited ``ok``; HLD §8.2 / I-5).

    ``ok`` and ``success`` are deliberately not read (review decision D2, the
    same day). No producer in the family uses ``ok: False`` / ``success: False``
    to mean "this call failed" without also carrying a truthy ``error``, and one
    uses ``success: False`` as the *answer*: vmware-aiops ``ping_from_vmk`` returns it
    for an unreachable host or an esxcli fault, which for an MTU probe is the
    result being asked for. Reading it filed those successful probes ``error``
    and disagreed with AIops' MCP frame detector (``_is_error_envelope``), which
    reads ``error`` only.

    ``status`` is not read either. ``{"status": "error"}`` is as often a
    successful call reporting the state of a task or object it polled as it is a
    failed call, and guessing wrong in either direction is the same lie. A tool
    whose failure is only a status string calls :func:`report_tool_failure`.
    """
    return bool(result.get("error")) or result.get("outcome") == "failed"
