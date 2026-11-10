"""VM reconfiguration limits evaluated from backend-read configuration facts."""

from __future__ import annotations

import math
from typing import Any

_FIELDS = {"max_cpu_change_pct": "cpu", "max_memory_change_pct": "memory_mb"}


def check_vm_change(
    limits: Any, before: dict, after: dict, change_version: str | None
) -> str | None:
    """Return a refusal, or None. Never trust a caller-provided percentage."""
    if limits is None or limits == {}:
        return None
    if not isinstance(limits, dict) or set(limits) - set(_FIELDS):
        return "Malformed change_limits: only max_cpu_change_pct and max_memory_change_pct are supported."
    for name, threshold in limits.items():
        if (
            isinstance(threshold, bool)
            or not isinstance(threshold, (int, float))
            or not _finite(threshold)
            or threshold < 0
        ):
            return f"Malformed change_limits.{name}: expected a finite nonnegative percentage."
    affected = [
        (name, field) for name, field in _FIELDS.items() if name in limits and field in after
    ]
    if not affected:
        return None
    if not isinstance(change_version, str) or not change_version.strip():
        return "Change limits require the VM configuration changeVersion; no reconfiguration was started."
    for name, field in affected:
        old, new = before.get(field), after[field]
        if any(isinstance(v, bool) or not isinstance(v, int) or v <= 0 for v in (old, new)):
            return f"Change limits require positive current and desired {field}; no reconfiguration was started."
        # Cross multiplication avoids division by zero and rounding at the boundary.
        if abs(new - old) * 100 > old * limits[name]:
            return f"VM reconfiguration exceeds change_limits.{name}; inspect current sizing and the configured limit."
    return None


def _finite(value: int | float) -> bool:
    try:
        return math.isfinite(value)
    except OverflowError:
        return False
