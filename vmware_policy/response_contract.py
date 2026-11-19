"""Add a shared error view without replacing legacy text or structured fields.

Only callers with an authoritative failure verdict may use this projection.
The reserved ``vmware_error`` key is transport metadata, not a business field.
"""

from __future__ import annotations

import json
from typing import Any

ERROR_FIELD = "vmware_error"
_FALLBACK = "Tool call failed. Inspect the error content for details."


def error_view(content: list[Any], structured: dict[str, Any] | None) -> dict[str, Any]:
    """Return the common {error, hint} view of an already failed result.

    No exception parsing, message classification or new remote reads. Existing
    authored hints are used only when strings; none are invented from prose.
    """
    def envelope(value: Any) -> dict[str, Any] | None:
        if isinstance(value, dict):
            if isinstance(value.get("error"), str) and value["error"]:
                return {"error": value["error"],
                        "hint": value.get("hint") if isinstance(value.get("hint"), str) else None}
            if "result" in value:
                return envelope(value["result"])
        if isinstance(value, list) and len(value) == 1:
            return envelope(value[0])
        return None

    found = envelope(structured)
    if found is not None:
        return found
    texts = [part.text for part in content
             if getattr(part, "type", None) == "text" and isinstance(part.text, str)]
    for text in texts:
        try:
            found = envelope(json.loads(text))
        except (ValueError, TypeError):
            continue
        if found is not None:
            return found
    return {"error": "\n".join(texts) or _FALLBACK, "hint": None}


def with_error_view(content: list[Any], structured: dict[str, Any] | None) -> dict[str, Any]:
    """Add the reserved view; every existing legacy business field stays intact."""
    return {**(structured or {}), ERROR_FIELD: error_view(content, structured)}
