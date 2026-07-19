"""The family's list-result envelope.

A bare ``list[dict]`` cannot tell an agent whether it is holding the whole
answer or the first page of one. Agents fill that gap by guessing, and the
guesses are bad in both directions: a fifty-row page gets summarised as "all
fifty VMs", or — worse — a long response gets reported as "no data returned"
(VMware-AIops issue #31, observed with Llama 3.3 70B).

Every list-returning tool wraps its rows with :func:`paginated`, so the count,
the limit, and whether more data exists are stated rather than inferred.

The envelope always carries the same six keys. Unknown values are explicit
``None`` rather than omitted, because a missing key is exactly the kind of gap
a model fills with invention::

    {
      "items":     [...],
      "returned":  50,
      "limit":     50,
      "total":     213,      # None when the backing API does not report one
      "truncated": True,
      "hint":      "Showing 50 of 213. ...",   # None when complete
    }
"""

from __future__ import annotations

from typing import Any

#: The envelope's key contract, in order. Public so tests and consumers assert
#: against the one definition instead of re-declaring it (the 2026-07-18 review
#: found ~12 hand-copied tuples in per-repo tests that a seventh key would
#: silently leave stale).
ENVELOPE_KEYS: tuple[str, ...] = ("items", "returned", "limit", "total", "truncated", "hint")

#: Keys the envelope owns; callers may not pass these as extras.
_RESERVED = frozenset(ENVELOPE_KEYS)


def _hint(returned: int, limit: int | None, total: int | None) -> str:
    """Explain the truncation without claiming a total we never fetched."""
    if total is not None:
        return (
            f"Showing {returned} of {total}. Raise limit or narrow the query "
            f"with a filter to see the rest."
        )
    return (
        f"Showing {returned}, which is the current limit ({limit}) — there may "
        f"be more. Raise limit or narrow the query with a filter to be sure "
        f"this is the whole picture."
    )


def paginated(
    items: list[dict],
    limit: int | None = None,
    total: int | None = None,
    **extra: Any,
) -> dict[str, Any]:
    """Wrap list rows in the family's envelope.

    Args:
        items: The rows to return, in the order the caller wants them kept.
        limit: The limit that produced this page. ``None``, ``0`` or a negative
            value means the query was unlimited, so nothing can be truncated.
        total: The full collection size when the backing API reports one. Left
            as ``None`` otherwise — a known total is what lets a full page be
            recognised as complete rather than flagged as possibly-truncated.
        **extra: Additional top-level keys (e.g. ``target``). May not shadow
            the envelope's own keys.

    Returns:
        The envelope dict. ``items`` is a new list; the caller's list is never
        mutated.

    Truncation is reported conservatively: with no ``total`` to check against, a
    page filled exactly to the limit is flagged as truncated, because it cannot
    be distinguished from one. Saying "there may be more" when there is not
    costs a redundant query; the opposite costs a wrong answer.
    """
    clashes = _RESERVED & set(extra)
    if clashes:
        raise ValueError(
            f"Envelope keys cannot be overridden via extras: "
            f"{', '.join(sorted(clashes))}. Rename the extra field."
        )

    rows = list(items)
    returned = len(rows)
    effective_limit = limit if limit and limit > 0 else None

    if total is not None:
        truncated = returned < total
    else:
        truncated = effective_limit is not None and returned >= effective_limit

    return {
        "items": rows,
        "returned": returned,
        "limit": effective_limit,
        "total": total,
        "truncated": truncated,
        "hint": _hint(returned, effective_limit, total) if truncated else None,
        **extra,
    }
