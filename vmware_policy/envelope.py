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


# Shared offset-pagination semantics; domain-specific caps stay in each skill.

def next_offset(returned: int, limit: int, offset: int, total: int | None) -> int | None:
    """The ``offset`` for the next page, or ``None`` when this page is the last.

    This — not ``truncated`` — is what a paging loop terminates on.

    With a ``total`` the answer is exact: there is a next page when rows remain
    behind the window this one consumed. Without one, a page filled exactly to
    the limit cannot be told apart from a page that was cut short, so it is
    reported as having a successor. Being wrong that way costs one more call
    that comes back empty and ends the walk; being wrong the other way costs
    rows the caller never learns exist.

    Args:
        returned: Rows in this page.
        limit: The validated page size that produced it.
        offset: The validated offset this page started at.
        total: The collection size when the manager reported one, else ``None``.

    Returns:
        The next offset, or ``None`` if this page ends the collection.
    """
    if returned <= 0:
        return None
    consumed = offset + returned
    if total is not None:
        return consumed if consumed < total else None
    return consumed if returned >= limit else None

def page_hint(
    returned: int, limit: int, offset: int, total: int | None, nxt: int | None
) -> str | None:
    """Explain the current offset window without implying another page exists."""
    if nxt is not None:
        if total is not None:
            return (
                f"Showing rows {offset}-{offset + returned - 1} of {total}. "
                f"Continue at offset {nxt} for the next page, or narrow the query "
                f"with a filter."
            )
        return (
            f"Showing {returned} rows from offset {offset}, which fills the limit "
            f"({limit}) — there may be more. Continue at offset {nxt}; the walk "
            f"ends when next_offset is null."
        )
    if returned == 0:
        if total is not None and offset >= total:
            return (
                f"No rows at offset {offset}: the collection holds {total}, so this "
                f"offset is past the end. There is no next page — start again at "
                f"offset 0."
            )
        # Zero rows that are not past a known end: the manager returned nothing
        # for a window inside the collection it reported. Say what happened
        # rather than inventing a cause.
        return ("No rows on this page, and no next page. "
                "Re-read from offset 0 to see the collection.")
    size = f"{total}" if total is not None else "the collection"
    return (
        f"Showing rows {offset}-{offset + returned - 1}, the last {returned} of {size}. "
        f"There is no next page. 'truncated' is true because these {returned} rows are "
        f"not the whole collection, not because more can be fetched — read from "
        f"offset 0 for all of it."
    )

def page_envelope(
    items: list[dict], *, limit: int, offset: int, total: int | None, **extra: Any,
) -> dict[str, Any]:
    """Wrap an offset-capable tool page without changing the six legacy keys.

    Only use for tools that accept offset. next_offset, not truncated, ends
    the walk; a final partial page can still be a subset of the collection.
    The caller's domain-specific maximum limit remains its responsibility.
    """
    if isinstance(limit, bool) or not isinstance(limit, int) or limit <= 0:
        raise ValueError("limit must be a positive integer")
    if isinstance(offset, bool) or not isinstance(offset, int) or offset < 0:
        raise ValueError("offset must be a nonnegative integer")
    nxt = next_offset(len(items), limit, offset, total)
    result = paginated(items, limit=limit, total=total, offset=offset,
                       next_offset=nxt, **extra)
    if result["truncated"]:
        result["hint"] = page_hint(len(items), limit, offset, total, nxt)
    return result
