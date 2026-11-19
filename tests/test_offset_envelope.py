"""Offset pagination terminates on next_offset, including unknown totals."""

import pytest

from vmware_policy.envelope import ENVELOPE_KEYS, next_offset, page_envelope


@pytest.mark.parametrize("returned,limit,offset,total,expected", [
    (2, 2, 0, 5, 2), (2, 2, 2, 5, 4), (1, 2, 4, 5, None),
    (0, 2, 6, 5, None), (0, 2, 0, None, None),
    (2, 2, 0, None, 2), (1, 2, 2, None, None),
    (0, 2, 2, None, None), (2, 2, 0, 2, None),
])
def test_continuation(returned, limit, offset, total, expected):
    assert next_offset(returned, limit, offset, total) == expected


def test_last_page_is_a_subset_but_has_no_successor():
    result = page_envelope([{"id": 4}], limit=2, offset=4, total=5)
    assert set(ENVELOPE_KEYS).issubset(result)
    assert result["offset"] == 4
    assert result["truncated"] is True
    assert result["next_offset"] is None
    assert "no next page" in result["hint"].lower()
    assert "raise limit" not in result["hint"].lower()


@pytest.mark.parametrize("total", [5, None])
def test_complete_walk_never_duplicates_or_drops_rows(total):
    rows = [{"id": n} for n in range(5)]
    found = []
    offset = 0
    seen = set()
    while offset is not None:
        assert offset not in seen
        seen.add(offset)
        result = page_envelope(rows[offset:offset + 2], limit=2, offset=offset, total=total)
        found.extend(result["items"])
        offset = result["next_offset"]
    assert found == rows


def test_unknown_full_last_page_needs_one_empty_read():
    first = page_envelope([{"id": 1}], limit=1, offset=0, total=None)
    assert first["next_offset"] == 1
    empty = page_envelope([], limit=1, offset=1, total=None)
    assert empty["total"] is None
    assert empty["next_offset"] is None


@pytest.mark.parametrize("limit,offset", [(0, 0), (True, 0), (1, -1), (1, True)])
def test_invalid_window_is_not_silently_rewritten(limit, offset):
    with pytest.raises(ValueError):
        page_envelope([], limit=limit, offset=offset, total=0)


def test_reserved_fields_cannot_be_overwritten():
    with pytest.raises(ValueError):
        page_envelope([], limit=1, offset=0, total=0, returned=999)
