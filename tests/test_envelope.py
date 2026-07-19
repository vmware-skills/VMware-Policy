"""The list-result envelope: make truncation visible to the model.

Source: VMware-AIops issue #31 (juanpf-ha). Running the family with a local
Llama 3.3 70B, the operator reported that "with long tool responses, it may
omit existing information or incorrectly state that no data was returned."

A bare ``list[dict]`` gives a model no way to tell a complete answer from a
page-one answer, so it guesses — and a guess that reads "no data" is worse than
a partial list, because it looks like a finding. This envelope states what was
returned, what the limit was, and whether more exists, so there is nothing left
to infer.
"""

import pytest

from vmware_policy.envelope import paginated

ROWS = [{"name": f"vm-{i:02d}"} for i in range(50)]


# ---------------------------------------------------------------------------
# Shape
# ---------------------------------------------------------------------------


def test_items_are_preserved_in_order():
    result = paginated(ROWS, limit=100)
    assert result["items"] == ROWS


def test_every_key_is_always_present():
    """Explicit nulls, never missing keys — a missing key invites invention."""
    result = paginated([], limit=None)
    for key in ("items", "returned", "limit", "total", "truncated", "hint"):
        assert key in result


def test_returned_counts_the_items():
    assert paginated(ROWS, limit=100)["returned"] == 50


def test_empty_result_is_not_truncated():
    result = paginated([], limit=50)
    assert result["returned"] == 0
    assert result["truncated"] is False


def test_unknown_total_is_explicit_null():
    assert paginated(ROWS, limit=100)["total"] is None


# ---------------------------------------------------------------------------
# Truncation detection
# ---------------------------------------------------------------------------


def test_short_page_is_not_truncated():
    assert paginated(ROWS[:10], limit=50)["truncated"] is False


def test_full_page_with_unknown_total_is_flagged_truncated():
    """Conservative: a page filled to the limit may have more behind it."""
    assert paginated(ROWS, limit=50)["truncated"] is True


def test_known_total_larger_than_page_is_truncated():
    assert paginated(ROWS, limit=50, total=213)["truncated"] is True


def test_known_total_equal_to_page_is_not_truncated():
    """A known total that matches removes the ambiguity a full page creates."""
    result = paginated(ROWS, limit=50, total=50)
    assert result["truncated"] is False


def test_no_limit_means_no_truncation():
    assert paginated(ROWS, limit=None)["truncated"] is False


# ---------------------------------------------------------------------------
# The hint — must be accurate about what is and is not known
# ---------------------------------------------------------------------------


def test_no_hint_when_complete():
    assert paginated(ROWS[:10], limit=50)["hint"] is None


def test_hint_states_exact_numbers_when_total_known():
    hint = paginated(ROWS, limit=50, total=213)["hint"]
    assert "50" in hint and "213" in hint


def test_hint_admits_uncertainty_when_total_unknown():
    """Do not claim a total we never fetched."""
    hint = paginated(ROWS, limit=50)["hint"]
    assert "213" not in hint
    assert "may be more" in hint.lower()


def test_hint_tells_the_agent_what_to_do():
    hint = paginated(ROWS, limit=50)["hint"]
    assert "limit" in hint.lower()
    assert "filter" in hint.lower()


# ---------------------------------------------------------------------------
# Extra fields and immutability
# ---------------------------------------------------------------------------


def test_extra_fields_are_merged():
    result = paginated(ROWS[:1], limit=50, target="vcenter-prod")
    assert result["target"] == "vcenter-prod"


def test_extra_fields_cannot_shadow_the_contract():
    with pytest.raises(ValueError):
        paginated(ROWS, limit=50, truncated=False)


def test_source_list_is_not_mutated():
    rows = [{"name": "a"}]
    paginated(rows, limit=50)
    assert rows == [{"name": "a"}]


def test_negative_or_zero_limit_is_treated_as_unlimited():
    assert paginated(ROWS, limit=0)["truncated"] is False
