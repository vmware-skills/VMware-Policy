"""Shared test fixtures for vmware_policy.

The budget tracker is a per-process singleton with an in-memory sliding window,
and the runaway breaker is on by default. Reset it (and clear budget env vars)
before every test so identical @vmware_tool calls in one test never leak into
another and false-trip the runaway guard.
"""

from __future__ import annotations

import os

import pytest

import vmware_policy.budget as budget_mod
import vmware_policy.undo as undo_mod

_BUDGET_ENV = (
    "VMWARE_MAX_TOOL_CALLS",
    "VMWARE_MAX_TOOL_SECONDS",
    "VMWARE_RUNAWAY_MAX",
    "VMWARE_RUNAWAY_WINDOW_SEC",
    "VMWARE_AUDIT_RATIONALE",
    "VMWARE_AUDIT_APPROVED_BY",
)


@pytest.fixture(autouse=True)
def _reset_budget(tmp_path):
    saved = {k: os.environ.pop(k, None) for k in _BUDGET_ENV}
    budget_mod.reset_budget()
    # Redirect the undo store to a tmp DB so tests never touch ~/.vmware/undo.db.
    undo_mod.reset_undo_store()
    undo_mod._store = undo_mod.UndoStore(tmp_path / "undo.db")
    yield
    budget_mod.reset_budget()
    undo_mod.reset_undo_store()
    for k, v in saved.items():
        if v is not None:
            os.environ[k] = v
        else:
            os.environ.pop(k, None)
