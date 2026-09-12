"""Shared test fixtures for vmware_policy.

The budget tracker is a per-process singleton with an in-memory sliding window,
and the runaway breaker is on by default. Reset it (and clear budget env vars)
before every test so identical @vmware_tool calls in one test never leak into
another and false-trip the runaway guard.
"""

from __future__ import annotations

import atexit
import os
import shutil
import tempfile
from pathlib import Path

# Session-wide sandbox, installed at import time — before vmware_policy is
# imported below — so no test can write the operator's real ~/.vmware/audit.db
# or the policy/budget/undo state beside it. OPS_HOME moves that folder; HOME
# moves anything resolved from "~". Added 2026-09-11, when VMware-VDI's suite
# was found writing real audit rows because it had no such sandbox; this suite
# had none either (scripts/lib/tests_are_sandboxed.py now requires it).
REAL_HOME = Path(os.path.expanduser("~"))
SANDBOX_HOME = Path(tempfile.mkdtemp(prefix="vmware-policy-tests-"))
os.environ["HOME"] = str(SANDBOX_HOME)
os.environ["OPS_HOME"] = str(SANDBOX_HOME / ".vmware")
os.environ["USERPROFILE"] = str(SANDBOX_HOME)
atexit.register(shutil.rmtree, SANDBOX_HOME, True)

import pytest  # noqa: E402

import vmware_policy.budget as budget_mod  # noqa: E402
import vmware_policy.undo as undo_mod  # noqa: E402

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


@pytest.fixture(autouse=True)
def _declared_environment():
    """Register a resolver labelling every target ``lab`` by default.

    The declared-environment REFUSAL was removed in v1.8.7 (read/write authz is
    the vCenter account's job now), so this no longer gates anything. It stays
    because it gives the decorator / audit / undo unit tests a registered
    resolver — env resolution returns a real label instead of ``""`` and does not
    emit the "no resolver registered" warning on every call.

    Tests specifically about environment resolution register their own resolver
    and override this (see test_guard.py).
    """
    from vmware_policy.environment import set_environment_resolver

    set_environment_resolver(lambda _target: "lab")
    yield
    set_environment_resolver(None)
