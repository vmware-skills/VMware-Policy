"""A reload is never observed half-done (HLD §16 D-13(4) [M1]).

With tools on worker threads, a check could run while a broken rules.yaml was
being loaded: rules already emptied, the load error not yet set -> "no rules,
allow everything". Reload and check now take the engine's lock.
"""

from __future__ import annotations

import threading
import time

import pytest

from vmware_policy.policy import PolicyEngine


@pytest.mark.unit
def test_a_check_waits_while_the_rules_are_being_replaced(tmp_path):
    rules = tmp_path / "rules.yaml"
    rules.write_text("deny:\n  - name: no-delete\n    operations: [delete_vm]\n", encoding="utf-8")
    engine = PolicyEngine(rules)

    results = []
    with engine._lock:
        # mid-reload state, exactly the failure path's first assignment
        engine._rules = {}
        t = threading.Thread(target=lambda: results.append(engine.check_allowed("delete_vm", env="")))
        t.start()
        time.sleep(0.2)
        assert t.is_alive(), "check ran while the rules were being replaced"
        engine._load_error = "rules.yaml is unreadable"
    t.join(2)
    assert results and results[0].allowed is False
