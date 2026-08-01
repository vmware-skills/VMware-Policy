# Auto-Remediation Patterns — Design

> **Status**: Wired into the `@vmware_tool` decorator as of v1.5.17 (in development). Pattern matching, rate limiting, and circuit-breaker are live. Auto-execution and trigger-against-historical-audit-events are still future work — see "What we are NOT shipping yet" below. Implementation: [`vmware_policy/patterns.py`](../vmware_policy/patterns.py). Candidate scanner: [`scripts/extract_patterns.py`](../scripts/extract_patterns.py). First reference pattern: [VMware-Storage/patterns/iscsi-target-stale-rescan.yaml](https://github.com/vmware-skills/VMware-Storage/blob/main/patterns/iscsi-target-stale-rescan.yaml).

## Goal

Codify the **L5 automation level** from the Enterprise Harness Engineering framework: an operation that has been performed by humans repeatedly, with consistent inputs and consistent positive outcomes, can be promoted to a **pattern** that the agent applies automatically without per-invocation human approval.

This closes the loop between L3 (every write is human-approved) and a hands-off "the system fixes itself."

## Three Hard Conditions

A candidate operation may be promoted to a pattern only if **all three** hold:

| Condition | Definition | How to check from `audit.db` |
|---|---|---|
| `risk: low` | The operation cannot cause data loss or service interruption beyond the issue it is fixing | `risk_level = 'low'` in audit row, or operation explicitly tagged in skill code |
| `reversible: true` | The operation has a documented inverse, OR the change is itself a no-op when re-applied | Skill provides a rollback tool, or the operation is idempotent |
| `repeatable: true` | The same operation has been performed ≥ N times in the last 90 days against the same resource class with the same outcome | Aggregate over `audit_log` filtered on `(skill, tool)` |

**Default thresholds for repeatable**:
- N = 5 successful runs
- 0 failures or rollbacks within 90 days
- All runs from at least 2 distinct human operators (not a single person's habit)

## Pattern Lifecycle

```
   [observe in audit.db]
            │
            ▼
   ┌──────────────────────┐
   │ extract_patterns.py  │  ← cron / on-demand
   │ scans last 90 days   │
   └──────────┬───────────┘
              │ produces candidate YAML
              ▼
   ┌──────────────────────┐
   │ Human review + sign  │  ← approval channel: GitHub PR, feishu, email
   │ (signed YAML)        │
   └──────────┬───────────┘
              │ merge → ~/.vmware/auto-remediation-patterns/
              ▼
   ┌──────────────────────┐
   │ @vmware_tool sees    │
   │ pattern match → skip │
   │ double-confirm,      │
   │ inject pattern_id    │
   │ into audit row       │
   └──────────┬───────────┘
              │
              ▼
   ┌──────────────────────┐
   │ Validation: post-op  │
   │ check expected state │
   │ failed → rollback    │
   │        → escalate L4 │
   └──────────────────────┘
```

## Pattern Schema (YAML)

```yaml
# pattern: iscsi-target-stale-rescan
# Schema version 1
schema_version: 1
pattern_id: iscsi-target-stale-rescan
description: >
  When an iSCSI target on a host shows stale device status,
  rescan the HBAs to refresh the device list. Idempotent and reversible.

# Hard conditions — verified by extractor + signed by human
classification:
  risk: low
  reversible: true
  repeatable: true

# What audit-row pattern triggers this remediation
trigger:
  skill: vmware-storage
  tool: storage_iscsi_status
  result_predicate:
    # Result JSON must satisfy this jsonpath/jq-like predicate
    # PoC uses simple key=value matching
    has_stale_devices: true

# What operation to perform when trigger matches
action:
  skill: vmware-storage
  tool: storage_rescan
  # Parameters interpolated from the triggering audit row
  params_from_trigger:
    host: "$.params.host"
    target: "$.params.target"

# How to verify success after action
validation:
  delay_seconds: 30
  re_check:
    skill: vmware-storage
    tool: storage_iscsi_status
    expect:
      has_stale_devices: false

# What to do if validation fails
on_validation_failure: escalate_l4   # or: rollback, retry_once

# Approval signature
approval:
  signed_by: <PR reviewer email>
  signed_at: <ISO timestamp>
  reviewed_audit_runs: [<audit_id_1>, <audit_id_2>, ...]
  thresholds_at_signing:
    success_count: 7
    failure_count: 0
    distinct_operators: 3
```

## Why iSCSI rescan is the right first PoC

1. **Risk**: rescanning HBAs is observably idempotent. Worst case is a few seconds of extra IO load on the target.
2. **Reversibility**: there is no destructive change to undo — the operation only re-reads device state.
3. **Repeatability**: in our reference deployments, this operation has historically been the most-repeated manual fix. Audit data should show clear repetition.
4. **Validation**: the success criterion is observable — `storage_iscsi_status` after rescan shows healthy devices.
5. **Tight blast radius**: the operation only affects a single ESXi host. No cluster-wide cascades.

## What ships in v1.5.17

- [x] Pattern matcher wired into `@vmware_tool` (`vmware_policy/patterns.py`)
- [x] Signed-YAML loading from `~/.vmware/auto-remediation-patterns/`, hot-reload on mtime
- [x] Per-pattern rate limiting (hourly + daily, per-target)
- [x] Circuit breaker (configurable threshold + cooldown, default 3 / 24h)
- [x] Audit row annotation: matched calls carry `_pattern_id` and `_pattern_armed` in result
- [x] Test suite: 16 unit tests in `tests/test_patterns.py` + 2 decorator integration tests

## What we are NOT shipping yet

These are deferred to a follow-up release:

- [ ] **Trigger matching against historical audit events** — currently the matcher only checks the `action` block; the `trigger` block is loaded but not consulted. Production use requires "given a recent audit row matching `trigger`, the next call to the `action` tool is auto-armed."
- [ ] **Auto-execution daemon** — today the matcher just *flags* a call as armed; an external worker that observes triggers and proactively runs actions is out of scope.
- [ ] **Validation post-step** — the YAML's `validation` block is ignored. The decorator only knows whether the action call returned ok or raised. Real validation requires a follow-up tool call after a delay.
- [ ] **Persistent state across restarts** — rate-limit and circuit-breaker counters live in process memory. A restart resets them.
- [ ] **Approval channel** — the YAML must already be signed by a human (PR-merged + `signed_by` filled). There is no in-band approval flow.
- [ ] **Telemetry export** — audit.db captures pattern_id, but no rollup or dashboard yet.

## Relationship to existing rules engine

`vmware-policy/rules_default.yaml` defines **deny** rules — what NOT to do. Auto-remediation patterns define **do automatically** rules — what TO do without prompting. They are complementary:

- A `deny` rule with `min_risk_level: critical` blocks an action even if a pattern matches.
- A pattern match grants permission to skip double-confirm but does not override deny rules.
- Both are evaluated by the `@vmware_tool` decorator at the same gate.

## Open questions for review

1. **Where does the matcher live?** Inside `@vmware_tool` (every call checks for matching patterns) is simplest but adds latency. Alternative: a separate `auto_remediate` subagent invoked only when an L4 workflow detects a known trigger.
2. **How fine-grained are pattern signatures?** Per-tool? Per-(tool, target)? Per-(tool, target, params)? Trade-off: specificity vs match rate.
3. **Should patterns expire?** A pattern signed 2 years ago may no longer be safe — the underlying API behavior may have changed. Proposal: 6-month re-signature requirement.
4. **Multi-vendor / multi-target consistency** — does a pattern signed against vCenter 7.x still apply to vCenter 8.x? Pattern needs `applies_to_versions` field.
