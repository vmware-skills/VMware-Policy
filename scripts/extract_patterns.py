"""Extract auto-remediation pattern candidates from audit.db.

PoC for L5 automation level (Enterprise Harness Engineering framework).

Reads ~/.vmware/audit.db, finds operations that meet repeatability thresholds,
and prints YAML-shaped candidate patterns for human review.

Usage:
    python -m scripts.extract_patterns                # default thresholds
    python -m scripts.extract_patterns --days 30
    python -m scripts.extract_patterns --min-runs 10

Design doc: docs/auto-remediation-patterns.md
"""

from __future__ import annotations

import argparse
import json
import sqlite3
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

_DEFAULT_DB = Path("~/.vmware/audit.db").expanduser()
_DEFAULT_LOOKBACK_DAYS = 90
_DEFAULT_MIN_RUNS = 5
_DEFAULT_MIN_OPERATORS = 2

# Operations that are inherently UNSAFE to auto-promote regardless of stats.
# Even if these meet thresholds, they require explicit human pattern authoring.
_DENYLIST = frozenset({
    ("vmware-aiops", "vm_delete"),
    ("vmware-aiops", "cluster_delete"),
    ("vmware-aiops", "vm_force_power_off"),
    ("vmware-vks", "delete_namespace"),
    ("vmware-vks", "delete_tkc"),
    ("vmware-nsx", "delete_segment"),
    ("vmware-nsx", "delete_tier1_gateway"),
    ("vmware-nsx-security", "delete_dfw_policy"),
    ("vmware-aria", "cancel_alert"),  # irreversible per Aria API
})


@dataclass
class Thresholds:
    min_runs: int = _DEFAULT_MIN_RUNS
    min_operators: int = _DEFAULT_MIN_OPERATORS


@dataclass
class CandidatePattern:
    skill: str
    tool: str
    success_count: int = 0
    failure_count: int = 0
    operators: set[str] = field(default_factory=set)
    risk_levels: set[str] = field(default_factory=set)
    sample_params: list[dict[str, Any]] = field(default_factory=list)
    first_seen: str = ""
    last_seen: str = ""

    def is_qualified(self, t: Thresholds) -> bool:
        return (
            self.success_count >= t.min_runs
            and self.failure_count == 0
            and len(self.operators) >= t.min_operators
            and self.risk_levels.issubset({"low"})
            and (self.skill, self.tool) not in _DENYLIST
        )

    def disqualified_reason(self, t: Thresholds) -> str:
        reasons = []
        if (self.skill, self.tool) in _DENYLIST:
            reasons.append("operation is on the L5 denylist (inherently unsafe)")
        if self.success_count < t.min_runs:
            reasons.append(f"only {self.success_count} successes (need ≥ {t.min_runs})")
        if self.failure_count > 0:
            reasons.append(f"{self.failure_count} failures observed (need 0)")
        if len(self.operators) < t.min_operators:
            reasons.append(f"only {len(self.operators)} distinct operators (need ≥ {t.min_operators})")
        non_low = self.risk_levels - {"low"}
        if non_low:
            reasons.append(f"observed at non-low risk levels: {sorted(non_low)}")
        return "; ".join(reasons) if reasons else "qualified"


def scan_audit(db_path: Path, days: int) -> dict[tuple[str, str], CandidatePattern]:
    """Aggregate audit rows into per-(skill, tool) candidate patterns."""
    if not db_path.exists():
        raise FileNotFoundError(f"Audit DB not found at {db_path}")

    cutoff = (datetime.now(tz=timezone.utc) - timedelta(days=days)).isoformat()

    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row
    try:
        rows = conn.execute(
            """
            SELECT ts, skill, tool, params, status, user, risk_level
            FROM audit_log
            WHERE ts >= ?
            """,
            (cutoff,),
        ).fetchall()
    finally:
        conn.close()

    candidates: dict[tuple[str, str], CandidatePattern] = {}
    for row in rows:
        key = (row["skill"], row["tool"])
        cand = candidates.setdefault(
            key, CandidatePattern(skill=row["skill"], tool=row["tool"])
        )
        if row["status"] == "ok":
            cand.success_count += 1
        else:
            cand.failure_count += 1

        cand.operators.add(row["user"] or "unknown")
        cand.risk_levels.add(row["risk_level"] or "unknown")

        if not cand.first_seen or row["ts"] < cand.first_seen:
            cand.first_seen = row["ts"]
        if row["ts"] > cand.last_seen:
            cand.last_seen = row["ts"]

        if len(cand.sample_params) < 3:
            try:
                cand.sample_params.append(json.loads(row["params"] or "{}"))
            except json.JSONDecodeError:
                pass

    return candidates


def render_candidate_yaml(cand: CandidatePattern, days_observed: int) -> str:
    """Print a candidate as a starter YAML stub. Human authors complete it."""
    sample = json.dumps(cand.sample_params[:1], indent=2) if cand.sample_params else "{}"
    return f"""\
# CANDIDATE — review before signing
# Source: extract_patterns.py scan
schema_version: 1
pattern_id: {cand.skill}-{cand.tool.replace('_', '-')}-auto

description: >
  AUTO-GENERATED CANDIDATE — observed {cand.success_count} successful runs,
  0 failures, by {len(cand.operators)} distinct operator(s).
  YOU MUST AUTHOR a precise description before signing.

classification:
  risk: low                 # confirmed from audit risk_level
  reversible: REVIEW        # human must verify
  repeatable: true          # confirmed from audit count

trigger:
  skill: {cand.skill}
  tool: REVIEW              # human must specify the upstream trigger
                            # (this script only finds the action, not the trigger)

action:
  skill: {cand.skill}
  tool: {cand.tool}
  # Sample params seen in audit:
  # {sample}

validation:
  delay_seconds: REVIEW
  re_check: REVIEW

on_validation_failure: escalate_l4

approval:
  status: poc_unsigned
  reviewed_audit_runs: []
  thresholds_at_signing:
    success_count: {cand.success_count}
    failure_count: {cand.failure_count}
    distinct_operators: {len(cand.operators)}
    days_observed: {days_observed}
"""


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--db", type=Path, default=_DEFAULT_DB)
    ap.add_argument("--days", type=int, default=_DEFAULT_LOOKBACK_DAYS)
    ap.add_argument("--min-runs", type=int, default=_DEFAULT_MIN_RUNS,
                    help=f"Minimum success count (default {_DEFAULT_MIN_RUNS})")
    ap.add_argument("--show-disqualified", action="store_true",
                    help="Also print operations that did not meet thresholds")
    args = ap.parse_args()

    thresholds = Thresholds(min_runs=args.min_runs)

    try:
        candidates = scan_audit(args.db, args.days)
    except FileNotFoundError as e:
        print(f"ERROR: {e}")
        print(f"\nNo audit data yet. Run some VMware skill operations first, then re-scan.")
        return 1

    if not candidates:
        print(f"No audit rows in the last {args.days} days at {args.db}")
        return 0

    qualified = [c for c in candidates.values() if c.is_qualified(thresholds)]
    disqualified = [c for c in candidates.values() if not c.is_qualified(thresholds)]

    print(f"# Audit scan: {sum(c.success_count + c.failure_count for c in candidates.values())} rows")
    print(f"# Window: last {args.days} days")
    print(f"# Qualified candidates: {len(qualified)}")
    print(f"# Disqualified: {len(disqualified)}")
    print()

    if qualified:
        print("=" * 72)
        print("QUALIFIED CANDIDATES")
        print("=" * 72)
        for cand in sorted(qualified, key=lambda c: -c.success_count):
            print()
            print(render_candidate_yaml(cand, args.days))

    if args.show_disqualified and disqualified:
        print()
        print("=" * 72)
        print("DISQUALIFIED — review reasons, may need more observation")
        print("=" * 72)
        for cand in sorted(disqualified, key=lambda c: -c.success_count):
            print(f"\n# {cand.skill}.{cand.tool}: {cand.disqualified_reason(thresholds)}")
            print(f"#   {cand.success_count} successes, {cand.failure_count} failures, "
                  f"{len(cand.operators)} operators, risk={sorted(cand.risk_levels)}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
