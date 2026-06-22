## v1.6.0 (unreleased) — trust architecture (token budget, accountability, risk tiers, undo)

Substantial, backward-compatible harness upgrades from the 2026-06-22 strategy review
(BACKLOG.md P0, direction A). All additive — existing skills keep working unchanged
until they opt into the new features. **Affects the whole family on next install.**

### Added
- **Token/call hard budget + runaway breaker** (`budget.py`). Per-process ceilings via
  `VMWARE_MAX_TOOL_CALLS` / `VMWARE_MAX_TOOL_SECONDS` (opt-in), plus an on-by-default
  guard that trips when the same `(tool, params)` is hammered in a short window
  (`VMWARE_RUNAWAY_MAX`=25 / `VMWARE_RUNAWAY_WINDOW_SEC`=120). Raises `BudgetExceeded`
  (a hard stop) — the structural fix for the "delete one snapshot, burn 26k tokens"
  unbounded-call failure mode. Enforced from `@vmware_tool`.
- **Audit accountability fields** (`audit.py`): `rationale`, `approved_by`, `risk_tier`
  columns, with in-place ALTER migration for existing audit.db files. The decorator
  sources rationale/approver from `VMWARE_AUDIT_RATIONALE` / `VMWARE_AUDIT_APPROVED_BY`.
- **Graduated-autonomy risk tiers** (`policy.py` `required_approval_tier`): rules.yaml
  `risk_tiers` map environment / resource tag / min-risk → tier (none/confirm/dual/review);
  dual/review tiers are denied without a recorded approver.
- **Undo-token primitive** (`undo.py`): `@vmware_tool(undo=...)` records a write's inverse
  descriptor to `~/.vmware/undo.db` and tags the result with `_undo_id`. CLI
  `vmware-audit undo-list` / `undo-show`. Recording only — execution stays in vmware-pilot.
- **Relocatable state dir** (`paths.py` `ops_home()`): `OPS_HOME` relocates harness state
  (default `~/.vmware`, fully back-compat); budget env vars accept an `OPS_*` alias.

### Notes
- `_bind_params` now applies declared defaults so env scoping + risk-tier matching see the
  effective target/tags even when a caller relied on a default value.
- 120 tests pass; bandit 0 Medium+. Version/publish coordination with the family is a
  release-time decision (candidate: family-wide v1.6.0).

## v1.5.37 (2026-06-12) — backlog: stop advertising an unimplemented feature

### Changed
- "limits" removed from the `@vmware_tool` feature list / docs — `change_limits` was a documented no-op;
  it's now clearly marked reserved/not-enforced (still logs a warning) rather than implying enforcement. (#2)

## v1.5.36 (2026-06-12) — shared-decorator correctness (affects the whole family)

### Fixed
- **`@vmware_tool` now supports async tools** — an `async def` tool was previously audited as "ok"
  with an un-awaited coroutine as its result.
- **Positional arguments are now audited and policy-scoped** — only `kwargs` were captured before, so
  a positionally-passed `target` vanished from the audit log and bypassed environment deny-rules.
- **Malformed maintenance window now fails closed** (deny + teaching error) instead of allowing
  high-risk operations 24/7.
- **Audit-log rotation checkpoints the WAL before renaming** — un-checkpointed frames could be lost.
- **Pattern matcher prefers an armable match** instead of letting an expired/unsigned pattern shadow it.
- `timeout_seconds` now logs a warning when exceeded (documented as advisory); `sanitize()` strips
  control characters before truncating and returns "" for None.

### Added
- `reset_engine()` / `reset_policy_engine()`, lock-guarded singletons, and a path-mismatch warning.

## v1.5.35 (2026-06-10) — security hardening: stop leaking credentials in logs & audit (affects all skills)

Shared dependency — these fixes protect every skill in the family.

### Fixed
- **Bypass-mode logging** no longer prints parameter *values* (which could carry
  passwords/tokens). When `VMWARE_POLICY_DISABLED=1`, only parameter *names* are logged.
- **Policy check** now receives the already-redacted `safe_params`, not the raw `kwargs`.
- **`_redact()`** recurses into lists/tuples, so secrets nested in collections
  (e.g. `{"targets": [{"password": "..."}]}`) are masked in audit records.
- **Exception text and tracebacks** are sanitized and secret-pattern–redacted
  (`password=…`, `token: …`) before being written to the audit DB.
- **Audit storage** directory is created 0700 and the DB (incl. WAL/SHM) 0600.

This release aligns the whole family back to a single version (1.5.35); vmware-policy and vmware-pilot return to the shared number after sitting at 1.5.22.

## v1.5.22 (2026-05-08)

**Family alignment** — no source changes in this skill.

- **align:** Tracks v1.5.22 family bump driven by Smithery onboarding for vmware-avi / vmware-harden / vmware-pilot.

## v1.5.21 (2026-05-08)

**Family alignment** — no source changes in this library. Skipped v1.5.20 family bump; this is the catch-up release.

- **chore:** Untracked `.venv/` from the repository (was committed by mistake; `.gitignore` already excludes it). Removed 1832 files from version control with no functional change.
- **align:** Tracks family v1.5.20 + v1.5.21 alignment.

## v1.5.19 (2026-05-06)

**Security + concurrency fixes** in pattern engine.

- **fix(patterns):** Approval gate now requires BOTH `signed_by` AND `approval.status == "approved"`. The previous AND-style condition (`if not signed_by AND status != "approved"`) let signed-but-rejected patterns retain their original risk classification, which was the opposite of intended behavior (yjs review 2026-05-06; CLAUDE.md 踩坑 #30).
- **fix(patterns):** `get_pattern_engine` singleton initialization now uses `threading.Lock` with double-checked locking to prevent multiple PatternEngine instances under concurrent first-access in multi-threaded callers.
- **smoke:** Family `scripts/family_smoke.sh` now recursively walks every Typer subcommand to trigger lazy imports.
- **align:** Family version bump to v1.5.19.

## v1.5.18 (2026-05-02)

**Bug fix from external code review (2026-05-02 by Hermes Agent / MiniMax-M2.7)**

- **fix:** `patterns.py` — pattern YAML now accepts the canonical rate-limit keys `max_per_hour` / `max_per_day` alongside the legacy `max_per_hour_per_host` / `max_per_day_per_cluster`. The dataclass field is `rate_max_per_hour_per_target` (target-agnostic), and the new keys remove the host/cluster naming mismatch flagged in review. Old keys still work — zero breakage for existing pattern files.
- **dev:** `[dependency-groups]` block aligned with the rest of the family — `pytest`, `pytest-cov`, `ruff` all available via `uv sync --group dev`.
- **align:** Family version bump to v1.5.18.

Tests: 16/16 pattern engine pass.

## v1.5.17 (2026-05-01)

**L5 auto-remediation pattern matcher integrated into `@vmware_tool`** — the v1.5.16 PoC scaffolding (design doc + extractor) now has a runtime engine.

- **feat:** New module `vmware_policy/patterns.py` — `PatternEngine` singleton. Loads signed YAML patterns from `~/.vmware/auto-remediation-patterns/*.yaml` with hot-reload on mtime. Validates schema, action signatures, and approval state.
- **feat:** `@vmware_tool` decorator integration — matched + armed calls have `_pattern_id` and `_pattern_armed` annotated on the result dict and the audit row. Outcome reporting in the `finally` block updates circuit-breaker state.
- **feat:** Per-`(pattern_id, target)` rate limiting — sliding hourly + daily windows. Per-target circuit breaker — configurable threshold (default 3 consecutive failures) and cooldown (default 24h).
- **safety:** Patterns must be signed (`approval.signed_by` non-empty + `status=approved`) AND classified `risk: low + reversible: true + repeatable: true` to be armable. Unsigned and high-risk patterns load for inspection but never arm. Failure modes are fail-open: load/match errors never block tool calls.
- **docs:** `docs/auto-remediation-patterns.md` now reflects the shipped surface and the deferred items (trigger-against-historical-audit, auto-execution daemon, post-action validation, persistent state across restarts).
- **align:** Family version bump to v1.5.17.

Tests: 34 → 52 passing (16 pattern engine + 2 decorator integration).

## v1.5.16 (2026-04-30)

**Enterprise Harness Engineering alignment** — adapted from the Linkloud × addxai framework articles ([part 1](https://mp.weixin.qq.com/s/hz4W7ILHJ1yz_pG0Z1xP-A), [part 2](https://mp.weixin.qq.com/s/F3qYbyB3S8oIqx-Y4BrWNQ)).

- **feat (PoC):** New `docs/auto-remediation-patterns.md` design doc — schema, lifecycle, and three hard conditions (risk:low + reversible + repeatable) for the L5 automation level from the EHE framework.
- **feat (PoC):** New `scripts/extract_patterns.py` — scans `~/.vmware/audit.db` for candidate L5 patterns, applies thresholds (≥5 successes, 0 failures, ≥2 distinct operators, low-risk only, denylist), prints YAML stubs for human authoring.
- **align:** Family version bump 1.5.14 → 1.5.16 (skipping 1.5.15 to align with the rest of the family).

## v1.5.14 (2026-04-21)

**Bug fixes from code review by @yjs-2026 (follow-up)**

- **fix:** `audit.py` — `query()` and `stats()` SQLite connections now wrapped in try/finally to prevent leaks on exception
- **fix:** `audit.py` — archive filename now uses `datetime.now(tz=timezone.utc)` consistent with audit record timestamps

## v1.5.13 (2026-04-21)

**Bug fixes from code review 2026-04-20**

- **fix(P0):** `audit.py` — `stats(days=N)` now correctly computes date range using `timedelta(days=days)` instead of ignoring the `days` parameter entirely
- **fix:** `policy.py` — `_check_limits()` now logs a warning when `change_limits` are configured but not enforced, instead of silently doing nothing
- **fix:** `policy.py` — `_in_maintenance_window()` now uses `datetime.now(tz=timezone.utc)` instead of naive `datetime.now()` for correct timezone handling
- **fix(security):** `decorators.py` — `_redact()` now recurses into nested dicts to redact sensitive values at any depth

# VMware Policy — Release Notes

## v1.5.12 (2026-04-17)

**Security & bug fixes from code review by @yjs-2026**

- **fix(security):** `_rule_matches` empty `operations: []` bypass — deny rules with empty operations list matched ALL operations instead of none, causing whitelist leak
- **fix(security):** `sanitize()` now strips Unicode Format characters (Cf category: zero-width spaces, bidi overrides) — closes prompt injection vector
- **fix:** `_maybe_reload` clears stale rules and logs warning when policy file is deleted, instead of silently using outdated rules
- **fix:** `_maybe_reload` logs exceptions instead of silently swallowing them (`except Exception: pass`)
- **fix:** `VMWARE_POLICY_DISABLED=1` bypass now logs full operation context (operation, env, risk_level, params) for audit trail

## v1.5.11 (2026-04-17)

- Align with VMware skill family v1.5.11 (AVI 22.x fixes from @timwangbc)

## v1.5.10 (2026-04-16)

- Align with VMware skill family v1.5.10

## v1.5.8 (2026-04-15)

- Align with VMware skill family v1.5.8 (NSX/AVI/Aria/AIops bug fixes)

## v1.5.7 (2026-04-15)

- Align with VMware skill family v1.5.7 (Pilot `__from_step_N__` fix + VKS SSL/timeout fix)

## v1.5.6 (2026-04-15)

- Align with VMware skill family v1.5.6

## v1.5.5 (2026-04-15)

- Align with VMware skill family v1.5.5

## v1.5.4 (2026-04-14)

- Security: bump pytest 9.0.2→9.0.3 (CVE-2025-71176, insecure tmpdir handling)
- Align version with VMware skill family v1.5.4

## v1.5.0 (2026-04-12)

### Anthropic Best Practices Integration

- **[READ]/[WRITE] tool prefixes**: All MCP tool descriptions now start with [READ] or [WRITE] to clearly indicate operation type
- **Read/write split counts**: SKILL.md MCP Tools section header shows exact read vs write tool counts
- **Negative routing**: Description frontmatter includes "Do NOT use when..." clause to prevent misrouting
- **Broadcom author attestation**: README.md, README-CN.md, and pyproject.toml include VMware by Broadcom author identity (wei-wz.zhou@broadcom.com) to resolve Snyk E005 brand warnings

### Policy-specific

- **Security fix**: Removed unused VMWARE_POLICY_CONFIG from metadata
- **Agent detection transparency**: Added documentation explaining which env vars are inspected for audit logging and why

## v1.4.5 — 2026-04-03

- **Security**: bump pygments 2.19.2 → 2.20.0 (fix ReDoS CVE in GUID matching regex)
- **Infrastructure**: add uv.lock for reproducible builds and Dependabot security tracking

## v1.4.0 — 2026-03-29

Initial release. Unified audit, policy enforcement, and sanitization for the VMware MCP skill family.

- `@vmware_tool` decorator: mandatory wrapper for all 162 MCP tools across 8 skills
- `AuditEngine`: SQLite WAL at ~/.vmware/audit.db, framework-agnostic (Claude/Codex/local)
- `PolicyEngine`: rules.yaml with hot-reload, deny rules, maintenance windows, risk-level gating
- `sanitize()`: consolidated from 22 duplicate implementations across 7 skills
- `vmware-audit` CLI: log/export/stats commands for querying audit trail
- Agent detection: auto-identify calling AI agent from environment variables
- Log rotation: 100MB threshold, keep 5 archives
- 34 unit tests, 70%+ coverage