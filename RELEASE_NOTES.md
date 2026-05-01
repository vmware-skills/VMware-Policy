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