# VMware Policy — Release Notes

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
