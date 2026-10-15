<!-- mcp-name: io.github.vmware-skills/vmware-policy -->

# VMware Policy

> **Author**: Wei Zhou, VMware by Broadcom — wei-wz.zhou@broadcom.com
> This is a community-driven project by a VMware engineer, not an official VMware product.
> For official VMware developer tools see [developer.broadcom.com](https://developer.broadcom.com).

Unified audit logging, policy enforcement, and sanitization for the VMware MCP skill family.

## Install

```bash
pip install vmware-policy
```

## Usage

```python
from vmware_policy import vmware_tool

@vmware_tool(risk_level="high", sensitive_params=["password"])
def delete_segment(name: str, env: str = "") -> dict:
    ...
```

## Reporting a failure the tool *returns*

Most tools signal failure by raising, and `@vmware_tool` records that. A tool that
instead catches the exception and returns an error payload looks identical to a
successful call — and for a long time was recorded as one, which also meant undo
tokens were written for changes that never happened and the circuit breaker never
saw a failure.

Dict-shaped payloads are now detected automatically. Nothing to do if a tool
returns the family shape:

```python
return {"error": msg, "hint": "Run 'vmware-nsx doctor'."}   # audited as a failure
```

A tool whose return type cannot carry that marker — one handing back console text,
say — must say so explicitly:

```python
from vmware_policy import report_tool_failure

except Exception as exc:
    report_tool_failure(str(exc))
    return f"Error: {msg}"
```

Strings are deliberately not sniffed: skills that return console output can emit
text beginning with "Error:" as *data*, and marking those calls failed would be
the same misreport in the opposite direction.

## CLI

```bash
vmware-audit log --last 20
vmware-audit log --status denied --since 2026-03-28
vmware-audit stats --days 7
vmware-audit policy          # which rules are in force
```

## Components

| Component | Description |
|-----------|-------------|
| `@vmware_tool` | Decorator around a skill's MCP tools -- policy pre-check + execute + audit row |
| `AuditEngine` | Append-only SQLite (WAL) audit log; rotates at 100 MB, keeps 5 archives |
| `PolicyEngine` | YAML rules: deny rules and maintenance window, hot-reloaded on file change. `change_limits` is reserved and not enforced. |
| `sanitize()` | Prompt-injection defense -- strips C0/C1 control and Unicode format characters, truncates (default 500 chars) |
| `vmware-audit` | Typer CLI -- query, export, statistics, rule status |

## Architecture

```
AI Agent -> vmware-pilot (optional orchestration) -> @vmware_tool pre-check -> skill operation -> audit row -> ~/.vmware/audit.db
```

vmware-policy is a **mandatory dependency** of every VMware skill. It provides:

- **Audit logging**: calls to MCP tools wrapped by `@vmware_tool` are recorded in the unified database `~/.vmware/audit.db`
- **Policy engine**: deny rules and maintenance window, hot-reloaded without a restart (change limits are a reserved field and not enforced)
- **Input sanitization**: all text from the vSphere/NSX/Aria APIs passes through `sanitize()`
- **AI agent detection**: records the caller from its environment: `claude`, `codex`, `deerflow`, `local` (an Ollama host) or `unknown`

## Policy rules

Read/write authorization belongs to the vCenter/NSX account's RBAC. The policy
engine only adds the operator's own deny rules and maintenance window, from
`~/.vmware/rules.yaml` (`$OPS_HOME/rules.yaml` if set). `vmware-audit policy`
reports which source is in force:

| Source | When | What is permitted |
|--------|------|-------------------|
| `user` | Your rules file exists and loads | Whatever your rules allow |
| `packaged-default` | No rules file | The shipped baseline, which denies nothing -- all operations are allowed by policy |
| `user-unreadable` | Your file exists but will not load (YAML error, not UTF-8) | Nothing -- every operation is denied until it loads; the baseline is never substituted |
| `baseline-unreadable` | No user file and the shipped baseline will not load | Nothing -- every operation is denied |

PyYAML is a declared dependency; if it is missing, decorated tool calls fail
rather than run. Rules hot-reload on file change.

`VMWARE_POLICY_DISABLED=1` is an operator escape hatch: in the process that has
it set (the MCP host, or a CLI shell) every policy check is skipped, including
the unreadable-rules denial. Auditing continues -- each bypassed check logs a
warning, and rows from both surfaces -- `@vmware_tool` MCP calls and `@guarded`
CLI commands -- are recorded with a `_bypassed` status suffix (`ok_bypassed`,
`error_bypassed`). Restrict who can set the MCP host's environment.

Copy the default rules to `~/.vmware/rules.yaml` and customize them:

```yaml
# Deny rules -- block specific operations
deny:
  - name: no-delete-in-prod
    operations: ["delete_*", "remove_cluster_host"]
    environments: ["production"]
    reason: "Destructive operations are not allowed in production"

# Maintenance window -- high/critical operations allowed only inside the window
maintenance_window:
  start: "22:00"
  end: "06:00"

# Change limits -- reserved field, not enforced today (the engine has no prior
# state to compute a delta from; configuring it only logs a "not enforced" warning)
change_limits:
  max_cpu_change_pct: 20
  max_memory_change_pct: 50
```

Rule changes hot-reload; no service needs a restart.

## Risk levels

The level a tool declares is recorded in the audit row, can be matched by a
deny rule's `min_risk_level`, and decides whether a configured maintenance
window applies. It does not by itself gate execution.

| Level | Examples |
|-------|----------|
| `low` | list, get, info, status |
| `medium` | reconfigure, update |
| `high` | power off, migrate, snapshot revert |
| `critical` | delete VM, delete cluster |

## VMware Skill Family

| Skill | Scope | Install |
|-------|-------|---------|
| **vmware-aiops** | VM lifecycle + deployment + guest ops | `uv tool install vmware-aiops` |
| **vmware-monitor** | Read-only monitoring | `uv tool install vmware-monitor` |
| **vmware-storage** | Storage management (iSCSI + vSAN) | `uv tool install vmware-storage` |
| **vmware-vks** | Tanzu Kubernetes | `uv tool install vmware-vks` |
| **vmware-nsx** | NSX networking | `uv tool install vmware-nsx-mgmt` |
| **vmware-nsx-security** | NSX security (DFW + security groups) | `uv tool install vmware-nsx-security` |
| **vmware-aria** | Aria Ops metrics/alerts/capacity | `uv tool install vmware-aria` |
| **vmware-avi** | AVI/ALB load balancing | `uv tool install vmware-avi` |
| **vmware-harden** | Compliance baselines + drift detection | `uv tool install vmware-harden` |
| **vmware-vdi** | Horizon VDI operations | `uv tool install vmware-vdi` |
| **vmware-privateai** | Private AI GPU / model-serving ops | `uv tool install vmware-privateai` |
| **vmware-debug** | Incident correlation / root cause | `uv tool install vmware-debug` |
| **vmware-log-insight** | Centralized log search | `uv tool install vmware-log-insight` |
| **vmware-pilot** | Multi-step workflow orchestration | `uv tool install vmware-pilot` |
| **vmware-policy** | Audit + policy (this package) | `uv tool install vmware-policy` |

## Security

- The audit database (`~/.vmware/audit.db`, local only, `0700` directory / `0600` files) records tool parameters, results, status, OS user and inferred agent -- treat it and its archives as sensitive.
- Parameters named in `sensitive_params` are stored as `***`; results from tools declaring `sensitive_result=True` are replaced; credential-named keys (`password`, `token`, `kubeconfig`, ...) in parameters and results, and credential-shaped text in error messages, are redacted on both the MCP and CLI surfaces. A credential under a key name not on that list must be declared in `sensitive_params`.
- `sanitize()` guards against prompt injection through API response text.
- Policy bypass (`VMWARE_POLICY_DISABLED=1`) skips policy checks, not auditing.

## Development

```bash
git clone https://github.com/vmware-skills/VMware-Policy.git
cd VMware-Policy
uv venv && source .venv/bin/activate
uv pip install -e ".[dev]"
pytest --cov=vmware_policy
```

## License

MIT
