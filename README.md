<!-- mcp-name: io.github.zw008/vmware-policy -->

# VMware Policy

> **Author**: Wei Zhou, VMware by Broadcom — wei-wz.zhou@broadcom.com
> This is a community-driven project by a VMware engineer, not an official VMware product.
> For official VMware developer tools see [developer.broadcom.com](https://developer.broadcom.com).

Unified audit logging, policy enforcement, and sanitization for the VMware MCP skill family.

- **Read-only gate for the whole family** (v1.8.0) — this package *implements* `apply_read_only_gate()`; the skills only call it. One env var puts every installed VMware skill into read-only mode, structurally removing write tools from the MCP registry rather than asking the model nicely. See [Read-Only Mode](#read-only-mode).

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

## Read-Only Mode

This package *implements* the family's read-only gate; the skills only call it. A prompt
instruction ("never modify anything") is advisory, and a weak model can ignore it.
`apply_read_only_gate()` makes the guarantee structural: when the mode is on, every write
tool is removed from the FastMCP registry before the server serves, so `list_tools()`
never offers them. The model cannot call what it cannot see.

### For operators

One variable puts every installed VMware skill into read-only mode:

```json
{ "env": { "VMWARE_READ_ONLY": "true" } }
```

Resolution order: per-skill env (`VMWARE_AIOPS_READ_ONLY`, `VMWARE_NSX_SECURITY_READ_ONLY`,
…) → family env `VMWARE_READ_ONLY` → the skill's own `read_only:` config flag → off. Off by
default, so nothing changes until you switch it on; each server logs exactly which tools it
withheld.

**Fail-closed.** A read-only mode that silently degrades to read-write is worse than none,
because operators stop checking. Anything that cannot be *proven* aborts startup with
`ReadOnlyGateError`:

- the FastMCP tool registry cannot be enumerated (e.g. an incompatible `mcp` version);
- a removal does not take effect — a write tool survives the sweep.

A switch value that cannot be parsed (`VMWARE_READ_ONLY=ture`) does not abort: it resolves
to **on**, with a warning naming the accepted values. A typo must never leave write tools
exposed.

### How tools are classified

A tool is withheld unless it is provably read-only. Signals, in priority order:

1. `FORCE_WRITE` membership;
2. `[WRITE]` docstring prefix;
3. `readOnlyHint=False` annotation;
4. `[READ]` docstring prefix;
5. `readOnlyHint=True` annotation;
6. nothing conclusive → treated as a write tool.

The docstring marker outranks the MCP annotation because it has full coverage (244/244
family tools), while vmware-harden and vmware-debug register their tools through a
`build_server()` factory that passes no annotations at all.

`FORCE_WRITE` overrides tools whose marker under-reports their real effect. All three
current entries are the same shape — read-only against the managed infrastructure, but
writing a file to a caller-supplied local path, with credentials involved:

| Tool | Skill | Why |
|------|-------|-----|
| `vm_guest_download` | vmware-aiops | Reads from the guest OS, but writes an operator-supplied `local_path` and takes guest credentials. |
| `get_supervisor_kubeconfig` | vmware-vks | Materialises a session-token credential file at a model-supplied local path. |
| `get_tkc_kubeconfig` | vmware-vks | Same shape as above. |

Tools that write only to a skill's own local store (vmware-harden's DuckDB twin, say) stay
exposed — that store is a cache of observations, not managed infrastructure.

### For skill authors

Call the gate once, after every tool module has registered and before the server runs:

```python
from vmware_policy import apply_read_only_gate

WITHHELD_WRITE_TOOLS: list[str] = apply_read_only_gate(
    mcp, "vmware-aria", config_flag=_config_read_only()
)
```

`apply_read_only_gate(mcp, skill, config_flag=None) -> list[str]` returns the sorted names
of the tools it removed (empty when the mode is off), so the caller can log what was
withheld; it is idempotent. `skill` is the hyphenated skill name and is normalised to the
per-skill env var (`vmware-nsx-security` → `VMWARE_NSX_SECURITY_READ_ONLY`). `config_flag`
carries the skill's own `read_only:` setting and is consulted only when neither env var is
set. To test the switch without touching a registry, use
`read_only_enabled(skill, config_flag=None) -> bool`.

Read-only mode landed with two sibling harness pieces from the same report
([VMware-AIops#31](https://github.com/zw008/VMware-AIops/issues/31)): the list envelope
`paginated()` (`envelope.py`) and declared environments `set_environment_resolver()`
(`environment.py`).

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
```