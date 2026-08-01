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
```