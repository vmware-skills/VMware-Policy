# VMware Policy -- Setup Guide

## Installation

### As a Dependency (Standard)

vmware-policy is automatically installed when you install any VMware skill:

```bash
uv tool install vmware-aiops       # installs vmware-policy as dependency
uv tool install vmware-monitor     # same
uv tool install vmware-nsx-mgmt   # same
```

### Standalone (For Audit Querying)

```bash
uv tool install vmware-policy
vmware-audit stats   # verify
```

### Development

```bash
git clone https://github.com/zw008/VMware-Policy.git
cd VMware-Policy
uv venv && source .venv/bin/activate
uv pip install -e ".[dev]"
pytest --cov=vmware_policy
```

## Configuration

### Audit Database

The audit database is created automatically at `~/.vmware/audit.db` on first use. No configuration needed.

```bash
# Verify the directory exists and is writable
mkdir -p ~/.vmware
chmod 700 ~/.vmware
```

### Policy Rules (Optional)

Policy rules are optional. Without `~/.vmware/rules.yaml`, all operations are allowed (audit logging still active).

```bash
# Copy the default rules template
cp $(python -c "import vmware_policy; import os; print(os.path.join(os.path.dirname(vmware_policy.__file__), 'rules_default.yaml'))") ~/.vmware/rules.yaml

# Edit rules as needed
vi ~/.vmware/rules.yaml
```

### Environment Variables

| Variable | Required | Description |
|----------|:--------:|-------------|
| `VMWARE_POLICY_DISABLED` | No | Set to `1` to bypass policy checks (still logged) |
| `VMWARE_READ_ONLY` | No | Set to `true` to put **every** installed VMware skill into read-only mode |
| `VMWARE_<SKILL>_READ_ONLY` | No | Per-skill override, wins over the family variable (e.g. `VMWARE_NSX_SECURITY_READ_ONLY`) |

### Read-Only Mode (Operators)

Off by default. When on, each skill's MCP server removes every write tool from its registry
before serving, so `list_tools()` never offers them -- structural, not a prompt instruction
the model may ignore. Resolution order, highest first:

| Priority | Signal | Scope |
|---|---|---|
| 1 | `VMWARE_<SKILL>_READ_ONLY` | One skill |
| 2 | `VMWARE_READ_ONLY` | Every installed VMware skill |
| 3 | `read_only: true` in that skill's `config.yaml` | One skill (skills that have a config file) |
| 4 | (nothing set) | Off |

The env vars come first so a deployment can be locked down from the MCP client's `env`
block without editing any config file. The combination `{"VMWARE_READ_ONLY": "true",
"VMWARE_<SKILL>_READ_ONLY": "false"}` locks the estate while leaving one skill writable --
the documented use is keeping vmware-pilot able to orchestrate while every downstream skill
enforces the lock on its own tools.

**Fail-closed.** Two conditions abort a server's start-up with `ReadOnlyGateError`: the
FastMCP tool registry cannot be enumerated (usually an incompatible `mcp` version), or a
removal did not take effect and a write tool survived. An unparseable value
(`VMWARE_READ_ONLY=ture`) does *not* abort -- it resolves to **on** with a warning naming
the accepted values, so a typo locks the deployment down rather than leaving it open.

**Verifying.** Each server logs a warning naming every tool it withheld at start-up. Skills
that ship a `doctor` (e.g. `vmware-log-insight doctor`) report the resolved state and its
source via `read_only_status()` -- the same resolver the gate uses, so the two cannot
disagree.

## Integration Into a New Skill

### 1. Add Dependency

In your skill's `pyproject.toml`:

```toml
dependencies = [
    "vmware-policy>=1.4.0",
    ...
]
```

### 2. Decorate All MCP Tools

```python
from vmware_policy import vmware_tool

@vmware_tool(risk_level="high", sensitive_params=["password"])
def my_tool(name: str, password: str) -> dict:
    ...
```

### 3. Sanitize API Responses

```python
from vmware_policy import sanitize

def list_items(api_client) -> list[dict]:
    raw = api_client.get_items()
    return [
        {"name": sanitize(item["name"]), "status": sanitize(item["status"])}
        for item in raw
    ]
```

### 4. Enforce Registration at Startup

```python
# In your MCP server startup
for tool in registered_tools:
    assert getattr(tool, "_is_vmware_tool", False), \
        f"{tool.__name__} not decorated with @vmware_tool"
```

### 5. Apply the Read-Only Gate

Call it once, after every tool module has registered and before the server runs:

```python
from vmware_policy import apply_read_only_gate

WITHHELD_WRITE_TOOLS: list[str] = apply_read_only_gate(
    mcp, "vmware-myskill", config_flag=_config_read_only()
)
```

Pass `config_flag=None` if the skill has no config file -- the env vars then become the
only switch. Keep the module-level name so the server can log what was withheld. The gate
classifies by the `[READ]`/`[WRITE]` docstring marker your tool descriptions already carry,
so a new write tool is withheld correctly with no extra registration.

### 6. Report the State in `doctor`

If the skill ships a `doctor`, add a check that calls `read_only_status()` rather than
re-walking the precedence chain -- ten hand-rolled copies is ten chances to drift from the
gate, and a doctor that disagrees with the gate is worse than no doctor. It must never
fail: read-only being on is a posture, not a fault.

```python
from vmware_policy.readonly import read_only_status

def _check_read_only() -> tuple[bool, str]:
    status = read_only_status("vmware-myskill", _config_read_only())
    if not status.recognised:
        return True, f"{status.source}={status.raw!r} unrecognised -> resolves to ON"
    if status.enabled:
        return True, f"ON (from {status.source}) -- write tools are withheld"
    return True, f"off (from {status.source}) -- write tools are exposed"
```

Pass the **same** `config_flag` the MCP server passes `apply_read_only_gate`, or the two
will report different states for the same deployment.

## Security

### Audit Database Security

- Location: `~/.vmware/audit.db` (user home directory)
- Permissions: inherited from `~/.vmware/` directory (recommend `chmod 700`)
- No network exposure -- SQLite is local-only
- WAL mode for concurrent write safety

### Rules File Security

- Location: `~/.vmware/rules.yaml`
- Contains only rule definitions, no credentials
- Readable by the user running the skill processes

### Sensitive Parameter Redaction

Parameters listed in `sensitive_params` are replaced with `***` in audit logs:

```python
# In audit.db, params column shows:
# {"name": "my-vm", "password": "***"}
```

### Data Sanitization

All API response text passes through `sanitize()`:
- Truncation: default 500 characters (configurable per call)
- Control character stripping: C0/C1 characters removed
- Prevents prompt injection via crafted VM names or descriptions

## AI Platform Compatibility

vmware-policy is framework-agnostic. It works with any MCP client:

| Platform | Status | Agent Detection |
|----------|:------:|-----------------|
| Claude Code | Supported | `CLAUDE_SESSION_ID` / `CLAUDE_CODE` |
| OpenAI Codex | Supported | `OPENAI_API_KEY` / `CODEX_SESSION` |
| Ollama (local) | Supported | `OLLAMA_HOST` |
| DeerFlow | Supported | `DEERFLOW_SESSION` |
| Any MCP client | Supported | Logged as "unknown" agent |

## MCP Server Configuration

vmware-policy does not run as an MCP server itself. It is a Python library consumed by other VMware skill MCP servers. The `vmware-audit` CLI is the user-facing interface.

```json
{
  "mcpServers": {
    "vmware-policy": {
      "command": "uvx",
      "args": ["--from", "vmware-policy", "vmware-audit"],
      "env": {}
    }
  }
}
```

> Note: This configuration exposes the `vmware-audit` CLI, not an MCP server. For MCP tool access, use the individual skill servers (vmware-aiops, vmware-nsx, etc.) which include vmware-policy as a dependency.

## Troubleshooting

### Import Error: "No module named vmware_policy"

Ensure vmware-policy is installed in the same environment as your skill:

```bash
uv pip install vmware-policy
```

### "Permission denied" on audit.db

```bash
chmod 700 ~/.vmware
chmod 600 ~/.vmware/audit.db
```

### Rules file changes not taking effect

The PolicyEngine checks file mtime on each call. Verify:

```bash
ls -la ~/.vmware/rules.yaml   # check mtime updated
python -c "import yaml; print(yaml.safe_load(open('$HOME/.vmware/rules.yaml')))"  # validate YAML
```

### PyYAML not installed

Policy rules require PyYAML. If not present, the PolicyEngine silently allows all operations (audit logging still works):

```bash
uv pip install pyyaml
```
