# VMware-Policy

Use shared policy checks and audit evidence across the VMware Skills family.

English · [简体中文](README-CN.md)

Community-maintained · MIT · Not an official VMware/Broadcom product.

[![18-second illustrative investigation demo](https://raw.githubusercontent.com/vmware-skills/marketplace/main/assets/demos/vmware-skills-en.gif)](https://github.com/vmware-skills/marketplace/blob/main/assets/demos/vmware-skills-en.mp4)

Synthetic-data animation, not a live recording. [Watch the AI-narrated family introduction (~2 min)](https://github.com/vmware-skills/marketplace/blob/main/assets/demos/vmware-skills-en.mp4)

## Why use it?

- Apply shared policy and risk metadata to tool calls.
- Query audit records with the vmware-audit CLI.
- Sanitize external text and retain execution boundaries.

## Get started

Install the published CLI and inspect its commands:

```sh
uv tool install vmware-policy==1.25.0
vmware-audit --help
```

Requires uv and Python >=3.10. Keep configuration and audit data locally; companion modules use their own target configuration. [Setup guide](skills/vmware-policy/references/setup-guide.md).

For Claude Code and other host installation paths, see the [family portal](https://github.com/vmware-skills/marketplace).

## Know the boundaries

A shared dependency library and CLI, not a standalone MCP server. Local policy does not replace VMware RBAC or provide independent human approval.

## Go deeper

- [Capabilities](skills/vmware-policy/references/capabilities.md)
- [CLI reference](skills/vmware-policy/references/cli-reference.md)
- [Agent guardrails](skills/vmware-policy/references/agent-guardrails.md)
- [Detailed usage and architecture](skills/vmware-policy/references/detailed-guide.md)
- [Canonical skill instructions](skills/vmware-policy/SKILL.md)

Part of [VMware Skills](https://github.com/vmware-skills/marketplace): 15 skills, 14 MCP servers and one shared Policy library. If it helps your work, star the family portal.

[Issues and feedback](https://github.com/vmware-skills/VMware-Policy/issues) · [MIT](https://opensource.org/license/mit/)
