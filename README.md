# VMware-Policy

<a id="readme-overview"></a>

Use shared policy checks and audit evidence across the VMware Skills family.

English · [简体中文](https://github.com/vmware-skills/VMware-Policy/blob/main/README-CN.md)

Community-maintained · MIT · Not an official VMware/Broadcom product.

[![24-second illustrative investigation demo](https://raw.githubusercontent.com/vmware-skills/marketplace/main/assets/demos/vmware-skills-en.gif)](https://github.com/vmware-skills/marketplace/releases/download/demos-2026-11-13-model-fit/vmware-skills-en.mp4)

Synthetic-data GIF; video includes redacted historical screenshots. [Download the AI-narrated family introduction (~3 min)](https://github.com/vmware-skills/marketplace/releases/download/demos-2026-11-13-model-fit/vmware-skills-en.mp4)

<a id="readme-capabilities-and-workflows"></a>

## Why use it?

- Apply shared policy and risk metadata to tool calls.
- Query audit records with the vmware-audit CLI.
- Sanitize external text and retain execution boundaries.

<a id="readme-quick-start"></a>

## Get started

Install the published CLI and inspect its commands:

```sh
uv tool install vmware-policy==1.25.0
vmware-audit --help
```

Requires uv and Python >=3.10. Keep configuration and audit data locally; companion modules use their own target configuration. [Setup guide](https://github.com/vmware-skills/VMware-Policy/blob/main/skills/vmware-policy/references/setup-guide.md).

For library integration and the audit CLI, use the [setup guide](https://github.com/vmware-skills/VMware-Policy/blob/main/skills/vmware-policy/references/setup-guide.md). Policy has no standalone MCP server.

Choose a model with the [shared model-fit workflow](https://github.com/vmware-skills/marketplace/blob/main/model-fit/RUNNER.md): compare the same tasks, review quality and safety, then select the smallest tested passing configuration per task group; this is not a production guarantee.

<a id="readme-safety-and-audit"></a>

## Know the boundaries

A shared dependency library and CLI, not a standalone MCP server. Local policy does not replace VMware RBAC or provide independent human approval.

<a id="readme-mcp-configuration"></a> <a id="readme-troubleshooting"></a> <a id="readme-reference"></a>

## Go deeper

- [Capabilities](https://github.com/vmware-skills/VMware-Policy/blob/main/skills/vmware-policy/references/capabilities.md)
- [CLI reference](https://github.com/vmware-skills/VMware-Policy/blob/main/skills/vmware-policy/references/cli-reference.md)
- [Agent guardrails](https://github.com/vmware-skills/VMware-Policy/blob/main/skills/vmware-policy/references/agent-guardrails.md)
- [Detailed usage and architecture](https://github.com/vmware-skills/VMware-Policy/blob/main/skills/vmware-policy/references/detailed-guide.md)
- [Canonical skill instructions](https://github.com/vmware-skills/VMware-Policy/blob/main/skills/vmware-policy/SKILL.md)

<a id="readme-companion-skills"></a>

Part of [VMware Skills](https://github.com/vmware-skills/marketplace): 15 skills, 14 MCP servers and one shared Policy library. If it helps your work, star the family portal.

<a id="readme-license"></a>

[Issues and feedback](https://github.com/vmware-skills/VMware-Policy/issues) · [MIT](https://opensource.org/license/mit/)
