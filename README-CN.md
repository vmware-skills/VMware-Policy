# VMware-Policy

<a id="readme-overview"></a>

在 VMware Skills 家族中共享策略检查与审计证据。

[English](https://github.com/vmware-skills/VMware-Policy/blob/main/README.md) · 简体中文

社区维护 · MIT 开源 · 非 VMware/Broadcom 官方产品。

[![24 秒调查示意演示](https://raw.githubusercontent.com/vmware-skills/marketplace/main/assets/demos/vmware-skills-zh.gif)](https://github.com/vmware-skills/marketplace/releases/download/demos-2026-11-13-operations/vmware-skills-zh.mp4)

GIF 使用合成数据；视频包含脱敏的历史截图。[下载家族 AI 配音介绍（约 3 分钟）](https://github.com/vmware-skills/marketplace/releases/download/demos-2026-11-13-operations/vmware-skills-zh.mp4)

<a id="readme-capabilities-and-workflows"></a>

## 能解决什么问题？

- 为工具调用应用共享策略与风险元数据。
- 通过 vmware-audit CLI 查询审计记录。
- 清洗外部文本，保留执行边界。

<a id="readme-quick-start"></a>

## 快速开始

安装已发布 CLI，并查看可用命令：

```sh
uv tool install vmware-policy==1.25.0
vmware-audit --help
```

需要 uv 与 Python >=3.10。配置与审计数据保存在本机，其他模块按各自目标配置连接。[配置指南](https://github.com/vmware-skills/VMware-Policy/blob/main/skills/vmware-policy/references/setup-guide.md)。

共享库集成与审计 CLI 安装见[配置指南](https://github.com/vmware-skills/VMware-Policy/blob/main/skills/vmware-policy/references/setup-guide.md)；Policy 没有独立 MCP server。

选模型可用[共享模型自测流程](https://github.com/vmware-skills/marketplace/blob/main/model-fit/RUNNER-CN.md)：统一任务、复核质量与安全，再按任务组选择最小已测通过配置；不代表生产质量保证。

<a id="readme-safety-and-audit"></a>

## 使用边界

共享依赖库与 CLI，并非独立 MCP server。本地策略不替代 VMware RBAC，也不提供独立人工审批。

<a id="readme-mcp-configuration"></a> <a id="readme-troubleshooting"></a> <a id="readme-reference"></a>

## 详细文档

- [能力范围](https://github.com/vmware-skills/VMware-Policy/blob/main/skills/vmware-policy/references/capabilities.md)
- [CLI 用法](https://github.com/vmware-skills/VMware-Policy/blob/main/skills/vmware-policy/references/cli-reference.md)
- [Agent 使用约束](https://github.com/vmware-skills/VMware-Policy/blob/main/skills/vmware-policy/references/agent-guardrails.md)
- [详细用法与架构](https://github.com/vmware-skills/VMware-Policy/blob/main/skills/vmware-policy/references/detailed-guide-CN.md)
- [唯一技能指令正本](https://github.com/vmware-skills/VMware-Policy/blob/main/skills/vmware-policy/SKILL.md)

<a id="readme-companion-skills"></a>

属于 [VMware Skills 家族](https://github.com/vmware-skills/marketplace/blob/main/README-CN.md)：15 个 skill、14 个 MCP server 与一个共享 Policy 库。如果对你有用，欢迎 Star 家族门户。

<a id="readme-license"></a>

[问题与反馈](https://github.com/vmware-skills/VMware-Policy/issues) · [MIT](https://opensource.org/license/mit/)
