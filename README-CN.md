# VMware-Policy

在 VMware Skills 家族中共享策略检查与审计证据。

English · [简体中文](README-CN.md)

社区维护 · MIT 开源 · 非 VMware/Broadcom 官方产品。

[![18 秒调查示意演示](https://raw.githubusercontent.com/vmware-skills/marketplace/main/assets/demos/vmware-skills-zh.gif)](https://github.com/vmware-skills/marketplace/blob/main/assets/demos/vmware-skills-zh.mp4)

使用合成数据的示意动画，非实时录屏。[观看家族配音介绍（约 2 分钟）](https://github.com/vmware-skills/marketplace/blob/main/assets/demos/vmware-skills-zh.mp4)

## 能解决什么问题？

- 为工具调用应用共享策略与风险元数据。
- 通过 vmware-audit CLI 查询审计记录。
- 清洗外部文本，保留执行边界。

## 快速开始

安装已发布 CLI，并查看可用命令：

```sh
uv tool install vmware-policy==1.25.0
vmware-audit --help
```

需要 uv 与 Python >=3.10。远程查询前，在本地配置目标与凭据。[配置指南](skills/vmware-policy/references/setup-guide.md).

Claude Code 及其他宿主安装方式见[家族门户](https://github.com/vmware-skills/marketplace/blob/main/README-CN.md)。

## 使用边界

共享依赖库与 CLI，并非独立 MCP server。本地策略不替代 VMware RBAC，也不提供独立人工审批。

## 详细文档

- [能力范围](skills/vmware-policy/references/capabilities.md)
- [CLI 用法](skills/vmware-policy/references/cli-reference.md)
- [Agent 使用约束](skills/vmware-policy/references/agent-guardrails.md)
- [详细用法与架构](skills/vmware-policy/references/detailed-guide-CN.md)
- [唯一技能指令正本](skills/vmware-policy/SKILL.md)

属于 [VMware Skills 家族](https://github.com/vmware-skills/marketplace/blob/main/README-CN.md)：15 个 skill、14 个 MCP server 与一个共享 Policy 库。如果对你有用，欢迎 Star 家族门户。

[问题与反馈](https://github.com/vmware-skills/VMware-Policy/issues) · [MIT](LICENSE)
