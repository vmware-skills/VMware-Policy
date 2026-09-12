<!-- mcp-name: io.github.vmware-skills/vmware-policy -->
# VMware Policy

> **作者**: Wei Zhou, VMware by Broadcom — wei-wz.zhou@broadcom.com
> 本项目由 VMware 工程师维护的社区项目，非 VMware 官方产品。
> VMware 官方开发者工具请访问 [developer.broadcom.com](https://developer.broadcom.com)。

VMware MCP 技能家族的统一审计日志、策略执行与输入消毒基础设施层。

## 安装

```bash
pip install vmware-policy
```

## 使用方法

```python
from vmware_policy import vmware_tool

@vmware_tool(risk_level="high", sensitive_params=["password"])
def delete_segment(name: str, env: str = "") -> dict:
    ...
```

## CLI 命令

```bash
vmware-audit log --last 20
vmware-audit log --status denied --since 2026-03-28
vmware-audit stats --days 7
vmware-audit policy          # 查看当前生效的规则
```

## 核心组件

| 组件 | 说明 |
|------|------|
| `@vmware_tool` | 装饰器 -- 包裹技能的 MCP 工具，负责策略前置检查 + 执行 + 写一条审计记录 |
| `AuditEngine` | 基于 SQLite WAL 的追加式审计日志引擎，支持日志轮转（100MB 阈值，保留 5 个归档） |
| `PolicyEngine` | 基于 YAML 的规则引擎：拒绝规则、维护窗口，文件变更时自动热加载。`change_limits` 为预留字段，不强制执行 |
| `sanitize()` | 提示注入防御 -- 清理 C0/C1 控制字符与 Unicode 格式字符后截断（默认 500 字符） |
| `vmware-audit` | Typer CLI -- 查询审计日志、导出 JSON、统计分析、查看规则状态 |

## 架构

```
AI Agent -> vmware-pilot（按需编排）-> @vmware_tool 前置检查 -> skill 操作 -> 后置审计 -> ~/.vmware/audit.db
```

vmware-policy 是所有 VMware 技能的**强制依赖**，提供：

- **审计日志**：经 `@vmware_tool` 包裹的 MCP 工具，其调用记录写入统一数据库 `~/.vmware/audit.db`
- **策略引擎**：deny 规则、维护窗口，热加载无需重启（变更限制为预留字段，不强制执行）
- **输入消毒**：所有来自 vSphere/NSX/Aria API 的文本经过 `sanitize()` 处理
- **AI Agent 检测**：自动识别 Claude、Codex、Ollama、DeerFlow 等调用方

## 策略规则配置

读写授权由 vCenter/NSX 账号的 RBAC 决定。策略引擎只在其上叠加运维人员自己写的
拒绝规则和维护窗口，规则文件为 `~/.vmware/rules.yaml`（设置了 `$OPS_HOME` 时为
`$OPS_HOME/rules.yaml`）。`vmware-audit policy` 会报告当前生效的规则来源：

| 来源 | 条件 | 放行范围 |
|------|------|----------|
| `user` | 你的规则文件存在且加载成功 | 按你的规则 |
| `packaged-default` | 没有规则文件 | 使用随包附带的基线，它不拒绝任何操作 -- 策略层面全部放行 |
| `user-unreadable` | 你的文件存在但无法加载（YAML 错误、非 UTF-8） | 全部拒绝 -- 直到文件可加载为止；不会改用基线 |
| `baseline-unreadable` | 没有用户文件，且随包基线也无法加载 | 全部拒绝 |

PyYAML 是声明的依赖；若缺失，被装饰的工具调用会失败而不是被执行。规则文件变更后自动热加载。

`VMWARE_POLICY_DISABLED=1` 是运维人员的应急开关：在设置了它的进程中（MCP 宿主，
或 CLI 所在 shell），所有策略检查都会跳过，包括"规则无法加载时全部拒绝"。审计不受
影响 -- 每次跳过都会记录一条警告，两个入口的审计行 -- `@vmware_tool` 的 MCP 调用和
`@guarded` 的 CLI 命令 -- 状态都带 `_bypassed` 后缀（`ok_bypassed`、`error_bypassed`）。
请限制谁能修改 MCP 宿主进程的环境变量。

将默认规则复制到 `~/.vmware/rules.yaml` 并自定义：

```yaml
# 拒绝规则 -- 阻止特定操作
deny:
  - name: no-delete-in-prod
    operations: ["delete_*", "cluster_delete"]
    environments: ["production"]
    reason: "生产环境禁止破坏性操作"

# 维护窗口 -- 高/危险操作仅在窗口内允许
maintenance_window:
  start: "22:00"
  end: "06:00"

# 变更限制 -- 预留字段，当前不强制执行（引擎无前置状态计算增量，
# 配置后仅记录一条 "未强制执行" 的警告）
change_limits:
  max_cpu_change_pct: 20
  max_memory_change_pct: 50
```

规则修改后自动热加载，无需重启任何服务。

## 风险等级

工具声明的等级会写入审计行，可被 deny 规则的 `min_risk_level` 匹配，并决定已配置的
维护窗口是否适用。等级本身不会拦截执行。

| 等级 | 示例 |
|------|------|
| `low` | list、get、info、status |
| `medium` | reconfigure、update |
| `high` | power off、migrate、snapshot revert |
| `critical` | delete VM、delete cluster |

## VMware 技能家族

| 技能 | 定位 | 安装命令 |
|------|------|---------|
| **vmware-aiops** | VM 生命周期 + 部署 + Guest Ops | `uv tool install vmware-aiops` |
| **vmware-monitor** | 只读监控 | `uv tool install vmware-monitor` |
| **vmware-storage** | 存储管理（iSCSI + vSAN） | `uv tool install vmware-storage` |
| **vmware-vks** | Tanzu Kubernetes | `uv tool install vmware-vks` |
| **vmware-nsx** | NSX 网络管理 | `uv tool install vmware-nsx-mgmt` |
| **vmware-nsx-security** | NSX 安全（DFW + 安全组） | `uv tool install vmware-nsx-security` |
| **vmware-aria** | Aria Ops 指标/告警/容量 | `uv tool install vmware-aria` |
| **vmware-avi** | AVI/ALB 负载均衡 | `uv tool install vmware-avi` |
| **vmware-pilot** | 多步骤工作流编排 | `uv tool install vmware-pilot` |
| **vmware-policy** | 审计 + 策略（本包） | `uv tool install vmware-policy` |

## 安全

- 审计数据库（`~/.vmware/audit.db`，仅本地，目录 `0700` / 文件 `0600`）记录工具参数、结果、状态、操作系统用户和推断的 agent -- 请将其及归档视为敏感数据
- `sensitive_params` 中列出的参数存为 `***`；声明了 `sensitive_result=True` 的工具，其结果整体替换；参数和结果中的凭据类键名（`password`、`token`、`kubeconfig` 等）以及报错文本中的凭据样式内容，在 MCP 和 CLI 两条路径上都会被脱敏。键名不在该列表中的凭据必须在 `sensitive_params` 中声明
- `sanitize()` 防止通过 API 响应文本进行提示注入
- 策略旁路（`VMWARE_POLICY_DISABLED=1`）只跳过策略检查，不跳过审计

## 开发

```bash
git clone https://github.com/vmware-skills/VMware-Policy.git
cd VMware-Policy
uv venv && source .venv/bin/activate
uv pip install -e ".[dev]"
pytest --cov=vmware_policy
```

## 许可证

MIT
