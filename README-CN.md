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
```

## 核心组件

| 组件 | 说明 |
|------|------|
| `@vmware_tool` | 装饰器 -- 所有 VMware MCP 工具的强制包装器，负责策略前置检查 + 执行 + 审计日志记录 |
| `AuditEngine` | 基于 SQLite WAL 的追加式审计日志引擎，支持日志轮转（100MB 阈值，保留 5 个归档） |
| `PolicyEngine` | 基于 YAML 的规则引擎，支持拒绝规则、维护窗口、变更限制，文件变更时自动热加载 |
| `sanitize()` | 提示注入防御 -- 截断至 500 字符 + 清理 C0/C1 控制字符 |
| `vmware-audit` | Typer CLI -- 查询审计日志、导出 JSON、统计分析 |

## 架构

```
AI Agent -> vmware-pilot（按需编排）-> @vmware_tool 前置检查 -> skill 操作 -> 后置审计 -> ~/.vmware/audit.db
```

vmware-policy 是所有 VMware 技能的**强制依赖**，提供：

- **审计日志**：所有 156+ MCP 工具的操作记录写入统一数据库 `~/.vmware/audit.db`
- **策略引擎**：deny 规则、维护窗口、变更限制，热加载无需重启
- **输入消毒**：所有来自 vSphere/NSX/Aria API 的文本经过 `sanitize()` 处理
- **AI Agent 检测**：自动识别 Claude、Codex、Ollama、DeerFlow 等调用方
- **只读门控**（v1.8.0）：本库是 `apply_read_only_gate()` 的实现方，各 skill 只是调用它——一个环境变量即可让所有已安装的 VMware skill 进入只读模式，写工具在服务启动前从 MCP 注册表移除，详见[只读模式](#只读模式)

## 策略规则配置

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

| 等级 | 需要确认 | 示例 |
|------|:--------:|------|
| `low` | 否 | list、get、info、status |
| `medium` | 否 | reconfigure、update |
| `high` | 是 | power off、migrate、snapshot revert |
| `critical` | 是 + 生产审批 | delete VM、delete cluster |

## 只读模式

本包是家族只读门控的**实现方**，各 skill 只是调用它。提示词约束（"不要修改任何东西"）只是建议，弱模型可以无视；`apply_read_only_gate()` 把这个承诺变成结构性的：只读模式开启时，所有写工具在服务启动前就从 FastMCP 注册表中移除，`list_tools()` 根本不会列出它们——模型看不见的工具就无法调用。

### 操作员用法

一个变量即可让所有已安装的 VMware skill 进入只读模式：

```json
{ "env": { "VMWARE_READ_ONLY": "true" } }
```

解析优先级：按 skill 环境变量（`VMWARE_AIOPS_READ_ONLY`、`VMWARE_NSX_SECURITY_READ_ONLY` 等）→ 家族环境变量 `VMWARE_READ_ONLY` → 该 skill 自己的 `read_only:` 配置项 → 默认关闭。默认关闭，不主动开启则行为完全不变；每个 server 启动时会记录被移除工具的完整清单。

**fail-closed 设计**：悄悄退化成读写的只读模式比没有更糟——操作员会因此不再核查。凡是无法**证明**只读已生效的情况，一律抛 `ReadOnlyGateError` 中止启动：

- FastMCP 工具注册表无法枚举（例如 `mcp` 包版本不兼容）；
- 移除未生效——有写工具在清扫后仍然存在。

开关值无法解析（如 `VMWARE_READ_ONLY=ture`）**不中止启动**，而是判定为**开启**，并输出一条列出合法取值的警告：拼错绝不能导致写工具继续暴露。

### 工具分类依据

除非能证明是只读，否则一律按写工具处理。信号优先级：

1. 命中 `FORCE_WRITE` 名单；
2. docstring 以 `[WRITE]` 开头；
3. `readOnlyHint=False` annotation；
4. docstring 以 `[READ]` 开头；
5. `readOnlyHint=True` annotation；
6. 无结论 → 按写工具处理。

docstring marker 优先级高于 MCP annotation，因为前者覆盖率是满的（家族 244/244 个工具），而 vmware-harden 和 vmware-debug 通过 `build_server()` 工厂注册工具，**完全不传** annotations。

`FORCE_WRITE` 用于覆盖那些 marker 低报了真实副作用的工具。当前三条形态一致——对被管基础设施只读，但会往调用方指定的本地路径写文件，且牵涉凭据：

| 工具 | 所属 skill | 理由 |
|------|-----------|------|
| `vm_guest_download` | vmware-aiops | 只从 guest OS 读，但会写入操作员指定的 `local_path`，且需要 guest 凭据 |
| `get_supervisor_kubeconfig` | vmware-vks | 在模型指定的本地路径落地一份 session-token 凭据文件 |
| `get_tkc_kubeconfig` | vmware-vks | 同上 |

只写入 skill 自身本地存储的工具（如 vmware-harden 的 DuckDB twin）仍然保留暴露——那是观测结果的缓存，不是被管基础设施。

### Skill 作者接入方式

在所有工具模块注册完成之后、server 运行之前调用一次：

```python
from vmware_policy import apply_read_only_gate

WITHHELD_WRITE_TOOLS: list[str] = apply_read_only_gate(
    mcp, "vmware-aria", config_flag=_config_read_only()
)
```

`apply_read_only_gate(mcp, skill, config_flag=None) -> list[str]` 返回被移除工具的名称（已排序；模式关闭时为空列表），便于调用方记录到底有哪些工具被拦下；该函数幂等。`skill` 传带连字符的 skill 名，内部会归一化成按 skill 的环境变量（`vmware-nsx-security` → `VMWARE_NSX_SECURITY_READ_ONLY`）。`config_flag` 承载该 skill 自己的 `read_only:` 配置，仅在两个环境变量都未设置时才生效。若只想判断开关状态而不触碰注册表，用 `read_only_enabled(skill, config_flag=None) -> bool`。

只读模式与同一份报告（[VMware-AIops#31](https://github.com/zw008/VMware-AIops/issues/31)）催生的另外两块 harness 能力一同落地：列表信封 `paginated()`（`envelope.py`）与声明式环境 `set_environment_resolver()`（`environment.py`）。

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

- 密码通过 `sensitive_params` 在审计日志中脱敏为 `***`
- 审计数据库仅本地存储（`~/.vmware/audit.db`），无网络暴露
- `sanitize()` 防止通过 API 响应文本进行提示注入
- 策略旁路模式（`VMWARE_POLICY_DISABLED=1`）仍记录审计日志

## 开发

```bash
git clone https://github.com/zw008/VMware-Policy.git
cd VMware-Policy
uv venv && source .venv/bin/activate
uv pip install -e ".[dev]"
pytest --cov=vmware_policy
```

## 许可证

MIT
