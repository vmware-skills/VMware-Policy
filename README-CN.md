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

## 报告工具*返回*的失败

大多数工具用抛异常表示失败，`@vmware_tool` 会记录下来。而捕获异常、返回一个错误载荷的工具，
看起来和一次成功调用一模一样——很长时间里它也确实被记成了成功，这同时意味着会为从未发生的变更
写入撤销令牌，熔断器也从来看不到失败。

现在 dict 形状的载荷会被自动识别。工具只要返回家族约定的形状，就什么都不用做：

```python
return {"error": msg, "hint": "Run 'vmware-nsx doctor'."}   # 记为失败
```

返回类型带不了这个标记的工具——比如返回控制台文本的——必须显式说明：

```python
from vmware_policy import report_tool_failure

except Exception as exc:
    report_tool_failure(str(exc))
    return f"Error: {msg}"
```

字符串是刻意不去嗅探的：返回控制台输出的 skill 可能把以 "Error:" 开头的文本当作*数据*输出，
把这些调用标为失败，就是方向相反的同一种误报。

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
AI Agent -> vmware-pilot（按需编排）-> @vmware_tool 前置检查 -> skill 操作 -> 写一条审计记录 -> ~/.vmware/audit.db
```

vmware-policy 是所有 VMware 技能的**强制依赖**，提供：

- **审计日志**：经 `@vmware_tool` 包裹的 MCP 工具，其调用记录写入统一数据库 `~/.vmware/audit.db`
- **策略引擎**：deny 规则、维护窗口，热加载无需重启（变更限制为预留字段，不强制执行）
- **输入消毒**：所有来自 vSphere/NSX/Aria API 的文本经过 `sanitize()` 处理
- **AI Agent 检测**：根据环境变量记录调用方：`claude`、`codex`、`deerflow`、`local`（Ollama 主机）或 `unknown`

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
    operations: ["delete_*", "remove_cluster_host"]
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

## 工具暴露范围

每个 skill 的 MCP server 都可以只提供一部分工具。`<cli> mcp --expose read`（或环境变量
`VMWARE_<SKILL>_MCP_EXPOSE=read`）只保留标注了 `readOnlyHint: true` 的工具；`--allow-write a,b`（或
`VMWARE_<SKILL>_MCP_ALLOW_WRITE`）在此基础上再保留指定的写工具。没有这个标注的工具一律算写工具。取值不认识，或者名字
不是这个 server 的写工具，server 会在开始服务前退出（退出码 2）。2.0 之前的旧工具名也可以用。

直接导入 server 对象的启动程序，可以调用同一段代码，不必去改 SDK 的私有注册表：

```python
from vmware_policy.exposure import restrict_tools

restrict_tools(mcp, skill="storage", expose="read", allow_write=["enable_iscsi"])
mcp.run(transport="streamable-http")
```

在已经运行的事件循环里请用 `await arestrict_tools(...)`。server 对象只需要有 SDK 公开的 `list_tools()` 和
`remove_tool()` 两个方法。`restrict_tools` 不读环境变量；如果要像 `<cli> mcp` 一样读取 `VMWARE_<SKILL>_MCP_*`，
请传入 `*settings("storage")`（或调用 `apply_or_exit`）。只要给了任一命令行选项，两个环境变量都会被忽略，两种来源不会混用。

会执行其他步骤的工具（计划、工作流或批量工具）能执行的所有写操作都会随它一起暴露，包括被这个设置隐藏的写操作。

这只决定向客户端提供哪些工具，**不是授权**：一次调用能改什么由账号权限决定，deny 规则对所有暴露出来的工具照样生效。

## 通过 HTTPS 提供 MCP

`vmware_policy.serve` 可以让 skill 的 MCP server 跑在 stdio（默认）、HTTPS，或者跑在本机 HTTP 上、由前面负责 TLS 的
反向代理转发。两种网络方式都必须先有 bearer token，没有 token 就不会绑定端口。

```bash
vmware-audit token create alice      # token 只显示这一次；文件里只存 sha256（权限 0600）
vmware-audit token list
vmware-audit token revoke alice      # 正在运行的 server 从下一个请求起就拒绝它
```

- token 存在 `$OPS_HOME/mcp-tokens`（默认 `~/.vmware`）。客户端发送 `Authorization: Bearer <token>`。
- `https` 需要 `--cert`/`--key`（PEM），以及客户端访问时用到的每一个主机名 `--public-name`；其他 Host 或 Origin 的请求
  一律拒绝（防 DNS 重绑定）。`http` 只能绑定 127.0.0.1、::1 或 localhost。
- 每条审计记录都写明调用者 `token:<名字>` 和接入方式（`mcp-https`、`mcp-http-loopback`）。
- 写明同一个 `target` 的调用依次执行，写明不同 target 的调用并行；没有写 target 的调用（即用 skill 的默认 target，
  或工具本身没有 `target` 参数）独占执行。等待中的调用按先来先服务处理，哪一类都不会把另一类饿死；想要并行，
  请写明 target。失控熔断按调用者分别计算。使用会话池的 skill（见下）不受这些限制。
- 一个会话只能由创建它的那个 token 名字使用（由 SDK 保证）。吊销一个 token 后用同样的名字新建，新 token 可以接着用
  旧会话，所以 token 泄露时请换一个新名字。空闲会话 30 分钟后过期。
- deny 规则可以按调用者限定：在 `$OPS_HOME/rules.yaml` 里写 `clients: ["intern-*"]`，只对这些 token 名字生效
  （stdio 和 CLI 调用不受这类规则影响）。
- 绑定端口之前，server 会先向自己发送不带 token 的 POST/GET/DELETE 请求，三个都得到 401 才会启动。
- `GET`/`HEAD /healthz` 不需要 token，返回 `{"status": "ok"}`，供负载均衡做健康检查；它不透露任何其他信息，
  也不校验 `Host`。其他所有路径都需要 token。
- 每条审计记录都带上调用方的关联 ID：`traceparent` 头里的 trace-id，没有则取 `X-Request-ID`，再没有取
  `X-Correlation-ID`（只保留安全字符，最长 128）。`vmware-audit log --correlation-id ID` 可以查出平台上某一次请求
  对应的记录。这个 ID 由调用方提供，只用于关联追踪，不能作为证明。
- **同一个端点的所有调用者都以该 server 的账号执行操作。** token 用来识别调用者，在平台上不授予任何权限。按权限等级、
  按可以互相看到工作内容的人群，各开一个端点。

## 会话池

连接平台的 skill 可以为每个 target 维护一个小的会话池（`vmware_policy.pool.SessionPool`，`VMWARE_MCP_POOL_SIZE`，
默认 2），并用 `run_server(..., pooled=True)` 启动 server。通过网络方式访问时，每个调用在整个执行过程中独占自己在每个 target 上的会话
（工具返回的是普通数据，返回之后不再从会话读取任何东西），所以同一 target 的调用可以并行，最多到池的大小；没有写 target 的调用也不再
逐个执行。已经持有会话的调用不会等待另一个 target：那个 target 的池满时，它会拿到一个临时的额外会话，所以跨 target
的调用不会死锁。等会话超过 300 秒的调用会收到一条写明 target 的错误。每个会话都是 target 上的一次登录。stdio 和 CLI
仍然每个 target 缓存一个会话，与池里的会话分开。

## 权限自诊断

`vmware_policy.access.vsphere_access_info(si, target=, requirements=, tool=)` 是各 vSphere skill 的 `get_access_info`
工具的实现：target 使用哪个账号、每个工具需要哪些权限（来自 skill 的需求表），以及当前会话在根文件夹上是否持有这些
权限（`AuthorizationManager.HasPrivilegeOnEntities`，只需要 System.View）。"根上未授予"不等于"没有权限"：具体对象
上的授权不在检查范围内。查询失败记为 `undetermined`，绝不当作已授予。

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
| **vmware-harden** | 合规基线 + Drift 检测 | `uv tool install vmware-harden` |
| **vmware-vdi** | Horizon VDI 运维 | `uv tool install vmware-vdi` |
| **vmware-privateai** | Private AI GPU / 模型服务运维 | `uv tool install vmware-privateai` |
| **vmware-debug** | 故障关联 / 根因 | `uv tool install vmware-debug` |
| **vmware-log-insight** | 集中日志检索 | `uv tool install vmware-log-insight` |
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
