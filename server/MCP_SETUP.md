# hackxplus MCP Server — 接入 Claude Code 配置

> 目的: 把 `server/` 的代码层 (资产库/门禁/探针/路由/续轮) 注册为 MCP 工具,
> 让 Claude Code 能按需调用。skill 层仍负责决策编排, MCP 层负责执行与状态。

> ✅ **已验证** (2026-08-27, Windows + mcp 2.0):
> `initialize → tools/list → tools/call` 全链路通过, 11 个工具全部可被 MCP client 发现。
> 端到端业务闭环: 建 target → 注入端点 → 垃圾洞被 Gate1 拦 → 真 SQLi 入库 → 资产树统计正确。

---

## 1. 安装依赖

```bash
python3 -m pip install --user --break-system-packages "mcp[cli]" requests
# 可选: 浏览器深度探索
python3 -m pip install --user playwright && python3 -m playwright install chromium
```

验证: `python3 server/mcp_server.py --self-test`

---

## 2. 注册到 Claude Code (二选一)

> ⚠️ **mcp 2.0 适配**: 库是 `pip install "mcp[cli]"` 装的 **2.x**, `FastMCP` 已移除,
> server 用的是 lowlevel API (`Server(on_list_tools=..., on_call_tool=...)`)。
> Windows 上验证 stdio 双向管道时, 不要用 git-bash 的 `&` 后台跑 server (stdin 变 /dev/null 会秒退),
> 用 Claude Code 自己的 MCP 启动机制即可。

### 方式 A — 全局 (所有项目可用)

编辑 `~/.claude/settings.json`:

```json
{
  "mcpServers": {
    "hackxplus": {
      "command": "python",
      "args": ["C:/Users/ZGW/Desktop/个人二开skill/hackxplus/server/mcp_server.py", "--db", "C:/Users/ZGW/Desktop/个人二开skill/hackxplus/data/hackxplus.db"],
      "env": {}
    }
  }
}
```

> 注意: Windows 路径用正斜杠; `--db` 指向持久化位置 (资产库), 先 `mkdir data`。

### 方式 B — 项目级 (仅 hackxplus 项目)

在仓库根 `.mcp.json`:

```json
{
  "mcpServers": {
    "hackxplus": {
      "command": "python",
      "args": ["${workspaceFolder}/server/mcp_server.py"]
    }
  }
}
```

配置后重启 Claude Code, `/mcp` 应看到 `hackxplus` 的 11 个工具。

---

## 3. 暴露的工具

| 工具 | 作用 | 续轮/报告用 |
|---|---|---|
| `asset_create_target` | 创建目标 (返回 target_id) | ✅ |
| `asset_get_asset_tree` | 恢复完整渗透状态 (续轮第一指令) | ✅ |
| `asset_inject_endpoint` | 注入新发现的接口 | ✅ |
| `asset_annotate_endpoint` | 接口风险标注 (risk_tags) | |
| `asset_record_vuln` | 漏洞入库 (触发五层门禁) | ✅ |
| `asset_update_coverage` | 更新覆盖矩阵 | ✅ |
| `probe_run` | 执行探针 (tier 1/2/3) | |
| `router_match` | 信号→技能映射 | |
| `gate_override_check` | 决策门覆写检测 (单向放宽) | |
| `session_checkpoint` | 写续轮点 | ✅ |
| `session_resume` | 恢复 pending 端点 | ✅ |

---

## 4. 自测

```bash
python server/mcp_server.py --self-test
# 期望:
#   inject: 1
#   record vuln (cors) → gate 1 拒绝
#   record vuln (sqli) → vuln_id 1
#   tree stats: vulns_found 1
```

---

## 5. 降级说明

- 未装 `mcp` 库 → MCP 模式不可用, 但 `HackXPlusCore` 核心逻辑仍可直接 import 调用
- 未装 `requests` → probe_engine 用 urllib 兜底 (仅 GET)
- 未装 `playwright` → browser.py 降级纯 HTTP 探测, 不阻塞流程
