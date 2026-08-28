# hackxplus — 自主渗透测试 Agent 系统 · 项目化设计文档

> 状态: **设计稿 v0.1** | 目的: 把 Claude Code Skill 包装成可上简历的工程化项目
> 对标: 《AI 智能渗透测试系统的设计与实现》(internal, 2025.12 启动) 的工程落地 + hackxplus 现有 AI 决策智慧
> 核心原则: **代码做执行与管控, LLM 做决策与推理**。prompt 知识数据化, 被代码消费。

---

## 0. 一句话定位(简历标题)

> **hackxplus — 基于 Claude Code 的自主渗透测试 Agent 系统**
> **知识层(50 探针 + 98 利用技能的信号路由) × 工程层(MCP 资产库 + 代码级五层质量门禁 + 自动续轮 + 浏览器深度探索)**
> 编排 25+ 安全工具与 LLM 推理, 从"给一个 URL"到"出漏洞报告"全流程自主。

---

## 1. 现状诊断(为什么需要这个设计)

### 1.1 现有资产(要保留的"脑子")

| 模块 | 现状 | 定位 |
|---|---|---|
| Wave 0-4 分阶段流水线 | markdown 编排 | 决策框架(保留) |
| 双层决策门 Gate1/Gate2 | markdown | 预算/范围控制(保留) |
| Gate Override 单向放宽 | markdown | **差异化卖点**(代码化) |
| 50 探针三层懒加载 | markdown | **差异化卖点**(数据化 JSON) |
| 信号路由(隐式框架检测 20+ 规则) | markdown | **差异化卖点**(代码化) |
| 98 个 hack-skills | 外部依赖, 不在仓库 | 需收纳进仓库 |
| OAST 全生命周期 | markdown | 保留 |

### 1.2 关键差距(要补的"骨架")

| # | Gap | 现状 | 目标 | 简历卖点 |
|---|---|---|---|---|
| G1 | **零工程代码** | 全部逻辑在 prompt | MCP Server + 执行引擎 | 工程能力 |
| G2 | **无外部状态** | progress.json 单会话 | 资产库(端点/覆盖/凭据/漏洞/流量) | 上下文管理 |
| G3 | **无自动续轮** | 重启跳过已完成步骤 | 上下文阈值→新 Session→恢复 | 任务连续性 |
| G4 | **无代码层门禁** | anti_patterns.md prompt 纪律 | 五层 Gate Chain 代码强制 | 误报率控制 |
| G5 | **浏览器非一等公民** | 仅验证/注册 | Playwright 抓流量/深度探索/接口发现 | 攻击面发现 |
| G6 | **无量化的结果** | 零实测数据 | 靶场 benchmark + 真实授权站点 | 可验证成果 |
| G7 | **无覆盖标准** | "出报告"即完 | coverage 矩阵 + 终止条件 | 工程严谨性 |

### 1.3 与参考文章的关系(面试叙事要点)

参考文章作者迭代路径: **P-E-R → Multi-Agent → 一体化 Agent**, 结论:
> "简单胜于复杂; 状态外置数据库; 代码层兜底优于 Prompt 约束; 别依赖 Claude Code 自带 compact。"

→ 我们的包装不是照抄, 而是**取其工程骨架(资产库/门禁/续轮), 用自己的 AI 决策智慧填装**:
- 他 15 个专家 Subagent 按需委派 → 我们 **50 探针 + 信号路由 + hack-skills 按需加载**, 零命中零 token 开销(成本控制更优)
- 他五层门禁做误报控制 → 我们 **Gate Override 单向放宽 + 隐式框架检测 + 信源可信度加权**(决策鲁棒性更优)

---

## 2. 目标架构

### 2.1 总览

```
                     ┌─────────────────────────────────────┐
                     │            Agent(决策中心)            │
                     │  · Wave 编排                        │
                     │  · 探针结果判断                      │
                     │  · 攻击链推理                       │
                     │  · 报告生成                        │
                     └───────┬─────────────────────────────┘
                             │ MCP 工具调用
        ┌────────────────────┼────────────────────┐
        ▼                    ▼                    ▼
┌───────────────┐   ┌────────────────┐   ┌─────────────────┐
│  probe_engine │   │  browser(Play) │   │   asset_store   │
│  50 探针引擎   │   │  浏览器=眼睛手  │   │  资产库(外部记忆) │
│  JSON 配置驱动 │   │  流量/接口发现  │   │  SQLite→MySQL    │
└───────┬───────┘   └───────┬────────┘   └───────┬─────────┘
        │                   │                    │
        ▼                   ▼                    ▼
   signal_router ──► gate_chain(五层门禁) ◄── runner(自动续轮)
   技术栈/攻击面 → 技能    漏洞入库前强制校验      上下文阈值→恢复
```

### 2.2 目录结构

```
hackxplus/
├── README.md                 # 重写: 架构图 + 量化指标
├── SKILL.md                  # 入口 (精简, 指向 agent/)
├── agent/                    # ← 知识层 (由 markdown 重构, 数据化)
│   ├── planner.md            # Wave 编排 → 决策逻辑
│   ├── probes/               # 50 探针 → JSON 配置 (probe_engine 消费)
│   │   ├── tier1_universal.json
│   │   ├── tier2_signal.json
│   │   └── tier3_feedback.json
│   ├── signals/              # 信号→技能映射表 (signal_router 消费)
│   └── skills/               # 98 hack-skills 收纳进仓库 (不再外部依赖)
├── server/                   # ★ 核心代码 (Python MCP Server)
│   ├── __init__.py
│   ├── mcp_server.py         # MCP 工具注册与分发
│   ├── asset_store.py        # 资产库 + 覆盖矩阵
│   ├── gate_chain.py         # 五层漏洞质量门禁
│   ├── probe_engine.py       # 探针执行引擎 (读 JSON 配置)
│   ├── signal_router.py      # 技术栈/攻击面/反馈 → 技能映射
│   ├── browser.py            # Playwright 封装: 流量/深度探索/接口发现
│   └── runner.py             # 自动续轮 + 上下文阈值 + 恢复
├── eval/                     # ★ benchmark (可量化验证)
│   ├── benchmark.py          # 批量跑靶场, 输出指标
│   ├── targets/              # 靶场清单 (DVWA/Pikachu/vulhub...)
│   └── results/              # 每次运行的 JSON 报告
├── scripts/                  # 保留原有工具脚本
│   ├── discover_tools.sh
│   ├── merge_results.sh
│   └── gen_*.py
└── install.sh                # 更新: 一键装依赖 + MCP 注册
```

---

## 3. 数据模型 (资产库 schema)

### 3.1 资产树 JSON (一次调用恢复完整渗透状态)

```json
{
  "target": "http://target.example.com",
  "hosts": [{
    "hostname": "target.example.com",
    "port": 8080,
    "endpoints": [{
      "id": 42,
      "path": "/api/user",
      "method": "GET",
      "params": ["id", "name"],
      "func_desc": "用户信息查询接口",
      "risk_tags": ["sqli", "idor"],
      "test_status": "pending",
      "priority": 1,
      "coverage": {
        "sqli": "pending",
        "idor": "not_vulnerable",
        "xss": "pending"
      }
    }]
  }],
  "credentials": [
    {"username": "admin", "password": "***", "login_url": "/login"}
  ],
  "stats": {
    "total_endpoints": 67,
    "tested": 41,
    "pending": 26,
    "vulns_found": 3
  }
}
```

### 3.2 数据库表 (SQLite 起步, 预留 MySQL)

| 表 | 字段 | 用途 |
|---|---|---|
| `targets` | id, url, scope, auth_mode | 目标管理 |
| `endpoints` | id, target_id, path, method, params, func_desc, risk_tags, priority, test_status | 接口清单 + 覆盖矩阵 |
| `coverage` | endpoint_id, vuln_type, status(pending/not_vulnerable/confirmed) | 每个接口×漏洞类型覆盖状态 |
| `credentials` | id, username, password, source, login_url | 凭据管理 |
| `traffic` | id, ts, method, url, request_headers, request_body, response_status, response_headers, response_body | HTTP 流量(用于深度分析) |
| `vulns` | id, endpoint_id, type, severity, description, evidence, dedup_key, gate_status | 已确认漏洞(过五层门禁) |
| `sessions` | id, run_id, started_at, context_threshold_reached, max_turns | 自动续轮记录 |

---

## 4. MCP 工具接口定义

| 工具 | 入参 | 返回 | 职责 |
|---|---|---|---|
| `asset_get_asset_tree` | target_id | 资产树 JSON | 恢复/查看完整渗透状态 |
| `asset_inject_endpoint` | target_id, path, method, params | endpoint_id | 浏览器/探针发现接口后入库 |
| `asset_annotate_endpoint` | endpoint_id, risk_tags, priority | ok | 接口风险标注 |
| `asset_record_vuln` | endpoint_id, type, severity, evidence | gate_result | 漏洞入库(触发五层门禁) |
| `asset_update_coverage` | endpoint_id, vuln_type, status | ok | 更新覆盖矩阵 |
| `browser_open` | url | screenshot, snapshot | 打开目标 |
| `browser_deep_explore` | max_links, max_depth | discovered_endpoints | 深度探索 + 捕获流量 |
| `browser_traffic` | detail(bool) | traffic[] | 获取捕获的 API 调用 |
| `probe_run` | endpoint_id, tier | probe_hits | 执行探针 |
| `router_match` | signals | skill_list | 信号→技能映射 |
| `session_checkpoint` | run_id | ok | 写续轮点 |
| `session_resume` | run_id | pending_endpoints | 恢复 |

---

## 5. 核心模块设计

### 5.1 gate_chain.py — 五层漏洞质量门禁 (G4)

```python
# 参考文章作者原话: "必须在代码层做硬性控制" → 我们用代码落地
GATE1_JUNK = ["cors", "security headers", "cookie flag", "clickjacking", "x-frame-options"]
GATE3_BLACKLIST = ["self-xss", "sourcemap", "version disclosure", "tls version", "directory listing"]

def validate_vuln(v):
    # Gate1: 垃圾洞标题拦截
    if any(k in v.title.lower() for k in GATE1_JUNK):
        return REJECT("junk-title", v)
    # Gate2: 描述否定检测
    if any(k in v.description.lower() for k in ["not a vulnerability", "expected behavior", "no impact"]):
        return REJECT("self-denied", v)
    # Gate3: 低价值类型黑名单
    if v.type in GATE3_BLACKLIST:
        return REJECT("blacklist-type", v)
    # Gate4: IDOR 危害校验 (必须证明访问了非授权数据)
    if v.type == "idor" and not v.evidence.get("unauthorized_data_access"):
        return REJECT("idor-no-impact", v)
    # Gate5: 去重 (同 endpoint + 同类型 + 同参数模式)
    key = f"{v.endpoint}:{v.type}:{canonical_params(v.params)}"
    if key in seen:
        return REJECT("duplicate", v)
    return ACCEPT(v)
```

### 5.2 asset_store.py — 外部记忆 (G2/G3)

- SQLite 起步(零依赖), 抽象 DAO 层, 可换 MySQL
- 覆盖矩阵: endpoint × vuln_type, 状态机 `pending → testing → not_vulnerable/confirmed`
- 会话表: 支持续轮恢复

### 5.3 runner.py — 自动续轮 (G3)

- 上下文阈值检测(约 50%)或 max_turns 耗尽 → `session_checkpoint` 写库
- 浏览器 SSE 长驻保活, 新 Session 连同一浏览器(继承登录态)
- 新 Session 首指令: `asset_get_asset_tree` → 从 pending 端点继续
- 终止条件: 连续 2 轮无新端点发现 → 判定充分探索; 最大 70 轮安全上限

### 5.4 probe_engine.py — 探针执行引擎 (G1 核心)

- 50 探针从 markdown → JSON 配置 (`name / category / tier / payloads / detect` )
- 代码执行 + 结构化输出 `probe_hits`, 替代"LLM 读 markdown 照着发请求"
- 三层懒加载: Tier1 永远跑 / Tier2 信号激活 / Tier3 反馈触发

### 5.5 signal_router.py — 信号路由代码化 (差异化)

- 输入: 技术栈信号(HTTP 头/Cookie/错误页/HTML) + 攻击面信号(登录/JWT/GraphQL/上传/支付) + 基础设施信号(CDN/SCM/actuator) + 探针反馈信号
- 输出: 技能加载清单(优先级 RCE>Auth>Info)
- Gate Override 逻辑落这里: 只允许"跳过→启用"单向放宽

### 5.6 browser.py — Playwright 封装 (G5)

- `deep_explore`: 遍历导航链接, 捕获后端 API 调用
- `traffic`: 提取请求/响应, 入库 `traffic` 表
- 登录态跨会话保活 (SSE 长驻)

---

## 6. 量化验证方案 (G6) — 简历的"数字"来源

### 6.1 靶场 benchmark (eval/benchmark.py)

| 靶场 | 预期覆盖 | 指标 |
|---|---|---|
| DVWA | SQLi/XSS/CMDi/FileUpload/LFI | 准确率 = 真阳 / (真阳+假阳) |
| Pikachu | SQLi/XXE/SSRF/IDOR/越权 | 召回率 = 真阳 / 已知漏洞总数 |
| vulhub (WordPress/ThinkPHP/Log4j...) | 已知 CVE | 耗时/目标 |

输出: **准确率、召回率、覆盖端点数、误报数、单目标耗时、续轮次数** → JSON + markdown 报告

### 6.2 真实授权站点

- 列: 目标 / AI 发现漏洞数 / 人工确认数 / 未确认数 / 耗时
- 参考文章口径: "137 个漏洞, 人工确认 32 个" — 我们也按这个口径出表

### 6.3 量化目标(设计冲刺目标)

- 靶场准确率 ≥ 80% (五层门禁后)
- 单目标平均覆盖端点 ≥ 30 个
- 垃圾洞报告数 → 0 (门禁拦截)
- 静态站 token 开销降 31% (已有设计数字, 保留为卖点)

---

## 7. 落地计划 (分阶段)

### Phase 1 — 工程骨架 (优先, 1-2 周)
1. `server/` MCP Server 骨架 + `asset_store.py`(SQLite)
2. `gate_chain.py` 五层门禁(代码层, 核心卖点)
3. `probe_engine.py` + 探针 JSON 化(挑 10 个核心探针先落地)
4. `eval/benchmark.py` + DVWA/Pikachu 靶场 → 跑出第一批数字

### Phase 2 — 深度能力 (2-3 周)
5. `signal_router.py` 代码化 + Gate Override
6. `browser.py` Playwright 流量捕获 + 接口发现
7. `runner.py` 自动续轮 + 上下文阈值

### Phase 3 — 打磨与包装 (1 周)
8. 98 skills 收纳进仓库
9. README 重写(架构图 + 量化指标)
10. 简历项目描述 + 面试叙事定稿

---

## 8. 简历项目描述(定稿稿)

> **hackxplus — 自主渗透测试 Agent 系统**(Claude Code · Python · MCP · Playwright · SQLite)
>
> 基于 Claude Code 构建 AI 驱动的黑盒渗透测试编排框架, 作为调度层编排 25+ 安全工具与 LLM 推理, 从"一个 URL"到"漏洞报告"全流程自主:
>
> - **编排与决策**: Wave0-4 分阶段流水线 + 双层决策门 + Gate Override 单向放宽(安全偏向); 信号驱动按需加载 50 探针 / 98 利用技能, 静态站上下文开销降 31%
> - **状态外置**: 自研 MCP 资产库(端点/覆盖矩阵/凭据/漏洞/流量)作为 Agent 外部记忆, 支持自动续轮(上下文达阈值开新 Session), 中断后从 pending 端点精确恢复
> - **质量门禁**: 代码层实现五层漏洞 Gate Chain(垃圾洞拦截 / 否定检测 / 低危黑名单 / IDOR 危害校验 / 去重), 将 AI 的"宁可错报"倾向压到门禁外
> - **可验证**: 在 N 个开源靶场(DVWA/Pikachu/vulhub) + M 个授权站点实测, 准确率 X%, 单目标平均覆盖端点 Y 个, 报告全文 0 垃圾洞

### 面试叙事 STAR

| 环节 | 内容 |
|---|---|
| **S 情境** | 黑盒渗透信息量巨大: 上下文爆炸 / AI 爱报垃圾洞 / 长任务中断丢进度 |
| **T 任务** | 构建自主渗透 Agent: 覆盖广 + 误报低 + 长任务连续 |
| **A 行动** | ① 调研业界: 参考 P-E-R / Multi-Agent 方案的失败教训 → 一体化 Agent ② 工程化: MCP 资产库外置状态 + 五层代码门禁 + 自动续轮 ③ 差异化: 50 探针懒加载 + 信号路由 + Gate Override ④ 量化: 靶场 benchmark |
| **R 结果** | 靶场准确率 X%, 覆盖端点 Y 个, 垃圾洞 0, 静态站 token 降 31% |

### 必须会回答的三个"为什么"(面试官追问)

1. **为什么不用现成的 sqlmap/nuclei 就行?**
   → 它们是单点工具, 我的是"调度层": 决定"该不该扫、扫哪、多深、扫完怎么验证利用"。sqlmap/nuclei 只是我 25+ 工具链里的两件。
2. **LLM 能处理 50 探针为什么还要代码化?**
   → 参考文章作者原话: 代码层兜底优于 Prompt 约束。探针是确定性执行(发请求+规则匹配), 不该花 LLM token; LLM 只做判断(探针结果解读/攻击链推理)。
3. **五层门禁会不会误杀真洞?**
   → 门禁是"低危垃圾洞拦截 + 去重", 不拦高危害确认。IDOR 校验只是要求"证明访问了非授权数据", 真越权照样过。

---

## 9. 风险与边界(诚实声明)

- **本项目是授权测试专用工具**, 只对获得授权的目标使用。简历上写"授权站点实测", 不写黑产场景。
- 98 skills 收纳进仓库时注意授权/来源标注(它们来自开源 hack-skills 项目)。
- 参考文章的 137/32 数据是**它的**成果, 不借用; 我们的数字必须从自己跑的 benchmark 出。
- 工作量估算是乐观值, 实际按 Phase 拆分迭代, 每 Phase 结束有可验证产物。

---

*设计文档 v0.1 — 待评审后进入 Phase 1 编码。*
