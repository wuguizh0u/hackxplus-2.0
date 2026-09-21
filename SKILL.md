---
name: hackprobe
description: "AI-assisted black-box security audit. Wave-driven architecture: recon → deep discovery → probe engine with on-demand hack-skills deep exploitation → attack chain report. Covers 40+ vulnerability categories including SQLi, XSS, SSRF, SSTI, CSRF, XXE, deserialization, NoSQL, race conditions, subdomain takeover, business logic, and more. Use when user provides a URL to hack, audit, or find vulnerabilities."
---

# hackprobe — AI-Assisted Black-Box Security Audit

## CONFIRMATION (MANDATORY)

Before ANY action, ask: **"You are about to run an active security audit against `<URL>`. Are you sure you want to proceed?"** Only proceed after explicit confirmation.

## STEP 0 — Directory Init + Target Registration (MANDATORY)

```bash
source infra/directory_setup.md
init_hackprobe_dir "<URL>"          # 导出 WORK_ROOT/TMP/SHARED/AUDIT_LOG/HACKXPLUS_DB
source scripts/discover_tools.sh   # 导出 $HACKPROBE_NMAP/$HACKPROBE_SQLMAP/$HACKPROBE_NUCLEI 等
cd "$WORK_ROOT"

# 落盘 target_id（后续所有 Wave 从这里读）
TARGET_ID=$(cat "$SHARED/target_id.txt" 2>/dev/null || echo "")
mkdir -p "$SHARED"
```

**然后注册主目标到 SQLite（真相源）** —— 调 MCP 工具 `asset_create_target`：

| 参数 | 值 |
|------|-----|
| `url` | `"<URL>"`（完整 URL，含 scheme） |
| `scope` | `"in-scope"` |
| `auth_mode` | `"unauthenticated"`（Gate 2 后回填真实值） |

拿到返回的 `target_id` 后落盘：

```bash
echo "<返回的 target_id>" > "$SHARED/target_id.txt"
```

> **契约**：本步失败不阻塞 Wave 1，但 `$SHARED/target_id.txt` 缺失时
> Wave 3 必须**先补调** `asset_create_target`。
> **SQLite 是唯一真相源**，`$SHARED/*.json` 只是 Wave 间的传递介质。

`discover_tools.sh` 自动发现 `D:/1渗透tools/` 下 40+ 工具，导出为 `$HACKPROBE_*` 环境变量。找不到的工具标记 skip，不阻塞流程。后续所有 Wave 优先用 `$HACKPROBE_*` 调工具，不存在再 curl 手工。

## PREREQUISITE — audit-rules (MANDATORY)

**Before Wave 1 starts**, invoke `Skill("audit-rules")` to load the audit discipline cheat-sheet. This refreshes:
- 🗑 Junk-finding blacklist: CORS w/o credentials, Self-XSS, Sourcemap, version-only, TLS warnings
- 🔬 No PoC = does not exist. Phenomenon ≠ vulnerability.
- ⏱ 20-minute rule: No exploitable finding in 20 min on one endpoint → switch attack surface
- 🎯 Attack surface decision tree: login→IDOR, API→unauth access, upload→bypass, payment→race condition

All audit-rules constraints override any conflicting instructions in downstream wave files.

## Architecture — Wave-Driven Pipeline

```
Wave 0 → Pre-flight 威胁建模（10-15s，不阻塞 Wave 1）
    ├── curl 首页特征 + httpx 技术栈 + DNS/CDN/WAF
    └── → _shared/target_profile.json（类型+策略）
        ↓
Wave 1 → 侦察与攻击面发现
    ├── 1a: 4 Agent 并行（OSINT/子域/端口/域名）+ A5 Host碰撞
    ├── 1b: 3 Agent 并行（技术栈/URL/密钥）
    └── 1c: 3 Agent 并行（默认凭证/敏感文件/SSL）
        ↓
     Gate 1: 6 问决策（WAF? 静态? API? 注册? 技术栈? 高价值子域?）
        ↓
Wave 2 → 深层挖掘（条件激活，低价值目标整 wave 跳过）
    ├── Nuclei safe-only / 深层子域 / 深目录爆破 / JS端点 / 密码爆破 / CVE映射
        ↓
     Gate 2: 4 问决策（新资产? 弱口令? 自动注册? WAF跳过?）
        ↓
Wave 3 → 探针 + 信号路由 + 深度利用（核心引擎，单执行体）
    ├── OAST 自动启动（interactsh-client，失败静默降级）
    ├── Step 0: 自动注册/登录（多通道，5min超时降级，绝不阻塞）
    ├── Step 1: Tier 1 — 12 通用探针（永远跑，~60s）
    ├── Step 2: 信号收集 → 路由表匹配 → Tier 2 条件探针
    ├── Step 3: 去重合并 → 按 RCE>Auth>Info 优先级排序
    ├── Step 4: 按需加载 hack-skills → 深度利用 + Tier 3 反馈（1轮，不递归）
    └── Step 5: 汇总 + OAST 收尾
        ↓
Wave 4 → AI 编排报告
    ├── 高危发现 AskUserQuestion 弹窗确认（无超时，等用户回复）
    ├── 攻击链关联 + CVSS 评分 + 业务影响
    ├── Chrome MCP 验证高影响链（CVSS ≥ 8.0）
    └── 生成 REPORT.md
        ↓
Cleanup → _work/tmp/ tar.gz 归档 + 安全清理临时文件
```

## 核心设计原则

1. **探针贱，技能贵** — 12 通用探针永远跑，98 hack-skills 命中才加载，未命中零开销
2. **信号驱动** — 技术栈/攻击面信号决定加载哪些 hack-skills
3. **不依赖 Wave 1 完美** — Tier 1 通用探针兜底
4. **curl 做 99%** — 重型工具只在确认值得用时调用
5. **三层懒加载** — 静态站仅 ~21KB 探针（省 ~31KB tokens）

## Agent Intelligence — 框架做不到的事

框架做苦力（扫端口/跑探针/CVE 映射）。**你（LLM）的推理能力才是挖洞核心：**

| 能力 | 做法 |
|------|------|
| **JS Bundle 逆向** | 读 JS bundle → 搜 API 路径/fetch/axios/WebSocket → 提取隐藏端点 |
| **参数推断** | JS 字段名→构造 API 参数；响应 JSON key→拼接到请求 |
| **IDOR 模式识别** | 含 ID/UUID 端点 → 顺序遍历 → 响应差异判断 |
| **GraphQL 内省** | 拉 schema → 找 dev/debug mutation → 实际调用 |
| **报错反推** | stack trace → 文件路径/DB 表名 → 构造利用 |
| **业务逻辑推断** | 理解流程 → 跳过步骤/改数值/并发 |

> 详见 `infra/agent_intelligence.md`

## 文件结构

```
hackprobe-main/
├── SKILL.md                    # 入口（本文件）
├── README.md                   # 快速入门 + 安装 + 环境变量
├── waves/
│   ├── wave0_preflight.md      # Pre-flight 威胁建模（目标分类）
│   ├── wave1_recon.md          # 侦察（3 子 wave + Host碰撞）
│   ├── wave2_deep.md           # 深层挖掘（条件激活）
│   ├── wave3_exploit.md        # 探针 + 信号 + 深度利用（核心）
│   └── wave4_report.md         # 报告（AskUserQuestion 确认 + REPORT.md）
├── probes/
│   ├── tier1_universal.md      # 12 通用探针（~15KB，永远加载）
│   ├── tier2_signal.md         # 25 信号驱动探针（~31KB，条件加载）
│   └── tier3_feedback.md       # 反馈式探针（~5KB，深度利用后触发）
├── infra/
│   ├── directory_setup.md      # 目录初始化 + heartbeat
│   ├── anti_patterns.md        # 纪律清单（20条 + MCP 策略 + 垃圾洞黑名单）
│   ├── shared_layer.md         # 共享数据层规范
│   ├── decision_gates.md       # Gate 1/2 决策
│   ├── signal_router.md        # 信号→技能映射 + 隐式框架检测
│   ├── failure_handling.md     # 超时/失败降级
│   ├── agent_intelligence.md   # LLM 推理能力指南
│   ├── oast_setup.md           # OAST 全生命周期
│   └── cleanup.md              # 归档清理
└── scripts/
    ├── discover_tools.sh       # 跨平台工具发现
    └── merge_results.sh        # 原子合并
```

## 覆盖率

| 维度 | 覆盖 |
|------|------|
| 侦察 | 子域名、端口、URL、技术栈、OSINT、域名情报、email 安全 |
| 自动化扫描 | nuclei safe tags、CVE 映射、密钥扫描、默认凭证、敏感文件 |
| 通用探针（永远跑） | SQLi、XSS、SSTI、CMDi、CORS、Open Redirect、HTTP Methods、CRLF、403 Bypass、IDOR、敏感文件、POST Body |
| 信号驱动探针 | SSRF、XXE、NoSQL、Deserialization(Java/PHP/.NET)、JWT、Type Juggling、Prototype Pollution、EL Injection、JNDI、LFI、Upload、GraphQL、Subdomain Takeover、Reset Bypass、Request Smuggling、Race Condition、Business Logic、Host Header、Cache Deception、CSP Bypass 等 |
| 深度利用 | 98 hack-skills 中命中的 10-20 个按需加载 |
| 报告 | 攻击链关联、CVSS 评分、业务影响、P0/P1/P2 优先级 |

## 执行约束

- **Wave 内子 wave 严格串行**，子 wave 内 Agent 并行
- **每个 Agent 写私有临时文件** `$TMP/<wave>_<id>_<output>.txt`
- **每子 wave 结束时** `merge_results.sh` 原子合并到 `_shared/`
- **超时降级**：关键路径 360s / 非关键 180s → 标记 skip → 不阻塞 pipeline
- **Gate 是硬屏障**：Gate 前所有 Agent done/skipped → Gate 决策 → 下一 Wave
- **静态站判定**：5 条全满足才是 static（Wave 0 确认），跳过 Wave 2 + Tier 2

## 与 hack-skills 的关系

hackprobe 是**执行引擎 + 探针层**，hack-skills 是**知识层**。

```
hackprobe:   发现攻击面 + 跑探针 + 命中→加载 hack-skills
hack-skills: 每个技能 200-1000 行深度 payload + bypass 矩阵 + per-DBMS/per-引擎专杀
```

路径: `.claude/skills/hack-skills/skills/<skill-name>/SKILL.md`
