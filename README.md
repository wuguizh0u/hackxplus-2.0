## **⚠️ 法律与合规声明**

本框架仅用于**授权环境**的安全测试、漏洞挖掘与学术研究。使用者须遵守《网络安全法》及相关地方法规，严禁利用本工具进行未授权的网络入侵或数据窃取。因滥用产生的一切法律责任由使用者自行承担。

---

# hackxplus 2.0

**AI 驱动的黑盒渗透测试 Agent 系统**（Claude Code Skill + MCP Server 代码层双层架构）。

编排 25+ 安全工具 + LLM 推理，覆盖 40+ 漏洞类型。从"给一个 URL"到"漏洞报告"全流程自主：侦察 → 漏洞探测 → 深度利用 → 攻击链报告。

> **注意**: skill 入口名 (`name: hackprobe`)、内部函数 (`init_hackprobe_dir`) 沿用历史命名, 项目仓库名为 hackxplus。二者是同一项目。

## 项目架构（Skill 知识层 × MCP 代码层）

hackxplus 是**双层架构**：不是纯 prompt 编排, 而是把"决策"与"执行/状态"分离。

```
┌──────────────────────────────────────────────┐
│  Skill 层 (决策知识)   waves/ probes/ infra/  │
│   · Wave 0-4 分阶段编排 + 双层决策门          │
│   · 50 探针 + 信号路由 + hack-skills 按需加载  │
│   · 隐式框架检测 20+ 规则                      │
└───────────────────┬──────────────────────────┘
                    │ MCP 工具调用 (11 个)
┌───────────────────▼──────────────────────────┐
│  server/ 代码层 (执行 + 管控)  ← ★ 项目化核心  │
│   · asset_store.py    SQLite 资产库(外部记忆)  │
│   · gate_chain.py     五层漏洞质量门禁(代码强制)│
│   · probe_engine.py   探针执行引擎(JSON 驱动)  │
│   · signal_router.py  信号→技能映射(代码化)    │
│   · browser.py        Playwright 流量/接口发现 │
│   · runner.py         自动续轮 + 恢复          │
│   · mcp_server.py     MCP Server 入口 (11 工具)│
└──────────────────────────────────────────────┘
```

**为什么是双层**：
- **探针是确定性执行**（发请求+规则匹配），不该花 LLM token → 代码化
- **状态外置到 SQLite**，不依赖对话上下文 → `asset_store.py`
- **关键规则代码层硬控制**（五层门禁），不靠 prompt 自觉 → `gate_chain.py`

## Agent 如何工作

### 工具调用链路（Agent 怎么知道调哪个工具）

```
Skill 层 (Wave 编排)          ── 给 LLM 的指令: 先侦察→再决策→再探测→再利用
        │  LLM 推理: "该记录漏洞了" → 读工具描述
        ▼
MCP 工具清单 (tools/list)     ── Claude Code 把 11 个工具(名称+参数schema+描述)注入上下文
        │  按需调用
        ▼
server/ 代码层                ── 工具内部执行真实逻辑(发请求/存库/门禁)
```

三层回答"agent 怎么知道":
1. **有哪些工具** → MCP `tools/list` 把 11 个工具注入 LLM 上下文，agent 天然"看得到"
2. **该用哪个** → 读工具描述 + LLM 推理（"记录漏洞"→ `asset_record_vuln`）
3. **按什么顺序** → Skill 层 Wave 编排告诉 agent 流程节奏

> **关键区分**: agent 调用的是封装好的 MCP 工具（`asset_`/`probe_`/`router_`），
> 不是直接跑 curl。curl 请求被封装在探针引擎内部——agent 只做"判断调哪个工具"。

### 可靠性设计（幻觉抑制 / 上下文管理 / 可追溯性）

| 设计目标 | 实现机制 |
|---|---|
| **AI 幻觉抑制** | ① No PoC = 不存在（无复现证据不算漏洞）② 20 分钟规则（单端点无突破就换攻击面）③ SSTI 双重确认（`{{7*7}}`=49 后再 `{{9*9}}`=81 防巧合）④ 代码层五层门禁 |
| **上下文爆炸治理** | ① 探针三层懒加载（Tier1 永远跑/Tier2 信号激活/Tier3 反馈，静态站省 ~31KB）② 状态外置 SQLite（上下文不存状态）③ 自动续轮（50% 阈值开新 Session） |
| **可追溯性** | ① 三目录审计（`_work/` 进度 + `_audit_log/` 心跳日志 + `_report/` 证据）② 每个 Agent 写私有文件 + heartbeat ③ 报告带原始 HTTP 证据 |

---

## 目录

- [Agent 如何工作](#agent-如何工作)
- [快速开始](#快速开始)
- [server/ 代码层](#server-代码层)
- [架构概览](#架构概览)
- [安装与依赖](#安装与依赖)
- [探针引擎](#探针引擎)
- [hack-skills 生态](#hack-skills-生态)
- [环境变量](#环境变量)
- [Token 消耗](#token-消耗)
- [设计原则](#设计原则)
- [贡献指南](#贡献指南)
- [License](#license)

---

## 快速开始

```bash
# 1. 克隆本仓库
git clone https://github.com/wuguizh0u/hackxplus-2.0.git
cd hackxplus

# 2. 克隆 hack-skills（98 个深度利用技能，独立仓库）
git clone https://github.com/yaklang/hack-skills.git ~/.claude/skills/hack-skills
#    ↑ 放在 ~/.claude/skills/ 下，框架自动发现

# 3. 安装依赖（一次性）
bash install.sh

# 4. 注册为 Claude Code Skill
cp -r . ~/.claude/skills/hackxplus/

# 5. 运行
/hackxplus https://your-target.com

# 快速扫描（仅侦察，跳过深度利用）
export HACKPROBE_QUICK=1
/hackxplus https://target.com
```

**前置条件**：Go 1.21+、Python 3、Claude Code CLI。

---

## server/ 代码层

server/ 是 2.0 新增的**工程层**，把 skill 层的关键逻辑从"prompt 约束"升级为"代码实现"。

### 快速上手

```bash
# 1. 依赖（mcp 2.x, requests; playwright 可选）
pip install "mcp[cli]" requests

# 2. 自测（不依赖 mcp 库也能跑核心逻辑）
python server/mcp_server.py --self-test

# 3. 接入 Claude Code → 见 server/MCP_SETUP.md
```

### 模块清单

| 模块 | 职责 |
|---|---|
| `asset_store.py` | SQLite 资产库: endpoints/coverage/credentials/traffic/vulns/sessions; 资产树 JSON 一次调用恢复全部状态 |
| `gate_chain.py` | 五层漏洞质量门禁: 垃圾洞拦截/否定检测/低危黑名单/IDOR 危害校验/去重 |
| `probe_engine.py` | 探针执行引擎: 读 JSON 配置发请求, 结构化输出 probe_hits |
| `signal_router.py` | 信号→技能映射: 技术栈/攻击面/基础设施/反馈 → 技能加载清单 |
| `browser.py` | Playwright 封装: 深度探索/流量捕获/接口发现; 无 playwright 降级纯 HTTP |
| `runner.py` | 自动续轮: 上下文阈值 50% → 新 Session → 从 pending 端点恢复 |
| `mcp_server.py` | MCP Server 入口: 11 个工具, mcp 2.0 lowlevel API |

### MCP 工具

接入后暴露 11 个 MCP 工具：

| 工具 | 作用 |
|---|---|
| `asset_create_target` | 创建目标 (返回 target_id) |
| `asset_get_asset_tree` | 恢复完整渗透状态 (续轮第一指令) |
| `asset_inject_endpoint` | 注入新发现的接口 |
| `asset_annotate_endpoint` | 接口风险标注 |
| `asset_record_vuln` | 漏洞入库 (触发五层门禁) |
| `asset_update_coverage` | 更新覆盖矩阵 |
| `probe_run` | 执行探针 (tier 1/2/3) |
| `router_match` | 信号→技能映射 |
| `gate_override_check` | 决策门覆写检测 (单向放宽) |
| `session_checkpoint` | 写续轮点 |
| `session_resume` | 恢复 pending 端点 |

### 五层漏洞质量门禁

漏洞入库前强制过 5 层代码门禁，把"宁可错报"的 AI 倾向压到代码层外：

1. **垃圾洞标题拦截** — CORS / 安全头缺失 / Cookie 属性 / 点击劫持
2. **描述否定检测** — "not a vulnerability" / "expected behavior"
3. **低价值类型黑名单** — self-xss / sourcemap / version-disclosure
4. **IDOR 危害校验** — 越权必须证明访问了非授权数据
5. **相同漏洞去重** — 同端点+同类型只入第一条

---

## 架构概览

```
audit-rules（前置纪律，每次必调）
    ↓
Wave 0 → Pre-flight 威胁建模（10-15s）
    ├── 首页特征提取（curl → title/form/SPA）
    ├── 技术栈指纹（httpx tech-detect）
    └── DNS/CDN/WAF 探测 → target_profile.json
    ↓
Wave 1 → 侦察与攻击面发现（3 子 wave 串行，10 Agent）
    ├── 1a: 4 Agent 并行（OSINT/子域/端口/域名）+ A5 Host 碰撞
    ├── 1b: 3 Agent 并行（技术栈/URL 收集/密钥泄漏）
    └── 1c: 3 Agent 并行（默认凭证/敏感文件/SSL 审计）
    ↓
Gate 1 → 6 问决策（强 WAF？静态站？API 重？有注册？…）
    ↓
Wave 2 → 深层挖掘（条件激活，低价值目标整 wave 跳过）
    ├── 深层子域 / 目录爆破 / JS 端点提取
    ├── 密码爆破 / CVE 映射
    └── Agent Intelligence: JS Bundle 逆向 / 参数推断
    ↓
Gate 2 → 4 问决策（新资产？弱口令？自动注册？WAF 跳过？）
    ↓
Wave 3 → 探针 + 信号路由 + 深度利用（核心）
    ├── Step 0: 认证获取（多通道：curl→Chrome MCP→手动→降级，5min 超时绝不阻塞）
    ├── OAST 自动启动（interactsh-client）
    ├── Tier 1: 12 通用探针（永远跑，~85s）
    ├── Tier 2: 36 信号驱动探针（按技术栈条件加载，静态站整层跳过）
    ├── Tier 3: 反馈探针（深度利用时按需触发，1 轮不递归）
    ├── 隐式框架检测（20+ 规则，Cookie/错误页/HTML 签名推断技术栈）
    ├── 信号→技能路由匹配
    └── 按需加载 hack-skills → 深度利用
    ↓
Wave 4 → AI 编排报告
    ├── 攻击链关联 + CVSS 评分 + 业务影响
    └── 生成 REPORT.md
    ↓
Cleanup → 归档临时文件 + 安全清理
```

### 决策门

| Gate | 触发点 | 决策内容 | 输出 |
|------|--------|---------|------|
| Gate 1 | Wave 1 后 | 强 WAF？纯静态站？API/GraphQL？注册入口？高价值子域？ | `_work/shared/decisions/gate1.json` + `gate1.md` |
| Gate 2 | Wave 2 后 | 新深层资产？弱口令命中？自动注册？WAF 跳过？ | `_work/shared/decisions/gate2.json` + `gate2.md` |

决策门是硬屏障 — 不通过不进入下一 Wave。

---

## 安装与依赖

### 一键安装

```bash
bash install.sh
```

自动安装以下工具（按平台选择 Homebrew / apt / go / pipx）：

| 类别 | 工具 | 安装方式 |
|------|------|---------|
| Go | subfinder, dnsx, httpx, katana, naabu, nuclei, dalfox, ffuf, gau, waybackurls, gf, qsreplace, anew, subzy, crlfuzz, interactsh-client | `go install` |
| Python | uro, s3scanner, wafw00f, theHarvester, arjun, jwt_tool | pipx / pip3 |
| System | nmap, sqlmap, testssl, feroxbuster, trufflehog, amass, exploitdb | Homebrew(brew) / Linux(apt) |

安装完成后自动运行验证，打印 `OK/MISSING` 清单。

### 本地工具（需自行获取）

以下工具框架会尝试调用，但 `install.sh` 不负责安装：

| 工具 | 用途 | 获取 |
|------|------|------|
| oneforall | 子域名收集套件 | github.com/shmilylty/OneForAll |
| URLFinder | JS 端点/API 提取 | github.com/pingc0y/URLFinder |
| 御剑 (yjdirscan) | 目录扫描 | 自行搜索 |
| ehole | 技术栈指纹 | github.com/EdgeSecurityTeam/EHole |
| tide / golin | 综合信息收集 | 自行搜索 |
| webpackscan | .map → JS 源码恢复 | 自行搜索 |
| bypass-403 | 403 绕过工具箱 | 自行搜索 |

> **缺失不报错** — 框架静默降级，curl 手搓替代重型工具。仅关键路径工具缺失时标注。

---

## 工具发现机制

框架通过 `scripts/discover_tools.sh` 自动检测已安装的安全工具。

### 默认行为（开箱即用）

- **macOS/Linux**：直接使用 `PATH` 中的工具（通过 Homebrew/apt/go/pipx 安装）
- **Windows**：默认查找 `PATH` 中的工具；可通过环境变量指定便携工具目录

### 搜索优先级

每个工具按 3 级优先级查找，**先命中先返回**：

```
1. 系统 $PATH
2. $HACKPROBE_TOOL_BASE 目录（递归，深度由 HACKPROBE_TOOL_MAXDEPTH 控制，默认 3）
3. 常见安装位置（/usr/bin, /usr/local/bin, /opt/homebrew/bin, ~/go/bin, ~/.local/bin, ~/bin）
```

> 命中后会跑**同名异工具校验**，已知两个工具会撞名：
>
> | 工具 | 真身 | 冒牌 | 判据 |
> |---|---|---|---|
> | `httpx` | ProjectDiscovery httpx（探测） | Python `httpx` HTTP 客户端 | 帮助含 `-json` |
> | `xray` | 长亭 xray（扫描器） | v2ray 代理套件的 `xray.exe` | 含 `Penetrates Everything` 即否决 |
>
> 冒牌货会被跳过并打印 `[skip]` 提示，继续往下找；校验不通过**不算命中**。
>
> ⚠️ 校验前会先做**可执行性预检**。因为执行失败时 shell 报错形如
> `<path>: Permission denied` —— **path 里就含工具名**，会让 `*xray*` 这类
> 特征匹配被自身路径污染而误判通过。跑不起来的直接否决，不进特征匹配。

### 高级定制（Windows 便携工具用户）

```powershell
# PowerShell（临时生效）
$env:HACKPROBE_TOOL_BASE = "C:/MyPortableTools"

# 或永久设置（系统环境变量）
[Environment]::SetEnvironmentVariable("HACKPROBE_TOOL_BASE", "C:/MyPortableTools", "User")
```

```bash
# Git Bash / MSYS2
export HACKPROBE_TOOL_BASE="C:/MyPortableTools"
```

**两个可调项：**

```bash
# ① 工具埋得深时调大搜索深度（默认 3，每多一层会多遍历文件，但通常仍是亚秒级）
export HACKPROBE_TOOL_MAXDEPTH=5

# ② 工具分散在多个目录时用分隔符并列
#    Windows 用 ';'，Unix 用 ':'
export HACKPROBE_TOOL_BASE="D:/1渗透tools/fox集成工具/tools;D:/standalone-tools"
```

**建议：把 BASE 指到真正放工具的目录，而不是整个便携包根目录。** 例如
`D:/1渗透tools` 下的工具埋在 `fox集成工具/tools/gui_scan/` 里（第 4 层），
直接指向 `D:/1渗透tools/fox集成工具/tools` 能让默认深度 3 正好够到，
同时避免扫到集成包里重复的副本和内置 runtime。

> 另外两个变量不由本脚本处理，但部分 wave 会直接引用：
> `$HACKPROBE_TOOLS_ROOT`（如 `waves/wave1_recon.md` 用它定位 hostscan）。
> `$HACKPROBE_NMAP_HOME` 曾被文档提及，但**代码中并未实现**。

### 添加自定义工具

**方法 1** — 放入便携目录自动发现：

```bash
cp my-scanner.exe $HACKPROBE_TOOL_BASE
```

探针中通过环境变量引用：`$HACKPROBE_MY_SCANNER`（工具名大写，`-` 变 `_`）。

**方法 2** — 放入 `$PATH`：

```bash
cp my-scanner /usr/local/bin/
```

**方法 3** — 在 `install.sh` 中注册。编辑 `install.sh` 的 `TOOLS` 变量，追加工具名。

---

## 探针引擎

### 三层懒加载

| Tier | 文件 | 大小 | 何时加载 | 数量 |
|------|------|------|---------|------|
| **Tier 1** | `tier1_universal.md` | ~16KB | 永远 | 13（P1-P12.5） |
| **Tier 2** | `tier2_signal.md` | ~33KB | 非静态站 + signals.json 存在 | 35（P13-P50）|
| **Tier 3** | `tier3_feedback.md` | ~5KB | 深度利用完成后 | 触发规则 |

静态站仅加载 ~21KB，节省 ~31KB 上下文（~10K tokens）。

### Tier 1 — 通用探针

| 编号 | 类别 | 手法 |
|------|------|------|
| P1 | SQLi | Boolean blind(diff>10%) + Time-based(SLEEP/pg_sleep) + OOB |
| P2 | XSS | `<script>alert(1)</script>` 反射检测 |
| P3 | SSTI | 7 引擎 polyglot + 双重确认(7×7=49 AND 9×9=81) |
| P4 | CMDi | 5 payload: `;id` `\|id` `` `id` `` `$(id)` `&id` |
| P5 | CORS | 3 向量: null origin / 任意子域+credentials / wildcard+creds |
| P6 | Open Redirect | `//evil.com` + URL 编码变体 |
| P7 | Sensitive Files | 20+ 常见敏感文件(.git/HEAD, .env, backup 等) |
| P8 | HTTP Methods | PUT/DELETE/PATCH + PUT 文件写入探针 |
| P10 | CRLF | `%0d%0aSet-Cookie:crlf=1` |
| P11 | 403 Bypass | 6 头绕过 + 7 种路径 fuzzing |
| P12 | IDOR | 数字 ID 顺序遍历 + UUID 替换 |
| P12.5 | POST Body | JSON body SQLi/SSTI/NoSQL/HPP 统一探针 |

### Tier 2 — 信号驱动（代表性）

- **有 URL 参数** → SSRF Metadata(AWS/GCP/Azure/阿里云) + 协议走私
- **Java 后端** → 反序列化 + EL 注入(SpEL/OGNL) + JNDI(Log4j)
- **PHP 后端** → 反序列化 + Type Juggling
- **JSON API** → NoSQL + Prototype Pollution + 隐藏参数爆破
- **有 JWT** → alg:none / RS→HS / kid 路径穿越 / jku 注入
- **有登录口** → 密码重置绕过(Host header 投毒)
- **有支付** → 价格/角色参数篡改

其余探针自带条件检查（XXE/LFI/文件上传/GraphQL/子域接管等），不满足立即返回。

### Tier 3 — 反馈式

深度利用输出出现新攻击面信号时追加对应技能，最多 1 轮不递归。

---

## hack-skills 生态

**98 个深度利用技能**，独立仓库（`hack-skills`），每个是独立 `SKILL.md`。探针命中才加载，未命中零 Token 开销。

### 安装

```bash
# 推荐：放在默认位置
git clone https://github.com/yaklang/hack-skills.git

# 或：放在框架目录下
git clone https://github.com/yaklang/hack-skills.git ./hack-skills

# 或：任意位置 + 环境变量
git clone https://github.com/yaklang/hack-skills.git /opt/hack-skills
export HACKPROBE_SKILLS_DIR="/opt/hack-skills/skills"
```

> 没有 hack-skills 也能跑 — Wave 1/2 侦察和 Wave 3 探针照常工作，只是探针命中后没有深度利用技能可加载，报告中会标注 "no hack-skills file"。建议还是下载以获得完整能力。

---

## 审计输出与目录结构

每次审计在当前目录创建以目标域名命名的文件夹：

```
example.com/
├── _work/                          ← ❶ 中间数据层
│   ├── progress.json               # 进度
│   ├── shared/                     # 共享数据层（merge 后）
│   │   ├── target_profile.json     # Pre-flight 目标画像
│   │   ├── signals.json            # 信号→技能映射结果
│   │   ├── httpx.json              # 技术栈指纹
│   │   ├── urls_all.json           # 全量 URL
│   │   ├── ports.json              # 端口扫描
│   │   ├── auth_tokens.json        # per-host 凭据（Step 0，按 host 分键）
│   │   ├── oast.json               # OAST 域名状态
│   │   ├── oast_callbacks.json     # OAST 回调记录
│   │   ├── probe_hits.json         # 合并后探针命中
│   │   └── decisions/              # Gate 决策记录(gate1.md/gate2.md)
│   └── tmp_archive_*.tar.gz        # 审计结束自动归档
│
├── _audit_log/                     ← ❷ 审计透明日志
│   ├── heartbeat.log               # 时间线 + 每步状态
│   ├── agent_logs/                 # 每个 Agent 实时日志
│   └── failures.log                # 失败/超时摘要
│
└── _report/                        ← ❸ 最终报告
    ├── REPORT.md                   # 摘要→攻击面→漏洞列表→攻击链→修复
    ├── screenshots/                # Chrome MCP 截图
    └── http_evidence/              # 原始 HTTP 证据
```

### 实时监控进度

```bash
# 心跳日志 — 所有 Agent 实时状态
tail -f example.com/_audit_log/heartbeat.log

# 失败摘要
cat example.com/_audit_log/failures.log
```

---

## 环境变量

| 变量 | 用途 | 默认值 |
|------|------|--------|
| `HACKPROBE_SKILLS_DIR` | hack-skills 技能路径（指向 `skills/` 子目录） | `~/.claude/skills/hack-skills/skills` |
| `HACKPROBE_TOOL_BASE` | 便携工具根目录 | 空（需用户自行设置） |
| `HACKPROBE_NMAP_HOME` | 独立 nmap 目录 | 空（需用户自行设置） |
| `HACKPROBE_TOOLS_ROOT` | 其他独立工具目录 | 空（需用户自行设置） |
| `HACKPROBE_QUICK` | 快速扫描模式（跳过 Wave 2-3） | 未设置（全量） |
| `WORK_ROOT` | 审计输出根目录 | `$(pwd)/<目标域名>` |

> `WORK_ROOT`/`TMP`/`SHARED`/`AUDIT_LOG`/`REPORT_DIR` 由初始化脚本自动设置，通常无需手动指定。

---

## Token 消耗

| 场景 | Token | 费用(Opus 4) |
|------|-------|-------------|
| 静态站 | ~38K | ~$0.50 |
| 全量(正常 CMS) | ~93K | ~$1.40 |
| 全量+深度利用命中多 | ~120K | ~$1.80 |

优化措施：Probes 按 tier 懒加载（静态站省 ~17K tokens，含 Tier2 ~10K + failure_handling ~4.7K + Tier3 ~2K）、hack-skills 命中才加载。

---

## 设计原则

1. **探针贱，技能贵** — 探针永远跑，98 hack-skills 命中才加载，未命中零 Token 开销
2. **信号驱动** — 技术栈信号决定注入/反序列化/框架特定攻击面；隐式框架检测 20+ 规则补 Server 头缺失
3. **不依赖 Wave 1 完美** — Tier 1 通用探针兜底
4. **curl 做 99%** — 重型工具（sqlmap/nuclei）只在确认值得用时调用
5. **共享数据层** — httpx 一次探测，全 Agent 复用，原子 merge 防竞态
6. **代码层兜底优于 Prompt 约束** — 关键规则（垃圾洞/去重/状态）在代码层硬控制

### 强制过滤（audit-rules）

以下**永不报告**：CORS 无凭证、Self-XSS、Sourcemap、纯版本号、TLS 警告。

---

## 贡献指南

| 想贡献的东西 | 仓库 |
|-------------|------|
| 新探针、Wave 逻辑、infra、脚本、README | **hackxplus**（本仓库） |
| server/ 代码层 (MCP/门禁/探针引擎) | **hackxplus**（本仓库） |
| 新漏洞深度利用技能、payload 库、bypass 矩阵 | **hack-skills**（独立仓库） |

### 提交流程
1. Fork → 分支 → PR
2. 探针贡献：`probes/tier2_signal.md`（条件驱动）或 `tier1_universal.md`（通用），3-8 行，独立函数，不满足立即 return
3. server 贡献：`server/` 下，带 `--self-test` 自测
4. hack-skill 贡献：往 hack-skills 仓库提 PR，在 `skills/<name>/SKILL.md`，格式 `title → preconditions → payloads → cleanup`

---

## License

MIT © hackxplus contributors

---

## 致谢

**github：yaklang团队[yaklang.io Project](https://github.com/yaklang)、nuromirzak师傅https://github.com/nuromirzak**

**@青鸾sec师傅**

以及[ProjectDiscovery](https://projectdiscovery.io/) 工具套件（subfinder, httpx, nuclei, naabu, katana, dnsx, interactsh）、[sqlmap](https://sqlmap.org/)、[dalfox](https://github.com/hahwul/dalfox)、[ffuf](https://github.com/ffuf/ffuf)、[OneForAll](https://github.com/shmilylty/OneForAll)、[URLFinder](https://github.com/pingc0y/URLFinder) 及 Claude Code 社区。
