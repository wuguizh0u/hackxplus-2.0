## **⚠️ 法律与合规声明**

本脚本仅用于授权环境的安全测试、漏洞挖掘与学术研究。使用者须遵守《网络安全法》及相关地方法规，严禁利用本工具进行未授权的网络入侵或数据窃取。因滥用产生的一切法律责任由使用者自行承担。



---

### 注意：

### 此skill终究是工具，只能辅助首轮全面辅助进行测试



### 使用前请先做两件事

**1.安装另一个开源skill**

​	**[yaklang/hack-skills: Helping AI Agent become an awesome practical hacker!](https://github.com/yaklang/hack-skills)**

**并确保放在这个路径  ~/.claude/skills/hack-skills**

**2.设置你本地的工具箱让它识别到**

**HACKPROBE_TOOL_BASE        主工具目录**

**HACKPROBE_TOOLS_ROOT	 其他工具目录**

**没区别 只要设置第一个就可以**



### 

# hackxplus

AI 驱动的黑盒渗透测试框架（Claude Code Skill + MCP Server 代码层）。编排 25+ 安全工具 + LLM 推理，覆盖 40+ 漏洞类型。探针扫盲点、AI 做推理、hack-skills 深利用。

## 项目架构（Skill 知识层 × MCP 代码层）

hackxplus 是**双层架构**: 不是纯 prompt 编排, 而是把"决策"与"执行/状态"分离。

```
┌──────────────────────────────────────────────┐
│  Skill 层 (决策知识)   waves/ probes/ infra/   │
│   · Wave 0-4 分阶段编排 + 双层决策门          │
│   · 50 探针 + 信号路由 + hack-skills 按需加载  │
│   · 隐式框架检测 20+ 规则                      │
└───────────────────┬──────────────────────────┘
                    │ MCP 工具调用
┌───────────────────▼──────────────────────────┐
│  server/ 代码层 (执行 + 管控)  ← ★ 项目化核心  │
│   · asset_store.py    SQLite 资产库(外部记忆)  │
│   · gate_chain.py     五层漏洞质量门禁(代码强制)│
│   · probe_engine.py   探针执行引擎(JSON 驱动)  │
│   · signal_router.py  信号→技能映射(代码化)    │
│   · browser.py        Playwright 流量/接口发现 │
│   · runner.py         自动续轮 + 恢复          │
└──────────────────────────────────────────────┘
```

**为什么是双层**: 探针是确定性执行(发请求+规则匹配), 不该花 LLM token;
状态外置到 SQLite(参考文章: 别依赖 Claude Code 自带 compact);
关键规则在代码层硬控制(五层门禁)而非只靠 prompt 约束。

### server/ 快速上手

```bash
# 1. 依赖
pip install "mcp[cli]" requests
# 2. 自测 (不依赖 mcp 库也能跑核心逻辑)
python server/mcp_server.py --self-test
# 3. 接入 Claude Code → 见 server/MCP_SETUP.md
```

接入后暴露 10 个 MCP 工具: `asset_get_asset_tree` / `asset_inject_endpoint` /
`asset_record_vuln`(触发五层门禁) / `probe_run` / `router_match` /
`gate_override_check` / `session_checkpoint` / `session_resume` ...

## 目录

- [项目架构](#项目架构skill-知识层--mcp-代码层)
- [快速开始](#快速开始)
- [架构概览](#架构概览)
- [安装与依赖](#安装与依赖)
- [工具发现机制](#工具发现机制)
- [自定义探针与脚本](#自定义探针与脚本)
- [探针引擎（48 Probes）](#探针引擎48-probes)
- [hack-skills 生态](#hack-skills-生态)
- [审计输出与目录结构](#审计输出与目录结构)
- [实时监控进度](#实时监控进度)
- [环境变量](#环境变量)
- [Token 消耗](#token-消耗)
- [平台兼容性](#平台兼容性)
- [设计原则](#设计原则)
- [贡献指南](#贡献指南)
- [License](#license)

---

## 快速开始

```bash
# 1. 克隆 hackprobe
git clone https://github.com/your-org/hackprobe.git
cd hackprobe

# 2. 克隆 hack-skills（98 个深度利用技能，独立仓库）
git clone https://github.com/your-org/hack-skills.git ~/.claude/skills/hack-skills
#    ↑ 放在 ~/.claude/skills/ 下，hackprobe 自动发现。不放这里也行——见下方说明。

# 3. 安装依赖（一次性）
bash install.sh

# 4. 注册为 Claude Code Skill
cp -r . ~/.claude/skills/hackprobe/

# 5. 运行
/hackprobe https://your-target.com

# 快速扫描（仅侦察，跳过深度利用）
export HACKPROBE_QUICK=1
/hackprobe https://target.com
```

**前置条件**：Go 1.21+、Python 3、Claude Code CLI。



### hack-skills 去哪了？为什么是独立仓库？

hackprobe 是**探针引擎 + 调度层**，hack-skills 是**知识层**（98 个漏洞的深度 payload、bypass 矩阵、每种 DBMS/框架的专杀手法）。两者独立发布——你可以只更新 hack-skills 而不动引擎。

**hack-skills 路径查找优先级**（hackprobe 自动按此顺序找）：

```
1. 环境变量 $HACKPROBE_SKILLS_DIR  （你显式指定）
2. ./hack-skills/skills/           （hackprobe 目录下的子目录）
3. ~/.claude/skills/hack-skills/skills/  （默认位置，推荐）
```

如果你放在其他位置，运行前 export 一下：

```bash
export HACKPROBE_SKILLS_DIR="/home/me/my-tools/hack-skills/skills"
/hackprobe https://target.com
```

> 没有 hack-skills 也能跑——Wave 1/2 侦察和 Wave 3 探针照常工作，只是探针命中后没有深度利用技能可加载，报告中会标注 "no hack-skills file"。建议还是下载以获得完整能力。

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

决策门是硬屏障—不通过不进入下一 Wave。
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

以下工具 hackprobe 会尝试调用，但 `install.sh` 不负责安装：

| 工具 | 用途 | 获取 |
|------|------|------|
| oneforall | 子域名收集套件 | github.com/shmilylty/OneForAll |
| URLFinder | JS 端点/API 提取 | github.com/pingc0y/URLFinder |
| 御剑 (yjdirscan) | 目录扫描 | 自行搜索 |
| ehole | 技术栈指纹 | github.com/EdgeSecurityTeam/EHole |
| tide / golin | 综合信息收集 | 自行搜索 |
| webpackscan | .map → JS 源码恢复 | 自行搜索 |
| bypass-403 | 403 绕过工具箱 | 自行搜索 |

> **缺失不报错** — hackprobe 静默降级，curl 手搓替代重型工具。仅关键路径工具缺失时标注。

---

## 工具发现机制

`hackprobe` 通过 `scripts/discover_tools.sh` 自动检测已安装的安全工具。

### 默认行为（开箱即用）

- **macOS/Linux**：直接使用 `PATH` 中的工具（通过 Homebrew/apt/go/pipx 安装）
- **Windows**：默认查找 `PATH` 中的工具；可通过环境变量指定便携工具目录

### 搜索优先级

每个工具按 5 级优先级查找：

```
1. $HACKPROBE_TOOL_BASE 下的子目录（gui_scan → gui_shouji → gui_other → gui_webshell）
2. $HACKPROBE_NMAP_HOME（独立 nmap 安装）
3. $HACKPROBE_TOOLS_ROOT（其他独立工具根目录）
4. 系统 $PATH
5. 常见安装位置（/usr/bin, /opt/homebrew/bin, ~/go/bin, ~/.local/bin）
```

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

# nmap 独立安装
export HACKPROBE_NMAP_HOME="C:/nmap"

# 其他独立工具目录
export HACKPROBE_TOOLS_ROOT="D:/standalone-tools"
```

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

**方法 3** — 在 `install.sh` 中注册。编辑 `install.sh` 第 191 行的 `TOOLS` 变量，追加工具名。

### 验证工具发现

```bash
source scripts/discover_tools.sh
# 输出示例:
#   ✅  nmap → /usr/bin/nmap
#   ✅  httpx → /home/user/go/bin/httpx
#   ⚠️  oneforall not found（非关键，继续）
```

---

## 自定义探针与脚本

### 添加自定义探针

编辑 `probes/tier2_signal.md`（信号驱动）或 `probes/tier1_universal.md`（通用），按格式追加：

```bash
### P51. 自定义检查（条件: Django 后端）

# 条件判断（不满足立即返回，不浪费请求）
if echo "$SIGNALS" | python3 -c "import sys,json;print(json.load(sys.stdin).get('tech',{}).get('framework',''))" 2>/dev/null | grep -qi "django"; then
  resp=$(curl -sk "${URL}/custom-endpoint/" --max-time 5)
  echo "$resp" | grep -qi "vulnerable-pattern" && \
    record_hit "P51" "my-exploit-skill" "Custom vuln: exposed config at ${URL}/custom-endpoint/"
fi
```

探针格式要求：条件注释 → 条件判断 → curl 探测 → `record_hit` 记录。

### 内置字典生成器

| 脚本 | 用途 | 示例 |
|------|------|------|
| `scripts/gen_custom_dirs.py` | 目标品牌→目录字典 | `python3 scripts/gen_custom_dirs.py "Example Corp" dirs.txt` |
| `scripts/gen_custom_subdomains.py` | 目标品牌→子域字典 | `python3 scripts/gen_custom_subdomains.py "example" subs.txt` |
| `scripts/gen_password_dict.py` | 目标画像→密码字典(~200候选) | `python3 scripts/gen_password_dict.py example.com --output pwds.txt` |
| `scripts/gen_deep_dicts.py` | 深层爆破字典 | `python3 scripts/gen_deep_dicts.py example.com` |

### 添加自定义 Wave / 脚本

在 `waves/` 下新建 `.md` 文件，按 `Preamble → Steps → bash/Python heredoc` 格式。在 `SKILL.md` 入口引用即可。

### 注册自定义 hack-skill

hack-skills 是独立仓库。在 hack-skills 目录的 `skills/` 下创建：

```
skills/my-exploit/
└── SKILL.md     # 格式: title → preconditions → payloads → cleanup
```

Wave 3 的 `signal_router.md` 自动发现新 skill 目录，无需注册到 hackprobe。

---

## 探针引擎（48 Probes）

### 三层懒加载

| Tier | 文件 | 大小 | 何时加载 | 数量 |
|------|------|------|---------|------|
| **Tier 1** | `tier1_universal.md` | ~16KB | 永远 | 12（P1-P12.5，无 P9） |
| **Tier 2** | `tier2_signal.md` | ~33KB | 非静态站 + signals.json 存在 | 36（P13-P50, 缺 P31/P32）|
| **Tier 3** | `tier3_feedback.md` | ~5KB | 深度利用完成后 | 10 触发规则 |

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

其余 20 个自带条件检查（XXE/LFI/文件上传/GraphQL/子域接管等），不满足立即返回。

### Tier 3 — 反馈式

深度利用输出出现新攻击面信号时追加对应技能，最多 1 轮不递归。



---

## hack-skills 生态

**98 个深度利用技能**，独立仓库（`hack-skills`），每个是独立 `SKILL.md`。探针命中才加载，未命中零 Token 开销。

### 安装

```bash
# 推荐：放在默认位置
git clone https://github.com/yaklang/hack-skills.git

# 或：放在 hackprobe 目录下
git clone https://github.com/yaklang/hack-skills.git ./hack-skills

# 或：任意位置 + 环境变量
git clone https://github.com/yaklang/hack-skills.git /opt/hack-skills
export HACKPROBE_SKILLS_DIR="/opt/hack-skills/skills"
```

### 技能列表

| 类别 | 技能 |
|------|------|
| 注入 | sqli, ssti, cmdi, nosql, xslt |
| 认证 | authbypass, jwt-oauth, oauth2, api-auth |
| SSRF/LFI | ssrf, path-traversal-lfi, lfi-to-rce |
| 反序列化 | java-deser, php-deser, ysoserial |
| CSRF/CORS | csrf, cors, clickjacking |
| XXE | xxe, xxe-oob |
| 上传 | upload-insecure, upload-to-rce, svg-exploit |
| GraphQL/API | graphql, api-bola, api-recon |
| 缓存/CDN | cache-deception, cache-poisoning, cdn-origin |
| 业务逻辑 | business-logic, race-condition, payment-bypass |
| 子域/DNS | subdomain-takeover, dns-rebinding |
| Email | email-injection, email-spoofing |
| 客户端 | electron-security, prototype-pollution, android-pentest, ios-pentest |

> 完整列表见 hack-skills 仓库 `skills/` 目录。

---

## 审计输出与目录结构

每次审计在当前目录创建以目标域名命名的文件夹：

```
example.com/
├── _work/                          ← ❶ 中间数据层
│   ├── progress.json               │   ├── shared/                     # 共享数据层（merge 后）
│   │   ├── target_profile.json     # Pre-flight 目标画像
│   │   ├── signals.json            # 信号→技能映射结果
│   │   ├── httpx.json              # 技术栈指纹
│   │   ├── urls_all.json           # 全量 URL
│   │   ├── ports.json              # 端口扫描
│   │   ├── auth_token.json         # 自动注册/手动输入 token（Step 0）
│   │   ├── oast.json               # OAST 域名状态
│   │   ├── oast_callbacks.json     # OAST 回调记录
│   │   ├── probe_hits.json         # 合并后探针命中
│   │   ├── exploitation_plan.json  # 深度利用清单
│   │   └── decisions/              # Gate 决策记录(gate1.md/gate2.md)
│   ├── 04_*.md                     # 深度利用输出（每 skill 一个文件）
│   └── tmp_archive_*.tar.gz        # 审计结束自动归档
│
├── _audit_log/                     ← ❷ 审计透明日志
│   ├── heartbeat.log               # 时间线 + 每步状态
│   ├── agent_logs/                 # 每个 Agent 实时日志
│   ├── tool_raw/                   # 工具原始输出
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

# 某个 Agent 详细日志
cat example.com/_audit_log/agent_logs/3_tier1_probes.log

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

## 平台兼容性

| 平台 | 状态 | 备注 |
|------|------|------|
| macOS | ✅ 完整 | Homebrew |
| Linux | ✅ 完整 | apt/go/pipx |
| Windows | ✅ 支持 | Git Bash/MSYS2 + 便携工具目录 |

---

## 设计原则

1. **探针贱，技能贵** — 48 探针永远跑，98 hack-skills 命中才加载，未命中零 Token 开销
2. **信号驱动** — 技术栈信号决定注入/反序列化/框架特定攻击面；隐式框架检测 20+ 规则补 Server 头缺失
3. **不依赖 Wave 1 完美** — Tier 1 通用探针兜底
4. **curl 做 99%** — 重型工具（sqlmap/nuclei）只在确认值得用时调用
5. **共享数据层** — httpx 一次探测，全 Agent 复用，原子 merge 防竞态

### 强制过滤（audit-rules）

以下**永不报告**：CORS 无凭证、Self-XSS、Sourcemap、纯版本号、TLS 警告。

---

## 贡献指南

两个仓库独立维护，请往对应仓库提 PR：

| 想贡献的东西 | 仓库 |
|-------------|------|
| 新探针、Wave 逻辑、infra、脚本、README | **hackxplus**（本仓库） |
| 新漏洞深度利用技能、payload 库、bypass 矩阵 | **hack-skills**（独立仓库） |

### 提交流程
1. Fork → 分支 → PR
2. 探针贡献：`probes/tier2_signal.md`（条件驱动）或 `tier1_universal.md`（通用），3-8 行，独立函数，不满足立即 return
3. hack-skill 贡献：往 hack-skills 仓库提 PR，在 `skills/<name>/SKILL.md`，格式 `title → preconditions → payloads → cleanup`
4. 脚本贡献：`scripts/`，给可执行权限

### 探针格式
```bash
### Pxx. 名称（条件: xxx）

# 条件判断
[条件不满足] && return

# curl 探测
resp=$(curl -sk "${URL}/target" --max-time 5)
echo "$resp" | grep -q "hit-pattern" && \
  record_hit "Pxx" "skill-name" "evidence"
```

---

## License

MIT © hackprobe contributors

---

## 致谢

**github：yaklang团队[yaklang.io Project](https://github.com/yaklang)、nuromirzak师傅https://github.com/nuromirzak**

**@青鸾sec师傅**

以及[ProjectDiscovery](https://projectdiscovery.io/) 工具套件（subfinder, httpx, nuclei, naabu, katana, dnsx, interactsh）、[sqlmap](https://sqlmap.org/)、[dalfox](https://github.com/hahwul/dalfox)、[ffuf](https://github.com/ffuf/ffuf)、[OneForAll](https://github.com/shmilylty/OneForAll)、[URLFinder](https://github.com/pingc0y/URLFinder) 及 Claude Code 社区。