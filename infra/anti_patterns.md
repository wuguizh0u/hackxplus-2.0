# Anti-Patterns — AI Agent 常见错误清单

> **每个 Wave 启动前必读。** 违反即浪费 token 和产生垃圾洞。

## 核心纪律

| # | DO | DON'T |
|---|-----|-------|
| 1 | 严格按 Wave 顺序，Wave 内 Agent 并行 | 跳过 Wave N 直接跑 Wave N+1 |
| 2 | trufflehog `--only-verified`，只报 API 验证通过的密钥 | 报告未验证的正则匹配 |
| 3 | Wayback 挖掘优先于主动扫描（IDOR 金矿） | 跳过互联网存档挖掘 |
| 4 | CORS: `Origin: https://evil.com` + credentials | 只用同源测 CORS |
| 5 | GraphQL: 狩猎 `dev*/debug*/test*/admin*` mutation | 内省完就停 |
| 6 | 按**业务影响**评级 | 报 20 个缺失 header 作为"20 个漏洞" |
| 7 | Nuclei: **仅 safe tags** | 不加 tag 过滤跑 nuclei |
| 8 | searchsploit: 只读，`-w` 获取 web 链接 | `searchsploit -m` 或 pipe 到 bash |
| 9 | 映射 product:version → CVE 用 OSV.dev API | 跳过映射直接搜 exploit |
| 10 | oneforall + 上下文感知自定义子域字典 | 只用静态字典 |
| 11 | 深目录爆破: dirsearch + 御剑（2 引擎） | 跑 4 个目录扫描器 |
| 12 | sqlmap: WAF 预检 → 被拦则跳过，写跟进建议 | 盲目跑 sqlmap 怼 WAF |
| 13 | 密码字典: 目标画像感知 ~200 候选，6-16 位 | 生成通用弱密码（123456, password） |
| 14 | 分层超时: 核心 Agent 360s, 轻量 180s | 让挂起的 Agent 阻塞 pipeline |
| 15 | 工具路径从 `$HACKPROBE_*` 变量取 | 硬编码路径 |
| 16 | `python3` 或 `python` 两个都试 | 硬编码 `python3` |
| 17 | 每个 Agent 写私有文件 `$TMP/<agent>_<output>.txt` | 多个 Agent 直接追写同一个文件 |
| 18 | Wave 结束时 merge 原子合并 | 边跑边读共享文件导致竞态 |
| 19 | 探针层永远跑，不管 Wave 1 信号 | 因为 Wave 1 没发现就跳过探针 |
| 20 | 信号路由只做补充，不做唯一判断依据 | 纯靠 Wave 1 信号决定测什么洞 |

## MCP 工具策略 — curl 是步兵，MCP 是特种兵

- **curl**：99% 请求，快、轻
- **Burp MCP**：仅 OOB Collaborator（盲 SSRF/XXE/SQLi）+ Repeater Tab（高危证据留底）
- **Chrome MCP**：仅浏览器渲染场景（SPA 注册/登录、DOM XSS 验证、CVSS≥8.0 链截图）

## 静态站判定 — SPA ≠ Static

5 条全满足才是 static：①可见文本>100字符 ②无 `<form>` ③无 XHR/fetch ④无 auth cookie ⑤确认静态生成器（Hugo/Jekyll/GitHub Pages）

| Profiled Type | Wave 2 | Wave 3 |
|---------------|--------|--------|
| static | SKIP | headers+CORS only |
| spa | FULL + JS 端点 | API fuzz 优先 |
| cms | FULL + CVE | CMS 专杀优先 |
| fintech | REDUCED | 手动 bypass 优先 |
| unknown | 正常 | 正常 |

## 垃圾洞黑名单 — 永不报告

CORS 无凭证 / Self-XSS / Sourcemap / 纯版本号 / TLS 警告
