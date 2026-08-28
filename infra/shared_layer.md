# Shared Data Layer — 共享数据层规范

所有 Wave 产出写入结构化数据到 `results/_shared/`。下游消费者读 JSON，不复探。

## 目录结构

```
<target_name>/                     ← 根目录（在当前路径下，以目标域名/IP 命名）
│
├── _work/                         ← 中间文件
│   ├── tmp/                       # Agent 私有临时文件
│   └── shared/                    # 共享数据层（merge 后写入）
│       ├── target_profile.json    # Wave 0 — 目标类型画像
│       ├── httpx.json             # httpx -json — HTTP 层唯一来源
│       ├── ports.json             # {tcp: {"80": {"service":"http","version":"nginx 1.18"},...}}
│       ├── techstack.json         # {frameworks:[], servers:[], cms:[], services:[], signals:[]}
│       ├── urls_all.json          # [{url, source, params:[], has_login:bool}, ...]
│       ├── subs_all.json          # [{subdomain, ip, http_status, https_status}, ...]
│       ├── hostcollision.json     # Host 碰撞结果
│       ├── fragile_subs.json      # 脆弱子域标记
│       ├── auth_token.json        # {token, type, cookie, auth_method}
│       ├── signals.json           # 信号提取结果 + matched_skills
│       ├── probe_hits.json        # 探针命中结果
│       ├── exploitation_plan.json # 去重合并后的利用计划
│       ├── tier3_escalations.json # Tier 3 反馈追加的技能
│       ├── failures.json          # 超时/失败记录
│       ├── partial/               # 超时 Agent 的部分数据保全
│       └── decisions/
│           ├── gate1.json / gate1.md
│           ├── gate2.json / gate2.md
│
├── _audit_log/                    ← 审计透明日志
│   ├── heartbeat.log              # 时间线 + 完成状态
│   ├── agent_logs/                # 每个 Agent 的实时输出
│   │   ├── 1a_a1_osint.log
│   │   ├── 1a_a2_subdomains.log
│   │   └── ...
│   └── failures.log               # 失败摘要（人类可读）
│
└── _report/                       ← 漏洞报告
    ├── REPORT.md
    ├── screenshots/
    └── http_evidence/
```

## 核心规则

1. **httpx 只跑一次**，输出 `-json` 到 `_shared/httpx.json`。所有下游 Agent 读这个文件，不复 probe。
2. **每个 Agent 写私有临时文件** `results/tmp/<wave>_<agent>_<output>.txt`，**绝不直接写 `_shared/`**。
3. **每子 Wave 结束时**，调用 `scripts/merge_results.sh` 原子合并私有文件到 `_shared/`。
4. **合并完成后**，所有 Agent 只读 `_shared/*.json` 作为 truth source。
5. **决策 Gate 必须在判断前读完整的 `_shared/`**，不允许基于不完整数据决策。

## 合并流程

```bash
# Wave 1a 完成后 → merge
bash scripts/merge_results.sh --wave 1a
# → 合并 results/tmp/1a_*.txt → _shared/subs_all.json, _shared/ports.json

# Wave 1b 完成后 → merge  
bash scripts/merge_results.sh --wave 1b
# → 追加 urls、techstack

# Wave 1c 完成后 → merge
bash scripts/merge_results.sh --wave 1c
# → 追加 secrets、ssl、defaults
```

## signals.json 架构（核心新增）

```json
{
  "tech": {
    "language": "java",            // null if unknown
    "backend": "Spring Boot 2.6",
    "server": "Apache Tomcat/9.0",
    "frontend": "Next.js",
    "cms": null,
    "template_engine": "Thymeleaf", // null if no evidence
    "database": ["MySQL", "Redis"]
  },
  "attack_surface": {
    "has_login": true,
    "has_register": true,
    "has_upload": false,
    "has_graphql": true,
    "has_xml_api": false,
    "has_json_api": true,
    "has_payment": true,
    "has_websocket": false,
    "has_cors_vuln": null,        // null = not tested yet
    "has_jwt": true,
    "has_multitenant": false,
    "cdn_present": "Cloudflare",
    "waf_present": "Cloudflare"
  },
  "infra": {
    "cname_to_cloud": ["cdn.target.com → AWS CloudFront"],
    "exposed_actuator": true,
    "scm_exposed": false,
    "open_ports": [80, 443, 3306, 6379, 8080],
    "email_security": {"spf": true, "dmarc": false, "dkim": false}
  }
}
```

## 共享读协议

```bash
# 任何 Agent 启动时必须 source 这个 preamble
# === SHARED LAYER PREAMBLE ===
# $TMP, $SHARED, $AUDIT_LOG, $REPORT_DIR 已由 directory_setup.md 的 init_hackprobe_dir 导出

# 等待共享层就绪（不超 5s，避免阻塞）
for f in "$SHARED/ports.json" "$SHARED/techstack.json" "$SHARED/urls_all.json"; do
  [ -f "$f" ] || echo "[WARN] $f not ready — some signal data may be missing"
done

# 读信号文件（Wave 3 核心输入）
SIGNALS=$(cat "$SHARED/signals.json" 2>/dev/null | python3 -c "
import sys,json
try: print(json.dumps(json.load(sys.stdin), indent=2))
except: print('{}')
")
```
