# Directory Setup — 每次渗透的输出结构

> Wave 0 之前执行。三目录输出到桌面，工作文件按 Wave 分子目录，只写结论不存原始响应。

## 初始化

```bash
init_hackprobe_dir() {
  local url="${1:?Usage: init_hackprobe_dir <url>}"
  local host=$(echo "$url" | sed -E 's|https?://||' | cut -d/ -f1 | cut -d: -f1 | sed 's/[<>:"/\\|?*]/_/g')
  [ ${#host} -gt 40 ] && host=$(echo "$host" | cut -c1-40)
  local date_str=$(date +%Y-%m-%d)
  local name="${host}_${date_str}"

  # 输出根目录 —— 必须全 ASCII
  #   原因：git-bash 无 LANG 时按 GBK 处理，含中文的路径经 bash 变量展开进
  #   Python 源码会被写坏（实测 exists=False）。ASCII 路径彻底绕开此问题。
  DESKTOP="$HOME/Desktop/hackxplus"
  REPORT_DIR="$DESKTOP/reports"          # 最终 REPORT.md
  AUDIT_DIR="$DESKTOP/audit/$name"       # timeline / heartbeat / agent_logs
  WORK_DIR="$DESKTOP/work/$name"         # 工作目录（_work 在这下面）

  mkdir -p "$REPORT_DIR" "$AUDIT_DIR"

  # ★ 工作根目录放在桌面工作目录下（不再用 /tmp）
  #   原因：Windows 下 /tmp 会落到 C:\tmp，且重启即清空 —— 会丢掉整个渗透状态
  #   （SQLite 资产库 / checkpoint / 共享数据层全在这棵树下）
  export WORK_ROOT="$WORK_DIR/_work"
  export TMP="$WORK_ROOT/tmp"                 # Agent 私有临时文件
  export SHARED="$WORK_ROOT/shared"           # 共享数据层（merge 后）
  export AUDIT_LOG="$AUDIT_DIR"               # 审计日志（timeline/heartbeat）
  export HACKXPLUS_DB="$WORK_ROOT/hackxplus.db"             # SQLite 资产库（真相源）
  export HACKXPLUS_CHECKPOINT="$WORK_ROOT/checkpoint.json"  # 续轮点

  mkdir -p "$WORK_DIR"/{wave0,wave1,wave2,wave3} \
           "$AUDIT_DIR/agent_logs" \
           "$TMP" "$SHARED/decisions" "$SHARED/partial"

  # 目标 URL 落盘，供后续 Wave 读取（不再依赖 shell 变量跨调用传递）
  echo "$url" > "$WORK_ROOT/target_url.txt"

  export REPORT_DIR AUDIT_DIR WORK_DIR HOST="$host" URL="$url"
  echo "$(date -Iseconds) | INIT | $url → $DESKTOP" > "$AUDIT_DIR/timeline.md"
  echo "[init] WORK_ROOT=$WORK_ROOT"
  echo "[init] TMP=$TMP"
  echo "[init] SHARED=$SHARED"
  echo "[init] DB=$HACKXPLUS_DB"
}
```

## 三目录规范

```
~/Desktop/hackxplus/                  # 输出根（全 ASCII）
├── reports/
│   └── {host}_{date}.md              # 最终 REPORT.md
├── audit/
│   └── {host}_{date}/
│       ├── timeline.md               # 每步一行, Gate 内联
│       ├── heartbeat.log             # 实时进度（tail -f）
│       └── agent_logs/               # 每个 Agent 的输出
└── work/
    └── {host}_{date}/
        ├── _work/                    # ★ 工作根目录 ($WORK_ROOT)
        │   ├── hackxplus.db          # SQLite 资产库 —— 唯一真相源
        │   ├── checkpoint.json       # 续轮点
        │   ├── target_url.txt        # 目标 URL
        │   ├── tmp/                  # ★ Agent 私有临时文件 ($TMP)
        │   └── shared/               # ★ 共享数据层 ($SHARED，只读 truth source)
        │       ├── target_profile.json
        │       ├── subs_all.txt / urls_all.txt / ports.json / techstack.json
        │       ├── signals.json
        │       ├── auth_tokens.json  # per-host 凭据镜像
        │       └── decisions/
        │           ├── gate1.json / gate1.md
        │           └── gate2.json / gate2.md
        ├── wave0/ … wave3/           # 人读结论（只写结论不存原始响应）
        └── (旧版 _shared/ 已废弃 → 统一到 _work/shared/)
```

### 变量契约（init 后全仓可用）

| 变量 | 指向 | 用途 |
|------|------|------|
| `$WORK_ROOT` | `{WORK_DIR}/_work` | 工作根，重启后仍在 |
| `$TMP` | `$WORK_ROOT/tmp` | Agent 私有临时文件 |
| `$SHARED` | `$WORK_ROOT/shared` | 共享数据层（merge 落点） |
| `$AUDIT_LOG` | `audit/{host}_{date}` | heartbeat / agent_logs |
| `$HACKXPLUS_DB` | `$WORK_ROOT/hackxplus.db` | MCP 资产库 |
| `$HACKXPLUS_CHECKPOINT` | `$WORK_ROOT/checkpoint.json` | 续轮状态 |

> **纪律**：`$SHARED` 只由 `merge_results.sh` 写；每个 Agent 只写自己的 `$TMP/<wave>_<id>_*`。
> SQLite 只能经 MCP 工具写，**禁止** skill 层直接 `sqlite3` 命令改库（否则绕过覆盖矩阵与门禁）。

## timeline.md 格式 — 每步一行 + Gate 内联

```markdown
# 审计时间线 — {host} ({date})

## Wave 0 — 预飞行
| 时间 | 步骤 | 结果 |
|------|------|------|
| HH:MM | curl 首页+响应头 | 状态码, CDN/WAF/框架关键发现 |
| HH:MM | WAF 探测 | 有无拦截 |
| HH:MM | DNS + 敏感路径扫 | 关键发现 |
| HH:MM | 目标分类 | type, static? → 进入Wave1 |

## Wave 1 — 侦察
| 时间 | 步骤 | 结果 |
|------|------|------|
| HH:MM | ... | ... |

## Gate 1
| # | 问题 | 结果 | 决策 |
|---|------|------|------|
| Q1 | 强WAF/CDN? | ... | ... |
| ... | ... | ... | ... |

## Wave 2 — 深层挖掘
...

## Gate 2
...

## Wave 3 — 定向利用
...

## Wave 4 — 报告
| HH:MM | 攻击链关联 | ... |
| HH:MM | 生成REPORT.md | N个发现, 严重度分布 |
```

## 工作文件规则

1. **只写结论** — 不存原始 HTTP 响应/大 JS bundle，只存提取后的 md 摘要
2. **按 Wave 分目录** — wave0/ wave1/ wave2/ wave3/
3. **Gate 决策放 _shared/decisions/** — gate1.md + gate2.md，方便复盘策略
4. **每文件一个主题** — subs/techstack/js_leak/api_discovery/path_bypass/probes_result
5. **漏洞确认放 wave3/probes_result.md** — 含端点+CVSS+可复现PoC一行

## 报告规则

- 输出到 `报告/{host}_{date}.md`
- 包含: 摘要 → 攻击面 → 漏洞详情(PoC+CVSS+修复) → 攻击链 → 已确认安全项 → 修复优先级
- 每个漏洞必须带可复现 curl 命令
- 垃圾洞不写入报告 (CORS无凭证/Self-XSS/Sourcemap/版本号/TLS警告)
- Info 级发现合并到附录一句话，不单独列

## heartbeat 辅助函数

```bash
heartbeat() {
  local phase="$1" status="$2" detail="$3"
  # 同时写 timeline.md 和终端
  echo "| $(date +%H:%M) | $phase | $status — $detail |" >> "$AUDIT_DIR/timeline.md"
  echo "[$(date +%H:%M:%S)] $phase | $status | $detail"
}
```
