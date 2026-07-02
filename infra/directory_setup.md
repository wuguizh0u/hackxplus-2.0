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

  # 桌面三目录
  DESKTOP="$HOME/Desktop/渗透测试报告"
  REPORT_DIR="$DESKTOP/报告"
  AUDIT_DIR="$DESKTOP/审计日志/$name"
  WORK_DIR="$DESKTOP/工作文件/$name"

  mkdir -p "$REPORT_DIR" "$AUDIT_DIR" "$WORK_DIR"/{wave0,wave1,wave2,wave3,_shared/decisions}
  # 运行时临时目录（curl/Js下载中间文件放这，结束清掉）
  mkdir -p "/tmp/pentest_$name"

  export WORK_ROOT="/tmp/pentest_$name"
  export REPORT_DIR AUDIT_DIR WORK_DIR HOST="$host" URL="$url"
  echo "$(date -Iseconds) | INIT | $url → $DESKTOP" > "$AUDIT_DIR/timeline.md"
}
```

## 三目录规范

```
桌面/渗透测试报告/
├── 报告/
│   └── {host}_{date}.md              # 最终 REPORT.md
├── 审计日志/
│   └── {host}_{date}/
│       └── timeline.md               # 每步一行, Gate 内联
└── 工作文件/
    └── {host}_{date}/
        ├── wave0/
        │   └── target_profile.json   # 目标分类+攻击面优先级
        ├── wave1/
        │   ├── subs_alive.md         # 存活子域+状态码
        │   └── techstack.md          # 技术栈识别
        ├── wave2/
        │   ├── js_leak.md            # JS逆向提取的敏感信息
        │   ├── api_discovery.md      # API端点+响应摘要
        │   └── path_bypass.md        # 绕过尝试+结果
        ├── wave3/
        │   └── probes_result.md      # 探针结果+确认漏洞列表
        └── _shared/decisions/
            ├── gate1.md              # 6问决策
            └── gate2.md              # 4问决策
```

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
