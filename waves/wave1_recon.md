# Wave 1 — 侦察与攻击面发现

> **分 3 个子 wave 解决并行竞态。** Agent 写私有临时文件，子 wave 结束后 merge。
> **所有 bash 脚本来自原 SKILL.md.bak 对应 Group，仅输出路径改为 `$TMP` 私有文件。**

## Wave 0 — Pre-flight（见 waves/wave0_preflight.md）

> **在 Wave 1 Agent 启动前启动（不阻塞），10-15 秒完成。输出 `_shared/target_profile.json`。**
> Wave 1 Agent 启动后读取画像调整策略。

---

## 全局 Preamble（每个 Agent 启动时 source）

```bash
# === WAVE 1 PREAMBLE ===
# $WORK_ROOT $TMP $SHARED $AUDIT_LOG $REPORT_DIR $URL $HOST 已由 init 脚本导出
source scripts/discover_tools.sh
# Lazy-load failure_handling (14KB) — only source on first actual failure
record_failure() { source infra/failure_handling.md 2>/dev/null; record_failure "$@"; }
TOOL_BASE="D:/1渗透tools/fox集成工具/tools"
mkdir -p "$TMP" "$SHARED" "$SHARED/decisions" "$AUDIT_LOG/agent_logs"
cd "$WORK_ROOT"
export WAVE_NAME="1"

# === Heartbeat start ===
source infra/directory_setup.md  # loads heartbeat() helper
heartbeat "wave1" "START" ""

# === Read Wave 0 pre-flight profile (if available) ===
# 路径经 argv 传入 —— 含中文的绝对路径不能展开进 Python 源码
# （git-bash 无 LANG 时按 GBK 处理，展开后路径被写坏 → 静默回落默认值）
read_profile() {
  python3 -c 'import json,sys
try:
    d = json.load(open(sys.argv[2], encoding="utf-8"))
    k = sys.argv[1]
    if k == "type":
        print(d.get("classification", {}).get("type", "unknown"))
    elif k == "waf":
        print(d.get("infra", {}).get("waf_likely", False))
    else:
        print(d.get("classification", {}).get("is_spa", False))
except Exception:
    print({"type": "unknown", "waf": "False", "spa": "False"}[sys.argv[1]])' \
    "$1" "$SHARED/target_profile.json"
}

if [ -f "$SHARED/target_profile.json" ]; then
  TARGET_TYPE=$(read_profile type)
  TARGET_WAF=$(read_profile waf)
  TARGET_SPA=$(read_profile spa)
  echo "[wave1] Pre-flight: type=$TARGET_TYPE waf=$TARGET_WAF spa=$TARGET_SPA"
else
  TARGET_TYPE="unknown"
  TARGET_WAF="False"
  TARGET_SPA="False"
  echo "[wave1] Pre-flight: not yet available, using default strategy"
fi
```

---

## Wave 1a — 信息收集（4 Agent 并行 → A5 串行 → merge）

| Agent | 原 Group | 输出 TMP 文件 | 依赖 | 原脚本位置 |
|-------|---------|--------------|------|-----------|
| **A1-OSINT** | 原 1A | `$TMP/1a_a1_osint.txt` | 无 | SKILL.md.bak L188-L235 |
| **A2-Subdomain** | 原 1B | `$TMP/1a_a2_subdomains.txt` | 无 | SKILL.md.bak L237-L499 |
| **A3-PortScan** | 原 1D | `$TMP/1a_a3_ports.json` | 无 | SKILL.md.bak L643-L795 |
| **A4-DomainIntel** | 原 1F | `$TMP/1a_a4_domain.txt` | 无 | SKILL.md.bak L891-L992 |
| **⏩ A5-HostCollision** | 新增 | `$TMP/1a_a5_hostcollision.json` | A2, A3 | 见下方 |

> A1-A4 并行执行。A5 在 A2 和 A3 都完成后串行执行（需要子域列表 + IP 列表）。

### A1-OSINT — 企业情报 + 被动信息收集

**Part 1 — WebSearch（Claude 内置工具，非 CLI）**：搜索后把发现写入 `$SHARED/01_osint.md`：

- 公司做什么？产品、行业、用户规模
- `"<COMPANY>" site:crunchbase.com` — 融资、员工数
- `site:linkedin.com "<COMPANY>" "tech stack" OR "we use" OR "hiring"` — 从招聘信息推技术栈
- `"<HOST>" site:stackshare.io` — 公开技术栈
- `"<HOST>" breach OR hack OR vulnerability OR CVE` — 历史安全事件
- 应用商店评价（若有 App）— 找安全相关抱怨
- 关键人物（CTO/VP Eng）— 后续负责任披露用
- 合规背景：涉及健康数据（GDPR Art.9）？金融（PCI-DSS）？儿童（COPPA）？

**Part 2 — theHarvester（被动 OSINT）**：收集邮箱、子域、员工姓名

```bash
echo "[wave1a] ====== A1-OSINT ====="
HARVESTER="${HACKPROBE_THEHARVESTER:-theHarvester}"

: > "$TMP/1a_a1_osint.txt"
echo "## Passive OSINT — theHarvester" > "$SHARED/01_osint.md"

if command -v "$HARVESTER" >/dev/null 2>&1; then
  "$HARVESTER" -d "$HOST" -b google,bing,dnsdumpster,virustotal,crtsh -l 200 \
    -f "$TMP/harvester_out" 2>/dev/null || true

  # 邮箱（经 stdin 管道，不经 bash 变量展开进 Python 源码）
  cat "$TMP/harvester_out.json" 2>/dev/null | python3 -c '
import sys, json
try:
    for e in json.load(sys.stdin).get("emails", []):
        print(e)
except Exception:
    pass' >> "$TMP/1a_a1_osint.txt" 2>/dev/null

  # 主机
  cat "$TMP/harvester_out.json" 2>/dev/null | python3 -c '
import sys, json
try:
    for h in json.load(sys.stdin).get("hosts", []):
        print(h)
except Exception:
    pass' >> "$TMP/1a_a1_osint.txt" 2>/dev/null
else
  echo "[A1] theHarvester 不可用 — 仅用 WebSearch 结果" >> "$TMP/1a_a1_osint.txt"
fi

echo "[A1] OSINT 完成 → $TMP/1a_a1_osint.txt ($(wc -l < "$TMP/1a_a1_osint.txt" 2>/dev/null | tr -d ' ') 行)"
```

### A2-Subdomain — 子域枚举 + DNS + 接管检测

```bash
echo "[wave1a] ====== A2-Subdomain ====="
SUBFINDER="${HACKPROBE_SUBFINDER:-subfinder}"
AMASS="${HACKPROBE_AMASS:-amass}"
DNSX="${HACKPROBE_DNSX:-dnsx}"
HTTPX="${HACKPROBE_HTTPX:-httpx}"

: > "$TMP/1a_a2_subdomains.txt"
echo "## Subdomain & DNS Enumeration" > "$SHARED/01_subdomains.md"
echo "**Target:** $HOST" >> "$SHARED/01_subdomains.md"

# --- 被动枚举 ---
command -v "$SUBFINDER" >/dev/null 2>&1 && \
  "$SUBFINDER" -d "$HOST" -silent 2>/dev/null >> "$TMP/1a_a2_subdomains.txt"
command -v "$AMASS" >/dev/null 2>&1 && \
  "$AMASS" enum -passive -d "$HOST" -timeout 3 2>/dev/null >> "$TMP/1a_a2_subdomains.txt"

# --- 证书透明度（SSL 证书日志能挖到隐藏子域）---
curl -s "https://crt.sh/?q=%25.$HOST&output=json" --max-time 30 2>/dev/null | python3 -c '
import sys, json
try:
    for c in json.load(sys.stdin):
        for name in c.get("name_value", "").split("\n"):
            if name.strip():
                print(name.strip())
except Exception:
    pass' >> "$TMP/1a_a2_subdomains.txt" 2>/dev/null

# --- 上下文字典爆破（公司名派生）---
if [ -f scripts/gen_custom_subdomains.py ]; then
  python3 scripts/gen_custom_subdomains.py --host "$HOST" \
    --output "$TMP/1a_a2_custom_subs.txt" 2>/dev/null || true
  if [ -s "$TMP/1a_a2_custom_subs.txt" ] && command -v "$DNSX" >/dev/null 2>&1; then
    "$DNSX" -silent -d "$TMP/1a_a2_custom_subs.txt" 2>/dev/null \
      >> "$TMP/1a_a2_subdomains.txt" || true
  fi
fi

sort -u "$TMP/1a_a2_subdomains.txt" -o "$TMP/1a_a2_subdomains.txt"

# --- DNS 解析 + HTTP 探活 ---
if [ -s "$TMP/1a_a2_subdomains.txt" ] && command -v "$DNSX" >/dev/null 2>&1; then
  "$DNSX" -silent -l "$TMP/1a_a2_subdomains.txt" 2>/dev/null \
    > "$TMP/1a_a2_resolved.txt" || true
fi

if [ -s "$TMP/1a_a2_resolved.txt" ] && command -v "$HTTPX" >/dev/null 2>&1; then
  "$HTTPX" -l "$TMP/1a_a2_resolved.txt" -silent -status-code -title -tech-detect \
    -json -o "$TMP/1a_a2_live.json" 2>/dev/null || true
  # 抽存活 URL 供 B2 与资产入库使用（路径经 argv 传参）
  python3 - "$TMP/1a_a2_live.json" "$TMP/1a_a2_urls.txt" <<'PYEOF' 2>/dev/null
import json, sys
src, dst = sys.argv[1], sys.argv[2]
urls = set()
try:
    with open(src, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                e = json.loads(line)
            except Exception:
                continue
            if e.get("url"):
                urls.add(e["url"])
except Exception:
    pass
with open(dst, "w", encoding="utf-8") as f:
    for u in sorted(urls):
        f.write(u + "\n")
print(f"[A2] {len(urls)} 个存活 URL")
PYEOF
fi

# --- DNS zone transfer（一次查询可能泄露整个 zone）---
NS_SERVER=$(dig NS "$HOST" +short 2>/dev/null | head -1)
if [ -n "$NS_SERVER" ]; then
  AXFR=$(dig axfr "$HOST" @"$NS_SERVER" 2>&1)
  if echo "$AXFR" | grep -q "XFR size"; then
    echo "[A2] ⚠ CRITICAL: DNS zone transfer 成功 —— 整个 zone 泄露" | tee -a "$TMP/1a_a2_subdomains.txt"
    echo "$AXFR" | grep -oE "[a-zA-Z0-9._-]+\.$HOST" >> "$TMP/1a_a2_subdomains.txt"
  fi
fi

# --- 子域接管检测（CNAME 指向已释放的云服务）---
if command -v "$DNSX" >/dev/null 2>&1 && [ -s "$TMP/1a_a2_subdomains.txt" ]; then
  "$DNSX" -silent -cname -l "$TMP/1a_a2_subdomains.txt" 2>/dev/null \
    > "$TMP/1a_a2_cnames.txt" || true
  grep -iE 'cloudfront\.net|herokuapp\.com|azurewebsites\.net|s3\.amazonaws\.com|fastly\.net|github\.io|netlify\.app|firebaseapp\.com|myshopify\.com|readme\.io|surge\.sh' \
    "$TMP/1a_a2_cnames.txt" 2>/dev/null > "$TMP/1a_a2_takeover_candidates.txt" || true
  [ -s "$TMP/1a_a2_takeover_candidates.txt" ] && \
    echo "[A2] ⚠ 子域接管候选: $(wc -l < "$TMP/1a_a2_takeover_candidates.txt" 2>/dev/null | tr -d ' ') 个"
fi

echo "[A2] 子域 $(wc -l < "$TMP/1a_a2_subdomains.txt" 2>/dev/null | tr -d ' ') 个"
```

#### A2-Subdomain 追加：脆弱子域标记

子域收集完成后统计脆弱子域计数供 Gate 1 Q6 使用。

```bash
# 脆弱子域统计（grep 计数，Gate 1 Q6 加分用）
FRAGILE_CRITICAL=$(grep -ciE 'admin|manage|internal|console|dashboard|portal|ops|jenkins|gitlab|grafana|kibana|phpmyadmin' "$TMP/1a_a2_subdomains.txt" 2>/dev/null || echo 0)
FRAGILE_HIGH=$(grep -ciE 'dev|test|qa|uat|stage|staging|sandbox|debug|demo|beta|old|temp|backup|bak|legacy' "$TMP/1a_a2_subdomains.txt" 2>/dev/null || echo 0)
echo "[wave1] Fragile subs: $FRAGILE_CRITICAL CRITICAL, $FRAGILE_HIGH HIGH"
echo "{\"fragile_count\":$((FRAGILE_CRITICAL + FRAGILE_HIGH)),\"critical_count\":$FRAGILE_CRITICAL}" > "$TMP/1a_a2_fragile_subs.json"
```

### A3-PortScan — 全端口扫描 + 服务识别 + WAF 检测

```bash
echo "[wave1a] ====== A3-PortScan ====="
NAABU="${HACKPROBE_NAABU:-naabu}"
NMAP="${HACKPROBE_NMAP:-nmap}"
WAFW00F="${HACKPROBE_WAFW00F:-wafw00f}"

: > "$TMP/1a_a3_ports.json"
echo "## Infrastructure Scan" > "$SHARED/01_infra.md"

# --- 全端口扫描（naabu 是 Go/异步，65535 端口约 2 分钟）---
if command -v "$NAABU" >/dev/null 2>&1; then
  "$NAABU" -host "$HOST" -p - -silent 2>/dev/null > "$TMP/1a_a3_ports.txt" || true
else
  # 回退：nmap 常见端口
  command -v "$NMAP" >/dev/null 2>&1 && \
    "$NMAP" -p- --min-rate 2000 -T4 "$HOST" -oG "$TMP/1a_a3_ports.gnmap" 2>/dev/null || true
  grep -oE '[0-9]+/open' "$TMP/1a_a3_ports.gnmap" 2>/dev/null | cut -d/ -f1 \
    | sed "s/^/$HOST:/" > "$TMP/1a_a3_ports.txt" || true
fi

# naabu 输出格式 host:port —— 抽 IP 供 A5 Host 碰撞用
cut -d: -f1 "$TMP/1a_a3_ports.txt" 2>/dev/null | sort -u > "$TMP/1a_a3_ips.txt"

echo "### Open Ports" >> "$SHARED/01_infra.md"
echo '```' >> "$SHARED/01_infra.md"
cat "$TMP/1a_a3_ports.txt" >> "$SHARED/01_infra.md" 2>/dev/null
echo '```' >> "$SHARED/01_infra.md"

# --- 服务识别 ---
PORTS=$(cut -d: -f2 "$TMP/1a_a3_ports.txt" 2>/dev/null | sort -un | paste -sd, -)
if [ -n "$PORTS" ] && command -v "$NMAP" >/dev/null 2>&1; then
  "$NMAP" -sV -sC -T4 -p "$PORTS" "$HOST" -oN "$TMP/1a_a3_nmap.txt" 2>&1 || true
  echo "### Service Detection" >> "$SHARED/01_infra.md"
  echo '```' >> "$SHARED/01_infra.md"
  cat "$TMP/1a_a3_nmap.txt" 2>/dev/null >> "$SHARED/01_infra.md"
  echo '```' >> "$SHARED/01_infra.md"
fi

# --- WAF 检测 ---
if command -v "$WAFW00F" >/dev/null 2>&1; then
  "$WAFW00F" "$URL" 2>&1 | tee "$TMP/1a_a3_waf.txt" >> "$SHARED/01_infra.md" || true
fi

# --- 结构化输出（merge 会 cp 成 $SHARED/ports.json）---
python3 - "$HOST" "$TMP/1a_a3_ports.txt" "$TMP/1a_a3_nmap.txt" "$TMP/1a_a3_ports.json" <<'PYEOF' 2>/dev/null
import json, re, sys

host, portfile, nmapfile, out = sys.argv[1:5]
tcp = {}

# 从 naabu 输出建基础表
try:
    with open(portfile, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if ":" in line:
                _, _, p = line.partition(":")
                if p.isdigit():
                    tcp[p] = {"service": "unknown", "version": ""}
except Exception:
    pass

# 从 nmap 输出补 service/version
try:
    with open(nmapfile, encoding="utf-8", errors="ignore") as f:
        for line in f:
            m = re.match(r"(\d+)/tcp\s+open\s+(\S+)\s*(.*)", line.strip())
            if m:
                port, svc, ver = m.group(1), m.group(2), m.group(3).strip()
                tcp.setdefault(port, {})
                tcp[port]["service"] = svc
                tcp[port]["version"] = ver
except Exception:
    pass

with open(out, "w", encoding="utf-8") as f:
    json.dump({"host": host, "tcp": tcp}, f, indent=2, ensure_ascii=False)
print(f"[A3] {len(tcp)} 个开放端口")
PYEOF

echo "[A3] 完成 → $TMP/1a_a3_ports.json"
```

> `$TMP/1a_a3_ips.txt` 是 **A5-HostCollision 的输入**，必须产出。

### A4-DomainIntel — WHOIS/RDAP + DNS 记录 + 邮件安全

```bash
echo "[wave1a] ====== A4-DomainIntel ====="
: > "$TMP/1a_a4_domain.txt"
echo "## Domain Intelligence & Email Security" > "$SHARED/01_domain.md"

# === WHOIS / RDAP ===
RDAP_RESP=$(curl -sk "https://rdap.org/domain/$HOST" --max-time 10 2>/dev/null)
if [ -n "$RDAP_RESP" ]; then
  # 原始 JSON 落 TMP
  printf '%s' "$RDAP_RESP" > "$TMP/1a_a4_rdap.json"
  # 摘要进人读报告（stdin 管道，不经变量展开）
  printf '%s' "$RDAP_RESP" | python3 -c '
import sys, json
try:
    d = json.load(sys.stdin)
    print(json.dumps({
        "name": d.get("ldhName"),
        "status": d.get("status"),
        "registrar": next((e.get("vcardArray", "")[1][1][3]
                           for e in d.get("entities", [])
                           if "registrar" in e.get("roles", [])), "unknown"),
        "events": [{e["eventAction"]: e["eventDate"]} for e in d.get("events", [])],
        "nameservers": [ns.get("ldhName") for ns in d.get("nameservers", [])],
    }, indent=2, ensure_ascii=False))
except Exception:
    print("RDAP parse failed")' >> "$TMP/1a_a4_domain.txt" 2>/dev/null
fi

# 经典 WHOIS 兜底
whois "$HOST" 2>/dev/null \
  | grep -iE "registrar|creation|expir|updated|name server|registrant|org|country|dnssec" \
  | head -20 >> "$TMP/1a_a4_domain.txt" || true

# === DNS 记录 ===
{
  echo "### Nameservers"
  dig "$HOST" NS +short 2>/dev/null
  echo ""
  echo "### MX (邮件服务商)"
  dig "$HOST" MX +short 2>/dev/null
  echo ""
  echo "### A / AAAA"
  dig "$HOST" A +short 2>/dev/null
  dig "$HOST" AAAA +short 2>/dev/null
} >> "$TMP/1a_a4_domain.txt" 2>/dev/null

# === 邮件安全（SPF / DMARC / DKIM）===
SPF=$(dig "$HOST" TXT +short 2>/dev/null | grep -i "v=spf1" || true)
DMARC=$(dig "_dmarc.$HOST" TXT +short 2>/dev/null | grep -i "v=DMARC" || true)

DKIM_FOUND=false
for selector in default google selector1 selector2 k1 mail dkim s1 s2; do
  DKIM=$(dig "${selector}._domainkey.$HOST" TXT +short 2>/dev/null | grep -i "v=DKIM" || true)
  if [ -n "$DKIM" ]; then
    DKIM_FOUND=true
    echo "DKIM selector=$selector" >> "$TMP/1a_a4_domain.txt"
    break
  fi
done

# 邮件安全摘要（人读）
{
  echo ""
  echo "### Email Security"
  echo "| 检查 | 状态 | 值 |"
  echo "|------|------|-----|"
  if [ -n "$SPF" ]; then echo "| SPF | ✓ 存在 | \`$SPF\` |"
  else echo "| SPF | **✗ 缺失** | 任何人可伪造该域发信 |"; fi
  if [ -n "$DMARC" ]; then
    echo "| DMARC | ✓ 存在 | \`$DMARC\` |"
    echo "$DMARC" | grep -qi "p=none" && echo "| DMARC 策略 | ⚠ 弱 | \`none\` —— 伪造邮件不被拒收 |"
  else
    echo "| DMARC | **✗ 缺失** | 无邮件认证策略 |"
  fi
  [ "$DKIM_FOUND" = false ] && echo "| DKIM | ⚠ 未找到 | 常见 selector 均无记录 |"
} >> "$SHARED/01_domain.md" 2>/dev/null

# 结构化输出（供 Tier 2 的 P45 SPF/DMARC 探针与 Gate 读取）
python3 - "$SPF" "$DMARC" "$DKIM_FOUND" "$TMP/1a_a4_domain.json" <<'PYEOF' 2>/dev/null
import json, sys
spf, dmarc, dkim, out = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4]
with open(out, "w", encoding="utf-8") as f:
    json.dump({"spf": bool(spf.strip()), "dmarc": bool(dmarc.strip()),
               "dmarc_policy": ("none" if "p=none" in dmarc else
                                "reject" if "p=reject" in dmarc else
                                "quarantine" if "p=quarantine" in dmarc else ""),
               "dkim": dkim == "true"}, f, indent=2)
PYEOF

echo "[A4] 完成 → SPF=$([ -n "$SPF" ] && echo yes || echo NO) DMARC=$([ -n "$DMARC" ] && echo yes || echo NO) DKIM=$DKIM_FOUND"
```

### A5-HostCollision — Host 碰撞（A2 + A3 完成后串行执行）

```bash
echo "[wave1] ====== A5-HostCollision ====="
HOSTSCAN="${HACKPROBE_TOOLS_ROOT:-D:/1渗透tools/fox集成工具/tools}/hostscan/hostscan.exe"

if [ -f "$HOSTSCAN" ] && [ -s "$TMP/1a_a2_subdomains.txt" ] && [ -s "$TMP/1a_a3_ips.txt" ]; then
  "$HOSTSCAN" -D "$TMP/1a_a2_subdomains.txt" -I "$TMP/1a_a3_ips.txt" \
    -O "$TMP/1a_a5_hostcollision.txt" -T 8 -t 5 2>&1 || true
  echo "[A5] Host 碰撞完成 → $TMP/1a_a5_hostcollision.txt"
else
  echo "[A5] SKIP: hostscan 或依赖文件缺失（需要 1a_a2_subdomains.txt + 1a_a3_ips.txt）"
  : > "$TMP/1a_a5_hostcollision.txt"
fi

# ★ 必须产出 JSON —— merge_results.sh 读的是 .json，只有 .txt 会导致结果全丢
#   字段名 high_value_hits / high_value_count 与 merge 和 Gate 1 Q6 的读取一致
python3 - "$TMP/1a_a5_hostcollision.txt" "$HOST" "$TMP/1a_a5_hostcollision.json" <<'PYEOF' 2>/dev/null
import json, os, sys

src, host, out = sys.argv[1], sys.argv[2], sys.argv[3]
HIGH_VALUE_KW = ("admin", "internal", "manage", "console", "dashboard",
                 "dev", "test", "staging", "uat", "gitlab", "jenkins")

hits, seen = [], set()
try:
    with open(src, encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if not line or line in seen:
                continue
            seen.add(line)
            # hostscan 输出通常形如 host 或 host:port 或 URL
            if line.startswith(("http://", "https://")):
                url, h = line, line.split("//", 1)[1].split("/", 1)[0]
            else:
                h = line.split(":", 1)[0]
                url = "https://" + line
            low = h.lower()
            hits.append({"host": h, "url": url,
                         "high_value": any(k in low for k in HIGH_VALUE_KW)})
except Exception:
    pass

payload = {"result": "ok" if hits else "no_hits",
           "host": host,
           "high_value_count": sum(1 for h in hits if h["high_value"]),
           "hits": hits,
           "high_value_hits": [h for h in hits if h["high_value"]]}

with open(out, "w", encoding="utf-8") as f:
    json.dump(payload, f, indent=2, ensure_ascii=False)
print(f"[A5] {len(hits)} 命中，其中高价值 {payload['high_value_count']}")
PYEOF
```

### Wave 1a 完成信号
```bash
# A1-A4 并行完成 → A5 串行执行 → 然后 merge
# 检查 TMP 文件存在性:
for f in 1a_a1_osint.txt 1a_a2_subdomains.txt 1a_a2_fragile_subs.json 1a_a3_ports.json 1a_a4_domain.txt 1a_a5_hostcollision.json; do
  [ -f "$TMP/$f" ] || echo "[WARN] $f missing — merge will run with partial data"
done
bash scripts/merge_results.sh --wave 1a
# merge_results.sh 额外处理:
#   - 1a_a5_hostcollision.json → _shared/hostcollision.json
#   - 1a_a5_hostcollision.json 中的 URL → 追加到 _shared/urls_all.txt
#   - 1a_a2_fragile_subs.json → _shared/fragile_subs.json
```

---

## Wave 1b — 依赖子域/端口（3 Agent，等 1a merge 完成）

> 条件: `_shared/subs_all.json` + `_shared/ports.json` 存在
> 每个 Agent 从 `_shared/` 只读

| Agent | 原 Group | 输出 TMP 文件 | 原脚本位置 |
|-------|---------|--------------|-----------|
| **B1-TechStack** | 原 1E | `$TMP/1b_b1_techstack.json` + `$TMP/1b_b1_httpx.json` | SKILL.md.bak L797-L892 |
| **B2-URLs** | 原 1C | `$TMP/1b_b2_urls.txt` + `$TMP/1b_b2_dirsearch.txt` | SKILL.md.bak L501-L641 |
| **B3-Secrets** | 原 2C | `$TMP/1b_b3_secrets.txt` | SKILL.md.bak L1398-L1462 |

### B1-TechStack（原 Group 1E）

> 输入：`$SHARED/subs_all.json`（活子域）+ `$SHARED/httpx.json`（若 1a 已有）
> 产出：`$TMP/1b_b1_httpx.json`（HTTP 层唯一来源）+ `$TMP/1b_b1_techstack.json`
> 人读摘要：`$SHARED/01_techstack.md`
>
> ⚠️ techstack.json 必须带顶层 `language`/`backend`/`server`/`frontend`/`cms`/
> `template_engine`/`database`/`services`/`signals` —— `merge_results.sh` 生成
> `signals.json` 时直接取这些键，缺了 Gate 1 与 Tier 2 的语言条件信号全是 None。

```bash
echo "[wave1b] ====== B1-TechStack ====="
source scripts/discover_tools.sh
# 行数统计 —— 文件缺失时返回 0 且不返回非 0（set -e 下 $() 里的失败会杀掉脚本）
count() { if [ -f "$1" ]; then wc -l < "$1" 2>/dev/null | tr -d ' \r'; else echo 0; fi; }

# ⚠️ discover_tools.sh 在 Windows 上可能把 HTTPX 解析到 Python 的 `httpx` CLI
#    （venv/Scripts/httpx）—— 那不是 ProjectDiscovery httpx，参数不兼容会直接报错。
#    只有「认 -json 开关」的才是真 httpx，否则清空变量走 curl 回退。
HTTPX="${HACKPROBE_HTTPX:-httpx}"
if command -v "$HTTPX" >/dev/null 2>&1; then
  if ! "$HTTPX" -h 2>&1 | grep -q -- '-json'; then
    echo "[B1] '$HTTPX' 不是 ProjectDiscovery httpx（无 -json 开关）— 回退 curl"
    HTTPX=""
  fi
else
  HTTPX=""
fi

# ---------- 1. 读 1a 产出的活子域（合并既有 httpx.json 里的存活 URL） ----------
python3 - "$SHARED/subs_all.json" "$SHARED/httpx.json" "$TMP/1b_b1_targets.txt" <<'PYEOF'
import json, os, sys

def load(p):
    try:
        with open(p, encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return None

targets = set()

subs = load(sys.argv[1])
if isinstance(subs, list):
    for s in subs:
        if isinstance(s, dict):
            host = s.get("subdomain") or s.get("host") or ""
            ok = any(str(s.get(k, "")).startswith(("2", "3")) for k in ("http_status", "https_status"))
            if host and (ok or not s.get("http_status")):
                targets.add("https://" + host)
        elif isinstance(s, str) and s:
            targets.add("https://" + s)

# 1a 若已跑过 httpx，其 JSON 里的存活 host 直接复用（HTTP 层唯一真相）
hx = load(sys.argv[2])
if isinstance(hx, list):
    for e in hx:
        if isinstance(e, dict) and e.get("url") and e.get("status_code"):
            targets.add(e["url"])

if not targets:
    targets.add(os.environ.get("URL", ""))

with open(sys.argv[3], "w", encoding="utf-8") as f:
    for u in sorted(targets):
        f.write(u + "\n")
print(f"[B1] {len(targets)} targets")
PYEOF

# ---------- 2. httpx 全量子域探测 → 唯一 HTTP 真相源 ----------
: > "$TMP/1b_b1_httpx.json"
if [ -n "$HTTPX" ] && command -v "$HTTPX" >/dev/null 2>&1 && [ -s "$TMP/1b_b1_targets.txt" ]; then
  "$HTTPX" -silent -json -tech-detect -status-code -title -content-length \
    -web-server -follow-redirects -l "$TMP/1b_b1_targets.txt" \
    > "$TMP/1b_b1_httpx.json" 2>/dev/null
  echo "[B1] httpx: $(count "$TMP/1b_b1_httpx.json") live hosts"
else
  # 回退：curl 手搓一行 JSON，保证下游 schema 不空。
  # ⚠️ 不要用 sed/printf 拼 JSON —— Server 头可能含引号/反斜杠，
  #    而 sed 的转义表达式在 set -e + pipeline 下极易被写坏并直接杀掉脚本
  #    （实测：sed -e 's/\\/\\\\/g' 报 unterminated 's' command → exit 1）。
  #    交给 Python json.dumps 生成，转义永远正确。
  python3 - "$TMP/1b_b1_targets.txt" "$TMP/1b_b1_httpx.json" <<'PYFALLBACK'
import json, subprocess, sys

targets_path, out_path = sys.argv[1], sys.argv[2]

def curl(args, timeout=12):
    try:
        r = subprocess.run(["curl"] + args, capture_output=True, timeout=timeout, text=True)
        return r.stdout or ""
    except Exception:
        return ""

try:
    with open(targets_path, encoding="utf-8", errors="ignore") as f:
        targets = [ln.strip() for ln in f if ln.strip()]
except Exception:
    targets = []

with open(out_path, "w", encoding="utf-8") as out:
    for u in targets:
        code = curl(["-sk", "-o", "/dev/null", "-w", "%{http_code}", "-L",
                     "--max-redirs", "3", "-A", "Mozilla/5.0", u, "--max-time", "8"]).strip()
        try:
            code_int = int(code)
        except Exception:
            code_int = 0
        head = curl(["-sk", "-I", "-L", "--max-redirs", "3", "-A", "Mozilla/5.0",
                     u, "--max-time", "8"])
        srv = ""
        for line in head.splitlines():
            if line.lower().startswith("server:"):
                srv = line.split(":", 1)[1].strip()
                break
        out.write(json.dumps({"url": u, "status_code": code_int,
                              "webserver": srv, "tech": []}, ensure_ascii=False) + "\n")
print(f"[B1] curl fallback: {len(targets)} target(s)")
PYFALLBACK
  echo "[B1] httpx 缺失 — 已用 curl 回退生成最小 httpx.json"
fi

# ---------- 3. 聚合 → techstack.json（含 signals.json 需要的全部顶层键） ----------
python3 - "$TMP/1b_b1_httpx.json" "$SHARED/ports.json" "$TMP/1b_b1_techstack.json" <<'PYEOF'
import json, os, re, sys

def load(p):
    try:
        with open(p, encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return None

rows = []
with open(sys.argv[1], encoding="utf-8") as f:
    for line in f:
        line = line.strip()
        if line:
            try:
                rows.append(json.loads(line))
            except Exception:
                pass

tech_raw = set()
for r in rows:
    for t in (r.get("tech") or []):
        tech_raw.add(str(t))

# httpx 的 tech 串形如 "Next.js:13.4.0" / "PHP:8.1.2"
def ver(name):
    for t in tech_raw:
        if t.lower().startswith(name.lower()):
            parts = t.split(":", 1)
            return parts[1] if len(parts) > 1 else None
    return None

blob = " ".join(tech_raw).lower()
servers = set()
for r in rows:
    ws = r.get("webserver") or (r.get("header", {}) or {}).get("server")
    if ws:
        servers.add(str(ws))

frameworks, cms, language, frontend, template_engine = [], None, None, None, None

if re.search(r"next\.js", blob):
    frontend = "Next.js"
elif re.search(r"nuxt", blob):
    frontend = "Nuxt.js"
elif re.search(r"angular", blob):
    frontend = "Angular"
elif re.search(r"svelte", blob):
    frontend = "SvelteKit"
elif re.search(r"react", blob):
    frontend = "React"
elif re.search(r"vue", blob):
    frontend = "Vue.js"

if "wordpress" in blob:
    cms = "WordPress"
elif "drupal" in blob:
    cms = "Drupal"
elif "joomla" in blob:
    cms = "Joomla"
elif "shopify" in blob:
    cms = "Shopify"

for name, pat in [("Spring Boot", r"spring"), ("ThinkPHP", r"thinkphp"),
                  ("Laravel", r"laravel"), ("Django", r"django"),
                  ("Flask", r"flask"), ("Express", r"express"),
                  ("FastAPI", r"fastapi"), ("Rails", r"rails"),
                  ("JFinal", r"jfinal"), ("RuoYi", r"ruoyi")]:
    if re.search(pat, blob):
        frameworks.append(name)

lang_map = [("PHP", r"php"), ("Java", r"java|tomcat|jetty|weblogic|spring"),
            ("ASP.NET", r"asp\.net|iis"), ("Python", r"python|django|flask|fastapi"),
            ("Node.js", r"node\.js|express|next\.js|nuxt"),
            ("Go", r"golang|gin\b|echo\b"), ("Ruby", r"ruby|rails"),
            ("Perl", r"perl")]
for name, pat in lang_map:
    if re.search(pat, blob) or re.search(pat, " ".join(servers).lower()):
        language = name
        break

tpl_map = [("Thymeleaf", r"thymeleaf"), ("Freemarker", r"freemarker"),
           ("Jinja2", r"jinja"), ("Smarty", r"smarty"), ("Twig", r"twig"),
           ("Blade", r"blade"), ("Velocity", r"velocity")]
for name, pat in tpl_map:
    if re.search(pat, blob):
        template_engine = name
        break

db_map = [("MySQL", r"mysql|mariadb"), ("PostgreSQL", r"postgres"),
          ("MongoDB", r"mongo"), ("Redis", r"redis"), ("MSSQL", r"mssql|sql server"),
          ("Oracle", r"oracle"), ("Elasticsearch", r"elasticsearch")]
database = [n for n, p in db_map if re.search(p, blob)]

services = sorted({t.split(":", 1)[0] for t in tech_raw})[:40]

# 1a 的端口 banner 补一层语言信息（httpx 看不出时用得上）
ports = load(sys.argv[2])
if isinstance(ports, dict):
    ptxt = json.dumps(ports).lower()
    if not language:
        for name, pat in lang_map:
            if re.search(pat, ptxt):
                language = name
                break
    for n, p in db_map:
        if re.search(p, ptxt) and n not in database:
            database.append(n)

out = {
    "language": language,
    "backend": frameworks[0] if frameworks else None,
    "server": sorted(servers)[0] if servers else None,
    "frontend": frontend,
    "cms": cms,
    "template_engine": template_engine,
    "database": database,
    "frameworks": frameworks,
    "servers": sorted(servers),
    "services": services,
    "signals": sorted(tech_raw)[:60],
    "versions": {t.split(":", 1)[0]: ver(t.split(":", 1)[0]) for t in tech_raw if ":" in t},
    "hosts": [{"url": r.get("url"), "status": r.get("status_code"),
               "title": r.get("title"), "server": r.get("webserver")} for r in rows][:200],
}

with open(sys.argv[3], "w", encoding="utf-8") as f:
    json.dump(out, f, indent=2, ensure_ascii=False)
print(f"[B1] techstack: lang={language} server={out['server']} cms={cms}")
PYEOF

# ---------- 4. HTML 源码 / 第三方服务识别（curl 手搓，httpx tech 看不出时兜底） ----------
{
  echo "# Tech Stack Fingerprint"
  echo ""
  echo "## From HTTP Headers"
  echo '```'
  curl -sk -I -L --max-redirs 3 "$URL" -A "Mozilla/5.0" 2>&1 | \
    grep -iE "x-powered-by|server:|x-nextjs|x-drupal|x-generator|x-aspnet|x-framework|via:" || true
  echo '```'
} >> "$SHARED/01_techstack.md"

PAGE=$(curl -sk -L --max-redirs 3 -A "Mozilla/5.0" "$URL" --max-time 15 2>/dev/null)

{
  echo ""
  echo "## From Page Source"
  echo "| Signal | Detected |"
  echo "|--------|----------|"
} >> "$SHARED/01_techstack.md"

for pair in "__NEXT_DATA__|Next.js" "__NUXT__|Nuxt.js" "__sveltekit|SvelteKit" \
            "__remixContext|Remix" "ng-version|Angular" "wp-content|WordPress" \
            "shopify|Shopify" "webflow|Webflow"; do
  needle="${pair%%|*}"; label="${pair##*|}"
  echo "$PAGE" | grep -qi -- "$needle" && echo "| Frontend/CMS | $label |" >> "$SHARED/01_techstack.md"
done

{
  echo ""
  echo "## Third-Party Services (from script/link tags)"
  echo '```'
  { echo "$PAGE" | grep -oiE 'src="https?://[^"]+' || true; } |     { grep -oE 'https?://[^/"]+' || true; } | sort -u | head -20 || true
  echo '```'
  echo ""
  echo "## Identified Services"
} >> "$SHARED/01_techstack.md"

while IFS='|' read -r needle label; do
  [ -z "$needle" ] && continue
  echo "$PAGE" | grep -qi -- "$needle" && echo "- $label" >> "$SHARED/01_techstack.md"
done <<'SERVICES'
google-analytics|Google Analytics
googletagmanager|Google Tag Manager
amplitude|Amplitude
segment|Segment
stripe|Stripe (payments)
solidgate|Solidgate (payments)
paypal|PayPal (payments)
customer\.io|customerio|Customer.io (CRM)
intercom|Intercom
hubspot|HubSpot
sentry|Sentry (error tracking)
auth0|Auth0 (authentication)
firebase|Firebase
supabase|Supabase
facebook.*pixel|fbevents|Facebook Pixel
clarity\.ms|Microsoft Clarity
hotjar|Hotjar
growthbook|launchdarkly|split\.io|Feature flags
SERVICES

echo "[B1] done → $TMP/1b_b1_httpx.json + $TMP/1b_b1_techstack.json"
```

> 补充（Claude 工具，非 CLI）：用 **WebSearch** 搜
> `site:linkedin.com "<COMPANY>" "tech stack" OR "we are hiring"`、
> `"<HOST>" site:stackshare.io`、`"<HOST>" breach OR vulnerability OR CVE`
> 抽岗位 JD 里的技术栈与历史事故，结论追加到 `$SHARED/01_techstack.md`。

### B2-URLs（原 Group 1C）

> 输入：`$SHARED/httpx.json`（HTTP 层唯一真相）+ `$SHARED/subs_all.json` + `$SHARED/target_profile.json`（company 短名）
> 产出：`$TMP/1b_b2_urls.txt` + `$TMP/1b_b2_dirsearch.txt` + `$TMP/1b_b2_custom_dirs.txt`
> 人读摘要：`$SHARED/01_urls.md`
>
> ⚠️ merge 只吃 `1b_b2_urls.txt` 与 `1b_b2_dirsearch.txt`（已读 merge_results.sh 的 1b 分支确认）。
> `1b_b2_custom_dirs.txt` 是**字典**不是 URL，不进 merge，由 Wave 2 D4 深度目录扫描复用。

```bash
echo "[wave1b] ====== B2-URLs ====="
source scripts/discover_tools.sh
# 行数统计 —— 文件缺失时返回 0 且不返回非 0（set -e 下 $() 里的失败会杀掉脚本）
count() { if [ -f "$1" ]; then wc -l < "$1" 2>/dev/null | tr -d ' \r'; else echo 0; fi; }

ANEW="${HACKPROBE_ANEW:-anew}"
GAU="${HACKPROBE_GAU:-gau}"
WAYBACK="${HACKPROBE_WAYBACKURLS:-waybackurls}"
KATANA="${HACKPROBE_KATANA:-katana}"
DIRSEARCH="${HACKPROBE_DIRSEARCH:-dirsearch}"
YURO="${HACKPROBE_URO:-uro}"
GF="${HACKPROBE_GF:-gf}"

# anew 幂等追加；anew 缺失时退化为 sort -u（注意读 stdin，不能只 cat "$1"）
anew_append() {
  local target="$1"
  if command -v "$ANEW" >/dev/null 2>&1; then
    "$ANEW" "$target"
  else
    local tmp; tmp=$(mktemp)
    cat - > "$tmp" 2>/dev/null
    cat "$target" "$tmp" 2>/dev/null | sort -u > "$target.u" && mv "$target.u" "$target"
    rm -f "$tmp"
  fi
}

: > "$TMP/1b_b2_urls.txt"
: > "$TMP/1b_b2_dirsearch.txt"
: > "$TMP/1b_b2_custom_dirs.txt"

{
  echo "# URL Collection"
  echo ""
} > "$SHARED/01_urls.md"

# ---------- 1. 目标清单：活子域 ∪ httpx 存活 URL（HTTP 层唯一真相） ----------
python3 - "$SHARED/subs_all.json" "$SHARED/httpx.json" "$TMP/1b_b2_targets.txt" <<'PYEOF'
import json, os, re, sys

def load(p):
    try:
        with open(p, encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return None

hosts, urls = [], set()

subs = load(sys.argv[1])
if isinstance(subs, list):
    for s in subs:
        if isinstance(s, dict):
            h = s.get("subdomain") or s.get("host") or ""
        elif isinstance(s, str):
            h = s
        else:
            h = ""
        h = h.strip().lower().lstrip("*.").strip()
        if h:
            hosts.append(h)
elif isinstance(subs, dict):
    for k, v in subs.items():
        h = str(v.get("subdomain") if isinstance(v, dict) else k or "").strip().lower()
        if h:
            hosts.append(h)

hx = load(sys.argv[2])
if isinstance(hx, list):
    for e in hx:
        if isinstance(e, dict) and e.get("url"):
            urls.add(str(e["url"]).strip())
        elif isinstance(e, str):
            urls.add(e.strip())

# 每条 JSONL 也可能是 httpx 的行式输出（1b 自己产出的就是行式）
if not urls and os.path.exists(sys.argv[2]):
    try:
        with open(sys.argv[2], encoding="utf-8", errors="ignore") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    d = json.loads(line)
                except Exception:
                    continue
                if isinstance(d, dict):
                    if d.get("url"):
                        urls.add(str(d["url"]).strip())
                    elif d.get("host"):
                        urls.add("https://" + str(d["host"]).strip())
    except Exception:
        pass

urls.discard("")

# 补 host 根 URL（httpx 没覆盖到的子域）
covered = {re.sub(r"^https?://", "", u).split("/")[0].lower() for u in urls}
for h in hosts:
    if h not in covered:
        urls.add("https://" + h)

if not urls:
    u = os.environ.get("URL", "").strip()
    if u:
        urls.add(u)

with open(sys.argv[3], "w", encoding="utf-8") as f:
    for u in sorted(urls):
        f.write(u + "\n")
print(f"[B2] targets: {len(urls)} urls / {len(hosts)} subdomains")
PYEOF

# ---------- 2. 历史 URL（gau / waybackurls） ----------
# host 级去重只取前 40 个，避免 300+ 子域时 gau 串行跑到超时
{ head -40 "$TMP/1b_b2_targets.txt" 2>/dev/null || true; } | \
  sed -E 's#^https?://##; s#/.*$##' | sort -u > "$TMP/1b_b2_hosts.txt" || true

if [ -s "$TMP/1b_b2_hosts.txt" ]; then
  while IFS= read -r sub || [ -n "$sub" ]; do
    sub="${sub%$'\r'}"
    [ -z "$sub" ] && continue
    if command -v "$GAU" >/dev/null 2>&1; then
      ( "$GAU" --blacklist png,jpg,gif,svg,css,woff,ico,mp4 "$sub" 2>/dev/null || true ) | \
        anew_append "$TMP/1b_b2_urls.txt" || true
    fi
    if command -v "$WAYBACK" >/dev/null 2>&1; then
      ( "$WAYBACK" "$sub" 2>/dev/null || true ) | anew_append "$TMP/1b_b2_urls.txt" || true
    fi
  done < "$TMP/1b_b2_hosts.txt" || true
fi
echo "[B2] after historical: $(count "$TMP/1b_b2_urls.txt") URLs"

# ---------- 3. 活体爬取（katana → 首页链接兜底） ----------
if command -v "$KATANA" >/dev/null 2>&1; then
  ( "$KATANA" -u "$URL" -d 5 -jc -silent 2>/dev/null || true ) | anew_append "$TMP/1b_b2_urls.txt" || true
else
  curl -sk -L --max-redirs 3 -A "Mozilla/5.0" "$URL" --max-time 15 2>/dev/null | \
    grep -oiE '(href|src|action)=["'"'"'][^"'"'"']+' | \
    sed -E 's/^(href|src|action)=["'"'"']//I' | \
    while IFS= read -r link || [ -n "$link" ]; do
      link="${link%$'\r'}"
      case "$link" in
        http*) echo "$link" ;;
        /*)    echo "${URL%/}${link}" ;;
        *)     ;;
      esac
    done | anew_append "$TMP/1b_b2_urls.txt"
fi

# ---------- 4. dirsearch 轻扫（2 引擎压制：dirsearch + 御剑，不跑 4 个） ----------
if command -v "$DIRSEARCH" >/dev/null 2>&1; then
  "$DIRSEARCH" -u "$URL" -e php,js,json,txt,bak,env,sql,xml,yml,conf,log \
    -t 30 --random-agent -q -o "$TMP/1b_b2_dirsearch_raw.txt" >/dev/null 2>&1 || true
  if [ -s "$TMP/1b_b2_dirsearch_raw.txt" ]; then
    { grep -oE 'https?://[^ ]+' "$TMP/1b_b2_dirsearch_raw.txt" 2>/dev/null || true; } | \
      sort -u >> "$TMP/1b_b2_dirsearch.txt" || true
  fi
else
  echo "[B2] dirsearch 缺失 — 目录发现交给 Wave 2 的 D4 双引擎（dirsearch + 御剑）"
fi
echo "[B2] dirsearch hits: $(count "$TMP/1b_b2_dirsearch.txt")"

# ---------- 5. 上下文感知目录字典（不是 URL，不进 merge；供 Wave 2 D4 / 御剑 / ffuf 复用） ----------
if [ -f scripts/gen_custom_dirs.py ]; then
  COMPANY=$(python3 -c '
import json, os, sys
try:
    with open(os.environ.get("PROFILE_PATH", ""), encoding="utf-8") as f:
        d = json.load(f)
    print((d.get("identity", {}) or {}).get("company") or (d.get("target", {}) or {}).get("company") or "target")
except Exception:
    print("target")' PROFILE_PATH="$SHARED/target_profile.json" 2>/dev/null || echo target)
  [ -z "$COMPANY" ] && COMPANY="target"
  # MSYS_NO_PATHCONV=1 —— 否则 git-bash 会把想传给 Python 的路径参数改写成 Windows 路径，
  # 导致输出被写到 C:/Users/.../Temp/... 而不是 $TMP
  MSYS_NO_PATHCONV=1 python3 scripts/gen_custom_dirs.py --host "$HOST" --url "$URL" --company "$COMPANY" \
    --urls-file "$TMP/1b_b2_urls.txt" --output "$TMP/1b_b2_custom_dirs.txt" 2>/dev/null || \
    echo "[B2] gen_custom_dirs.py 失败 — 退化为路径片段拼装"
else
  python3 - "$TMP/1b_b2_urls.txt" "$TMP/1b_b2_custom_dirs.txt" <<'PYEOF'
import re, sys

segs = set()
try:
    with open(sys.argv[1], encoding="utf-8", errors="ignore") as f:
        for line in f:
            for m in re.findall(r"/([a-zA-Z][a-zA-Z0-9_-]{2,20})(?=/|$|\?)", line):
                if not m.endswith((".js", ".css", ".png", ".jpg", ".svg", ".ico", ".woff", ".woff2")):
                    segs.add(m.lower())
except Exception:
    pass

seeds = ["api", "admin", "upload", "user", "v1", "v2", "auth", "config", "static"]
roots = sorted(segs)[:40] + seeds
words = ["", ".bak", ".old", ".zip", ".tar.gz", "/", ".json", ".txt", ".log",
         "/config", "/debug", "/list", "/export"]
with open(sys.argv[2], "w", encoding="utf-8") as f:
    for r in roots:
        for w in words:
            f.write(f"/{r}{w}\n")
print(f"[B2] custom dirs (fallback): {len(roots)} roots x {len(words)} suffixes")
PYEOF
fi
echo "[B2] custom dirs: $(count "$TMP/1b_b2_custom_dirs.txt") entries"

# ---------- 6. 归一化去重（uro 折叠参数，比 sort -u 聪明） ----------
# 先滤掉黑名单静态资源，再 uro。注意 uro 会折叠参数值（/p?id=1 与 /p?id=2 → /p?id=FUZZ），
# 这是**有意为之** —— Wave 3 要的是参数名，不是每个具体取值。
if [ -s "$TMP/1b_b2_urls.txt" ]; then
  grep -viE '\.(png|jpe?g|gif|svg|webp|ico|bmp|css|woff2?|ttf|eot|otf|mp4|webm|mp3|avi|mov|pdf|zip|rar|7z|gz|tar|exe|dmg|apk|msi|swf|map)(\?|$)' \
    "$TMP/1b_b2_urls.txt" > "$TMP/1b_b2_urls.clean" 2>/dev/null || cp "$TMP/1b_b2_urls.txt" "$TMP/1b_b2_urls.clean"
  if command -v "$YURO" >/dev/null 2>&1; then
    "$YURO" < "$TMP/1b_b2_urls.clean" 2>/dev/null | sort -u > "$TMP/1b_b2_urls.uro" || \
      sort -u "$TMP/1b_b2_urls.clean" > "$TMP/1b_b2_urls.uro"
  else
    sort -u "$TMP/1b_b2_urls.clean" > "$TMP/1b_b2_urls.uro"
  fi
  mv "$TMP/1b_b2_urls.uro" "$TMP/1b_b2_urls.txt"
  rm -f "$TMP/1b_b2_urls.clean"
fi
[ -s "$TMP/1b_b2_dirsearch.txt" ] && sort -u "$TMP/1b_b2_dirsearch.txt" -o "$TMP/1b_b2_dirsearch.txt"

# ---------- 7. 参数分类（给 Wave 3 注入阶段选靶） ----------
{
  echo "**Total URLs:** $(count "$TMP/1b_b2_urls.txt")"
  echo ""
  echo "## Injection Candidates"
  echo "| Category | Count |"
  echo "|----------|-------|"
} >> "$SHARED/01_urls.md"

for cat in sqli xss ssrf lfi redirect idor; do
  CNT=0
  if command -v "$GF" >/dev/null 2>&1; then
    # tee 出来的是本轮 gf 命中的 URL，Wave 3 直接读这批文件选靶
    CNT=$( { grep -iE '\?' "$TMP/1b_b2_urls.txt" 2>/dev/null || true; } | \
           { "$GF" "$cat" 2>/dev/null || true; } | sort -u | \
           tee "$TMP/1b_b2_${cat}_params.txt" | wc -l | tr -d ' ' || true)
  else
    case "$cat" in
      sqli)     PAT='\?.*(id|select|query|search|q|name|cat|item|order_by|sort)=' ;;
      xss)      PAT='\?.*(q|s|search|keyword|name|msg|message|comment|callback)=' ;;
      ssrf)     PAT='\?.*(url|uri|path|dest|redirect|target|proxy|src|feed|host|webhook)=' ;;
      lfi)      PAT='\?.*(file|path|page|inc|include|doc|template|dir|folder|root|load)=' ;;
      redirect) PAT='\?.*(redirect|url|next|return|goto|dest|continue|target)=' ;;
      idor)     PAT='\?.*(id|uid|user_id|uuid|account|order|pid|gid)=' ;;
      *)        PAT='\?' ;;
    esac
    { grep -iE "$PAT" "$TMP/1b_b2_urls.txt" 2>/dev/null || true; } | \
      sort -u > "$TMP/1b_b2_${cat}_params.txt" || true
    CNT=$(count "$TMP/1b_b2_${cat}_params.txt")
  fi
  echo "| ${cat} | ${CNT:-0} |" >> "$SHARED/01_urls.md"
done

echo "[B2] done → $TMP/1b_b2_urls.txt ($(count "$TMP/1b_b2_urls.txt") URLs)"
```

### B3-Secrets（原 Group 2C）

> 输入：`$TMP/1b_b2_urls.txt`（B2 产出的 URL，避免重复 gau）
> 产出：`$TMP/1b_b3_secrets.txt`（merge 时按 secrets.json 落 `$SHARED/secrets.json`）
>       + `$TMP/1b_b3_jwt_tokens.txt`（merge → `$SHARED/jwt_tokens.txt`，Tier 2 的 P20/P21 读它）
> 人读摘要：`$SHARED/01_secrets.md`

```bash
echo "[wave1b] ====== B3-Secrets ====="
source scripts/discover_tools.sh
# 行数统计 —— 文件缺失时返回 0 且不返回非 0（set -e 下 $() 里的失败会杀掉脚本）
count() { if [ -f "$1" ]; then wc -l < "$1" 2>/dev/null | tr -d ' \r'; else echo 0; fi; }

TRUFFLEHOG="${HACKPROBE_TRUFFLEHOG:-trufflehog}"
JS_DIR="$TMP/1b_b3_js"
mkdir -p "$JS_DIR"
: > "$TMP/1b_b3_secrets.txt"
: > "$TMP/1b_b3_jwt_tokens.txt"

{
  echo "# Secret Scanning"
  echo ""
} > "$SHARED/01_secrets.md"

# ---------- 1. 从 B2 的 URL 里挑 JS（并集：B2 私产 + _shared 已 merge 的） ----------
# ⚠️ 逐个文件判存在再 cat —— 直接 cat 不存在的文件在 set -o pipefail 下会
#    让整条管道返回非 0，进而杀掉脚本（实测 B3 在此静默 exit 1）。
{
  [ -f "$TMP/1b_b2_urls.txt" ] && cat "$TMP/1b_b2_urls.txt"
  [ -f "$SHARED/urls_all.txt" ] && cat "$SHARED/urls_all.txt"
  true   # 两个文件都不存在时也保证块返回 0
} 2>/dev/null | grep -iE '\.js(\?|$)' | sort -u > "$TMP/1b_b3_js_files.txt" || true
echo "**JS files found:** $(count "$TMP/1b_b3_js_files.txt")" >> "$SHARED/01_secrets.md"

# ---------- 2. 下载 JS 供 trufflehog 扫描 ----------
while IFS= read -r jsurl || [ -n "$jsurl" ]; do
  jsurl="${jsurl%$'\r'}"
  [ -z "$jsurl" ] && continue
  FILE=$(echo "$jsurl" | sed 's/[^a-zA-Z0-9]/_/g')
  FILE="${FILE:0:180}.js"
  curl -sk "$jsurl" --max-time 10 -A "Mozilla/5.0" -o "$JS_DIR/$FILE" 2>/dev/null || true
done < "$TMP/1b_b3_js_files.txt" || true
echo "[B3] downloaded $(ls -1 "$JS_DIR" 2>/dev/null | wc -l | tr -d ' ' || echo 0) JS files"

# ---------- 3. trufflehog（--only-verified 降噪） ----------
{
  echo ""
  echo "## TruffleHog Results"
  echo '```'
} >> "$SHARED/01_secrets.md"

if command -v "$TRUFFLEHOG" >/dev/null 2>&1; then
  ( "$TRUFFLEHOG" filesystem "$JS_DIR" --no-update --only-verified --json 2>/dev/null || true ) | \
    head -200 > "$TMP/1b_b3_secrets.txt.raw" || true
  [ -f "$TMP/1b_b3_secrets.txt.raw" ] || : > "$TMP/1b_b3_secrets.txt.raw"
  # 原始 JSON 行 → 可读行 + 保留 json 落地
  python3 - "$TMP/1b_b3_secrets.txt.raw" "$TMP/1b_b3_secrets.txt" "$SHARED/01_secrets.md" <<'PYEOF'
import json, sys

seen = set()
nv = []
lines = []
try:
    with open(sys.argv[1], encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                d = json.loads(line)
            except Exception:
                continue
            det = d.get("DetectorName") or d.get("detector_name") or "unknown"
            raw = d.get("Raw") or d.get("raw") or ""
            src = (d.get("SourceMetadata") or {}).get("Data", {})
            loc = ""
            if isinstance(src, dict):
                for v in src.values():
                    if isinstance(v, dict) and v.get("file"):
                        loc = v["file"]
                        break
            key = (det, raw[:64])
            if key in seen:
                continue
            seen.add(key)
            nv.append({"detector": det, "file": loc, "raw": raw[:300],
                       "verified": bool(d.get("Verified"))})
            lines.append(f"[{det}] {loc} :: {raw[:120]}")
except Exception:
    pass

try:
    with open(sys.argv[2], "w", encoding="utf-8") as f:
        json.dump(nv, f, indent=2, ensure_ascii=False)
except Exception:
    pass

try:
    with open(sys.argv[3], "a", encoding="utf-8") as f:
        if lines:
            f.write("\n".join(lines[:60]) + "\n")
        else:
            f.write("no verified secrets\n")
except Exception:
    pass
print(f"[B3] trufflehog: {len(nv)} findings")
PYEOF
  rm -f "$TMP/1b_b3_secrets.txt.raw"
  # 无 trufflehog 时给一个空 JSON 数组占位，保证 secrets.json 可解码
  [ -s "$TMP/1b_b3_secrets.txt" ] || echo "[]" > "$TMP/1b_b3_secrets.txt"
else
  echo "trufflehog not available" >> "$SHARED/01_secrets.md"
  echo "[]" > "$TMP/1b_b3_secrets.txt"
fi

echo '```' >> "$SHARED/01_secrets.md"

# ---------- 4. 手动正则（trufflehog 漏掉的 / 未验证的） ----------
{
  echo ""
  echo "## Custom Pattern Matches"
  echo "| Pattern | File |"
  echo "|--------|------|"
} >> "$SHARED/01_secrets.md"

# ⚠️ 不要用 `grep | while read` 逐条匹配 —— 无命中时 grep 返回 1，
#    pipeline 的非 0 在 set -e 下会直接杀掉脚本（实测 B3 在 AIza 那条静默 exit 1）。
#    改为一次性 Python 扫描：无命中天然返回 0，且 JWT 产出确定（一行一个 token）。
python3 - "$JS_DIR" "$TMP/1b_b3_jwt_tokens.txt" "$SHARED/01_secrets.md" <<'PYSCAN'
import os, re, sys

js_dir, jwt_path, md_path = sys.argv[1], sys.argv[2], sys.argv[3]

PATTERNS = [
    ("AWS Access Key",     re.compile(r"AKIA[0-9A-Z]{16}")),
    ("Google API Key",     re.compile(r"AIza[0-9A-Za-z_\-]{35}")),
    ("Stripe Secret",      re.compile(r"sk_live_[0-9a-zA-Z]{24}")),
    ("GitHub PAT",         re.compile(r"ghp_[A-Za-z0-9]{36}")),
    ("Credential Pattern", re.compile(
        r"(api[_-]?key|secret[_-]?key|access[_-]?token|auth[_-]?token)[\"']?\s*[:=]\s*[\"'][^\"']{8,}",
        re.I)),
    ("DB Connection",      re.compile(r"(mysql|postgres|postgresql|mongodb|redis|jdbc|amqp)://[^\"'<> ]+")),
]
# ★ JWT —— Tier 2 的 P20/P21 消费，必须一行一个 token
JWT = re.compile(r"eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}")

files = []
try:
    for name in sorted(os.listdir(js_dir)):
        p = os.path.join(js_dir, name)
        if os.path.isfile(p) and name.endswith(".js"):
            files.append((name, p))
except Exception:
    pass

rows, jwts = [], set()
for name, path in files:
    try:
        with open(path, encoding="utf-8", errors="ignore") as f:
            blob = f.read()
    except Exception:
        continue
    for label, rx in PATTERNS:
        for m in rx.findall(blob):
            hit = m if isinstance(m, str) else m[0]
            rows.append((label, name, hit[:160]))
    for m in JWT.findall(blob):
        jwts.add(m)
        rows.append(("JWT Token", name, m[:40] + "..."))

with open(jwt_path, "w", encoding="utf-8") as f:
    for t in sorted(jwts):
        f.write(t + "\n")

try:
    with open(md_path, "a", encoding="utf-8") as f:
        for label, name, hit in rows[:120]:
            f.write(f"| {label} | {name} | `{hit}` |\n")
except Exception:
    pass

print(f"[B3] custom patterns: {len(rows)} match(es) | JWT: {len(jwts)}")
PYSCAN

echo "[B3] JWT tokens: $(count "$TMP/1b_b3_jwt_tokens.txt")"

# ---------- 5. JWT 解码（只 decode，不做爆破；爆破留给 Tier 2 P20/P21） ----------
{
  echo ""
  echo "## JWT Analysis"
} >> "$SHARED/01_secrets.md"

if [ -s "$TMP/1b_b3_jwt_tokens.txt" ]; then
  echo "**JWTs found:** $(count "$TMP/1b_b3_jwt_tokens.txt")" >> "$SHARED/01_secrets.md"
  { head -10 "$TMP/1b_b3_jwt_tokens.txt" 2>/dev/null || true; } | \
  while IFS= read -r token || [ -n "$token" ]; do
    token="${token%$'\r'}"
    TOKEN="$token" python3 - "$SHARED/01_secrets.md" <<'PYEOF'
import base64, json, os, sys

def b64(s):
    s += "=" * (-len(s) % 4)
    try:
        return json.loads(base64.urlsafe_b64decode(s.encode()).decode("utf-8", "replace"))
    except Exception:
        return None

tok = os.environ.get("TOKEN", "")
parts = tok.split(".")
lines = [f"\n#### Token: `{tok[:40]}...`", "```"]
for label, seg in (("header", parts[0] if parts else ""),
                   ("payload", parts[1] if len(parts) > 1 else "")):
    d = b64(seg)
    lines.append(f"-- {label} --")
    lines.append(json.dumps(d, indent=2, ensure_ascii=False) if d else "decode failed")
lines.append("```")
try:
    with open(sys.argv[1], "a", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")
except Exception:
    pass
PYEOF
  done || true
else
  echo "No JWTs found in JS files." >> "$SHARED/01_secrets.md"
fi

echo "[B3] done → $TMP/1b_b3_secrets.txt + $TMP/1b_b3_jwt_tokens.txt"
```

### Wave 1b 完成信号
```bash
for f in 1b_b1_techstack.json 1b_b2_urls.txt 1b_b3_secrets.txt; do
  [ -f "$TMP/$f" ] || echo "[WARN] $f missing"
done
bash scripts/merge_results.sh --wave 1b
# → 生成 _shared/techstack.json, _shared/httpx.json, _shared/urls_all.txt
# → 自动触发 signals.json 生成
```

---

## Wave 1c — 自动化检测（3 Agent，等 1b merge 完成）

| Agent | 原 Group | 输出 TMP 文件 | 原脚本位置 |
|-------|---------|--------------|-----------|
| **C1-Defaults** | 原 2A | `$TMP/1c_c1_defaults.json` | SKILL.md.bak L1000-L1189 |
| **C2-Sensitive** | 原 2B | `$TMP/1c_c2_sensitive.txt` | SKILL.md.bak L1191-L1235 |
| **C3-SSL** | 原 2D | `$TMP/1c_c3_ssl.json` | SKILL.md.bak L1464-L1496 |

### C1-Defaults（原 Group 2A）

> 输入：`$SHARED/ports.json`（1a 已验证的开放端口）
> 产出：`$TMP/1c_c1_defaults.json`（merge_json_append → `$SHARED/defaults.json`）
> 人读摘要：`$SHARED/01_defaults.md`
>
> ⚠️ **验证码红线**：登录表单含验证码（图形/短信/滑块/reCAPTCHA 等）时，
> **禁止**做用户名枚举与密码爆破。本 Agent 只做「已知默认口令单次探测」，
> 命中即停，不迭代字典。检测到验证码写入报告标注「存在验证码保护，未爆破」。

```bash
echo "[wave1c] ====== C1-Defaults ====="
source scripts/discover_tools.sh
# 行数统计 —— 文件缺失时返回 0 且不返回非 0（set -e 下 $() 里的失败会杀掉脚本）
count() { if [ -f "$1" ]; then wc -l < "$1" 2>/dev/null | tr -d ' \r'; else echo 0; fi; }

NMAP="${HACKPROBE_NMAP:-nmap}"
REDISCLI="${HACKPROBE_REDIS_CLI:-redis-cli}"
MYSQL="${HACKPROBE_MYSQL:-mysql}"
PSQL="${HACKPROBE_PSQL:-psql}"

# ---------- 1. 从 ports.json 取端口（只取 1a 验证过的） ----------
PORTS=$(python3 - "$SHARED/ports.json" <<'PYEOF'
import json, sys
try:
    with open(sys.argv[1], encoding="utf-8") as f:
        d = json.load(f)
except Exception:
    d = {}
tcp = d.get("tcp", d) if isinstance(d, dict) else {}
out = sorted({int(k) for k in tcp if str(k).isdigit()})
print(",".join(str(p) for p in out) if out else
      "80,443,8080,8443,8888,3000,9090,3306,6379,5432,27017,9200,11211,8123")
PYEOF
)
echo "[C1] ports: $PORTS"

# ---------- 2. nmap NSE http-default-accounts ----------
{
  echo "# Default Login Detection & Service Enumeration"
  echo ""
  echo "## Default Credential Scan (nmap NSE)"
  echo '```'
} > "$SHARED/01_defaults.md"

if command -v "$NMAP" >/dev/null 2>&1; then
  "$NMAP" --script http-default-accounts -Pn -T4 -p "$PORTS" "$HOST" 2>&1 | \
    tee "$TMP/1c_c1_nmap.txt" | head -80 | tee -a "$SHARED/01_defaults.md" >/dev/null
else
  echo "nmap not available" | tee "$TMP/1c_c1_nmap.txt" >> "$SHARED/01_defaults.md"
fi
echo '```' >> "$SHARED/01_defaults.md"

# ---------- 3. 手动默认口令探测（单次，不迭代） ----------
# ⚠️ 验证码红线：登录页含验证码特征 → 整块跳过该面板，只写「未爆破」标注
{
  echo ""
  echo "## Manual Default Credential Probes"
  echo "| Status | Panel | Creds Tried |"
  echo "|--------|-------|-------------|"
} >> "$SHARED/01_defaults.md"

PANELS="/admin /wp-login.php /manager/html /phpmyadmin/ /grafana/login /jenkins/login /login /admin/login /console"
CREDS="admin:admin admin:password admin:123456 admin:admin123 tomcat:tomcat tomcat:s3cret root:root root: root:123456"
HITS=0
SKIPPED=0

for path in $PANELS; do
  LOGIN_HTML=$(curl -sk -L --max-redirs 2 -A "Mozilla/5.0" "${URL}${path}" --max-time 6 2>/dev/null)
  [ -z "$LOGIN_HTML" ] && continue

  # 验证码预检（图形/短信/滑块/reCAPTCHA/hCaptcha/极验/turnstile）
  if echo "$LOGIN_HTML" | grep -qiE 'captcha|verify[_-]?code|recaptcha|hcaptcha|geetest|验证码|slider|turnstile'; then
    echo "[C1] CAPTCHA detected at $path — skipping credential probes (纪律红线)"
    echo "| SKIP | \`$path\` | 存在验证码保护，未进行爆破测试 |" >> "$SHARED/01_defaults.md"
    SKIPPED=$((SKIPPED + 1))
    continue
  fi
  # 不是登录页（无表单 / 无 password 字段）就跳过，避免对静态路径打 POST
  echo "$LOGIN_HTML" | grep -qiE '<form|type=["'"'"']password' || continue

  for cred in $CREDS; do
    USER="${cred%%:*}"; PASS="${cred#*:}"
    STATUS=$(curl -sk -o /dev/null -w "%{http_code}" --max-time 6 \
      -X POST "${URL}${path}" \
      -d "username=${USER}&password=${PASS}&j_username=${USER}&j_password=${PASS}" \
      -A "Mozilla/5.0" -L 2>/dev/null)
    # 302/303 + Location 含 session/token 才算命中，减少 SPA「永远 200」的误报
    LOC=$(curl -sk -o /dev/null -w "%{redirect_url}" --max-time 6 \
      -X POST "${URL}${path}" \
      -d "username=${USER}&password=${PASS}&j_username=${USER}&j_password=${PASS}" \
      -A "Mozilla/5.0" 2>/dev/null)
    if [[ "$STATUS" =~ ^(302|303)$ ]] && echo "$LOC" | grep -qiE 'session|token|dashboard|home|index|main'; then
      echo "| $STATUS | \`$path\` | \`${USER}:${PASS}\` |" >> "$SHARED/01_defaults.md"
      echo "[C1] HIT (redirect) $path $USER:$PASS → $STATUS"
      HITS=$((HITS + 1))
    elif [ "$STATUS" = "200" ] && echo "$LOGIN_HTML" | grep -qiE 'type=["'"'"']password'; then
      : # 200 不单独判命中（多为 SPA 回显登录页），仅记录痕迹
    fi
  done
done
echo "[C1] panel probes: $HITS hit(s), $SKIPPED panel(s) skipped for CAPTCHA"

# ---------- 4. DB / 缓存 / 搜索 空口令与默认口令（只读命令，不写任何数据） ----------
# ⚠️ 每个目标只发探测性只读命令；命中只在 JSON 留证。
#    绝不 dump / 改键 / flushdb / 写文件。
python3 - "$HOST" "$PORTS" "$TMP/1c_c1_defaults.json" \
  "$(command -v "$MYSQL" 2>/dev/null || echo '')" \
  "$(command -v "$REDISCLI" 2>/dev/null || echo '')" \
  "$(command -v "$PSQL" 2>/dev/null || echo '')" <<'PYEOF'
import json, os, socket, subprocess, sys

host, ports, out_path = sys.argv[1], sys.argv[2], sys.argv[3]
mysql_bin, redis_bin, psql_bin = sys.argv[4], sys.argv[5], sys.argv[6]
port_list = sorted({int(p) for p in ports.split(",") if p.strip().isdigit()})

def run(cmd, timeout=8, env=None):
    try:
        r = subprocess.run(cmd, capture_output=True, timeout=timeout, text=True, env=env)
        return (r.stdout or "") + (r.stderr or "")
    except Exception:
        return ""

def tcp_open(port, t=3):
    try:
        with socket.create_connection((host, port), timeout=t):
            return True
    except Exception:
        return False

findings = []

# --- MySQL 3306 : 空 root / 弱口令（只 SELECT 1） ---
if 3306 in port_list and tcp_open(3306) and mysql_bin:
    for pw in ["", "root", "123456"]:
        args = [mysql_bin, "-h", host, "-uroot", "--connect-timeout=5", "-e", "SELECT 1"]
        if pw:
            args.insert(3, f"-p{pw}")
        out = run(args)
        if "Access denied" in out or "Can't connect" in out:
            continue
        if "\n1" in out or out.strip().endswith("1"):
            findings.append({"service": "mysql", "port": 3306, "user": "root",
                             "password": pw or "<empty>", "impact": "full DB access"})
            break

# --- Redis 6379 : 无认证 PING（不 INFO 之外不 GET / 不 KEYS） ---
if 6379 in port_list and tcp_open(6379) and redis_bin:
    for pw in ["", "redis", "123456"]:
        args = [redis_bin, "-h", host, "-p", "6379"]
        if pw:
            args += ["-a", pw, "--no-auth-warning"]
        args += ["PING"]
        if "PONG" in run(args):
            findings.append({"service": "redis", "port": 6379, "user": None,
                             "password": pw or "<none>",
                             "impact": "unauthenticated redis" if not pw else "default password"})
            break

# --- PostgreSQL 5432 : postgres/postgres（只 SELECT 1） ---
if 5432 in port_list and tcp_open(5432) and psql_bin:
    for pw in ["postgres", "", "123456"]:
        env = dict(os.environ, PGPASSWORD=pw, PGCONNECT_TIMEOUT="5")
        r = run([psql_bin, "-h", host, "-U", "postgres", "-d", "postgres",
                 "-c", "SELECT 1", "-w", "-t", "-A"], timeout=10, env=env)
        if "1" in r and "denied" not in r.lower() and "error" not in r.lower()[:40]:
            findings.append({"service": "postgresql", "port": 5432, "user": "postgres",
                             "password": pw or "<empty>", "impact": "full DB access"})
            break

# --- MongoDB 27017 : 无认证（只 ping） ---
if 27017 in port_list and tcp_open(27017):
    try:
        import pymongo
        c = pymongo.MongoClient(host, 27017, serverSelectionTimeoutMS=5000)
        c.admin.command("ping")
        findings.append({"service": "mongodb", "port": 27017, "user": None,
                         "password": "<none>", "impact": "unauthenticated mongodb"})
        c.close()
    except Exception:
        pass

# --- Elasticsearch 9200 : 无认证（只读根节点） ---
if 9200 in port_list:
    out = run(["curl", "-sk", "--max-time", "5", f"http://{host}:9200/"])
    if '"cluster_name"' in out or '"tagline"' in out:
        findings.append({"service": "elasticsearch", "port": 9200, "user": None,
                         "password": "<none>", "impact": "unauthenticated ES (data readable)"})

# --- Memcached 11211 : 无认证（只 stats，不 items/get） ---
if 11211 in port_list:
    try:
        s = socket.create_connection((host, 11211), timeout=5)
        s.sendall(b"stats\r\n")
        data = s.recv(1024).decode("utf-8", "replace")
        s.close()
        if "STAT " in data:
            findings.append({"service": "memcached", "port": 11211, "user": None,
                             "password": "<none>", "impact": "unauthenticated memcached"})
    except Exception:
        pass

# --- ClickHouse 8123 : 默认 default 空口令（只 SELECT 1） ---
if 8123 in port_list:
    out = run(["curl", "-sk", "--max-time", "5", f"http://{host}:8123/?query=SELECT%201"])
    if out.strip() == "1":
        findings.append({"service": "clickhouse", "port": 8123, "user": "default",
                         "password": "<empty>", "impact": "unauthenticated clickhouse"})

result = {"host": host, "ports_scanned": port_list, "findings": findings}
try:
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(result, f, indent=2, ensure_ascii=False)
except Exception as e:
    sys.stderr.write(f"[C1] write failed: {e}\n")
print(f"[C1] db/service default creds: {len(findings)} finding(s)")
for x in findings:
    print(f"     - {x['service']}:{x['port']} pw={x['password']} -> {x['impact']}")
PYEOF

# 无命中时也保证 JSON 存在且可解码（merge_json_append 会读）
# 用 Python 写占位对象 —— 避免手拼 JSON 时 $HOST 含特殊字符把文件写坏
[ -s "$TMP/1c_c1_defaults.json" ] || \
  python3 -c 'import json,sys; json.dump({"host": sys.argv[1], "findings": []}, open(sys.argv[2], "w", encoding="utf-8"), indent=2)' \
    "$HOST" "$TMP/1c_c1_defaults.json"

echo "[C1] done → $TMP/1c_c1_defaults.json"
```

### C2-Sensitive（原 Group 2B）

> 输入：`$SHARED/urls_all.txt`
> 产出：`$TMP/1c_c2_sensitive.txt` + `$TMP/1c_c2_feroxbuster.txt` + `$TMP/1c_c2_upload_surface.json`
> 人读摘要：`$SHARED/01_content.md`
>
> ⚠️ `1c_c2_upload_surface.json` 必产出 —— merge 后是 `$SHARED/upload_surface.json`，
> Tier 2 的 **P27** 探针读它判定 `has_upload` 信号。

```bash
echo "[wave1c] ====== C2-Sensitive ====="
source scripts/discover_tools.sh
# 行数统计 —— 文件缺失时返回 0 且不返回非 0（set -e 下 $() 里的失败会杀掉脚本）
count() { if [ -f "$1" ]; then wc -l < "$1" 2>/dev/null | tr -d ' \r'; else echo 0; fi; }

FEROX="${HACKPROBE_FEROXBUSTER:-feroxbuster}"
: > "$TMP/1c_c2_sensitive.txt"
: > "$TMP/1c_c2_feroxbuster.txt"

{
  echo "# Content Discovery"
  echo ""
} > "$SHARED/01_content.md"

# ---------- 1. feroxbuster 递归内容发现 ----------
if command -v "$FEROX" >/dev/null 2>&1; then
  "$FEROX" -u "$URL" -d 3 -t 50 -x php,js,json,txt,bak,env,sql,xml,yml,yaml,conf,config,log \
    --quiet --no-state -o "$TMP/1c_c2_ferox_raw.txt" >/dev/null 2>&1 || true
  if [ -s "$TMP/1c_c2_ferox_raw.txt" ]; then
    # 抓 URL 列作为「发现路径」并入 sensitive_files（merge 时与 c2_sensitive 合并）
    grep -oE 'https?://[^ ]+' "$TMP/1c_c2_ferox_raw.txt" 2>/dev/null | \
      sort -u >> "$TMP/1c_c2_feroxbuster.txt"
  fi
  {
    echo "## Feroxbuster Results"
    echo '```'
    head -100 "$TMP/1c_c2_ferox_raw.txt" 2>/dev/null
    echo '```'
    echo ""
  } >> "$SHARED/01_content.md"
else
  echo "feroxbuster not available (dirsearch 已在 Wave 1b B2 扫过一轮)" >> "$SHARED/01_content.md"
fi
echo "[C2] feroxbuster: $(count "$TMP/1c_c2_feroxbuster.txt") URLs"

# ---------- 2. 敏感文件探针 + 上传面测绘 ----------
{
  echo "## Sensitive File Probe"
  echo "| Status | Size | Path |"
  echo "|--------|------|------|"
} >> "$SHARED/01_content.md"

python3 - "$URL" "$TMP/1c_c2_sensitive.txt" "$TMP/1c_c2_upload_surface.json" "$SHARED/01_content.md" <<'PYEOF'
import json, subprocess, sys

url, sens_path, upload_path, md_path = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4]
base = url.rstrip("/")

TARGETS = [
    "/.env", "/.env.local", "/.env.production", "/.env.backup", "/.env.dev",
    "/.git/config", "/.git/HEAD", "/.git/COMMIT_EDITMSG", "/.git/logs/HEAD",
    "/.gitignore", "/.github/workflows/",
    "/wp-config.php", "/wp-config.php.bak", "/config.php", "/config.yml", "/config.json",
    "/.aws/credentials", "/.ssh/id_rsa", "/.htpasswd",
    "/backup.sql", "/dump.sql", "/db.sql", "/database.sql", "/backup.zip",
    "/phpinfo.php", "/info.php", "/test.php", "/debug.php", "/server-status", "/server-info",
    "/api/swagger.json", "/swagger.json", "/openapi.json", "/api/docs", "/redoc",
    "/graphql", "/graphiql", "/__graphql",
    "/package.json", "/composer.json", "/composer.lock", "/Dockerfile", "/docker-compose.yml",
    "/.well-known/security.txt", "/robots.txt", "/sitemap.xml",
    "/admin", "/wp-admin", "/administrator", "/_admin", "/cms",
    "/debug", "/test", "/staging", "/dev",
    "/logs/error.log", "/error.log", "/access.log",
]

# 上传端点候选 —— Tier 2 的 P27 读 upload_surface.json 判定 has_upload 信号
UPLOAD_PATHS = [
    "/upload", "/api/upload", "/api/v1/upload", "/file/upload", "/api/files",
    "/admin/upload", "/api/import", "/api/v1/import", "/_upload", "/uploader",
    "/kindeditor/upload", "/ueditor/upload", "/ckfinder/upload",
    "/api/attachment/upload", "/api/avatar/upload", "/api/image/upload",
    "/api/media/upload", "/api/csv/import", "/api/excel/import",
    "/api/backup/restore", "/fileupload", "/uploadfile", "/upload.php",
]

# 上传证据关键词：命中即认为该端点确实是上传面（而不只是路径存在）
UPLOAD_EVIDENCE = ("multipart/form-data", "type=\"file\"", "type='file'",
                   "enctype", "fileupload", "ueditor", "kindeditor",
                   "ckfinder", "choosefile", "webuploader", "dropzone")

def probe(path, body=True):
    """返回 (status, size, body_snippet)。--max-redirs 2 防止无限跳转。"""
    try:
        r = subprocess.run(
            ["curl", "-sk", "-o", "/dev/null", "-w", "%{http_code} %{size_download}",
             "-L", "--max-redirs", "2", "-A", "Mozilla/5.0",
             base + path, "--max-time", "5"],
            capture_output=True, timeout=12, text=True)
        parts = (r.stdout or "").split()
        status = parts[0] if parts else "000"
        size = int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else 0
        snippet = ""
        if body and status in ("200", "405"):
            r2 = subprocess.run(
                ["curl", "-sk", "-L", "--max-redirs", "2", "-A", "Mozilla/5.0",
                 base + path, "--max-time", "6"],
                capture_output=True, timeout=14, text=True)
            snippet = (r2.stdout or "")[:20000]
        return status, size, snippet
    except Exception:
        return "000", 0, ""

hits, uploads = [], []

for path in TARGETS:
    status, size, _ = probe(path, body=(path in ("/.git/config", "/.env", "/phpinfo.php")))
    if status in ("200", "301", "302", "401", "403"):
        hits.append((status, size, path))

for path in UPLOAD_PATHS:
    status, size, body = probe(path)
    if status in ("000", "404"):
        continue
    ev = [k for k in UPLOAD_EVIDENCE if k in body.lower()]
    # 有「上传证据」的才算确认；405 = 路径存在但不吃 GET，也记为候选
    if ev or status == "405":
        uploads.append({"path": path, "status": status, "size": size,
                        "evidence": ev, "confirmed": bool(ev)})

# 敏感文件命中行（merge_unique_lines 直接吃这些 URL 行）
with open(sens_path, "w", encoding="utf-8") as f:
    for _status, _size, path in hits:
        f.write(f"{base}{path}\n")

# upload_surface.json —— P27 读它触发上传面检测
surface = {
    "base": base,
    "endpoints": uploads,
    "count": len(uploads),
    "confirmed_count": sum(1 for e in uploads if e.get("confirmed")),
    "has_upload": len(uploads) > 0,
    "upload_tech": sorted({k for e in uploads for k in e["evidence"]
                           if k in ("ueditor", "kindeditor", "ckfinder",
                                    "webuploader", "dropzone")}),
    "probed": len(UPLOAD_PATHS),
}
with open(upload_path, "w", encoding="utf-8") as f:
    json.dump(surface, f, indent=2, ensure_ascii=False)

# 人读表
with open(md_path, "a", encoding="utf-8") as f:
    for status, size, path in hits:
        f.write(f"| {status} | {size}b | `{path}` |\n")
    f.write(f"\n## Upload Attack Surface\n\n")
    f.write(f"**{len(uploads)} endpoint(s)** "
            f"({surface['confirmed_count']} confirmed by form/evidence)\n\n")
    if uploads:
        f.write("| Status | Path | Evidence |\n|--------|------|----------|\n")
        for e in uploads:
            f.write(f"| {e['status']} | `{e['path']}` | "
                    f"{', '.join(e['evidence']) or 'status-only'} |\n")

print(f"[C2] sensitive hits: {len(hits)} | upload endpoints: "
      f"{len(uploads)} ({surface['confirmed_count']} confirmed)")
PYEOF

# 无命中时也要有可解码 JSON（merge 会 cp 到 $SHARED/upload_surface.json，P27 必读）
[ -s "$TMP/1c_c2_upload_surface.json" ] || \
  python3 -c 'import json,sys; json.dump({"base": sys.argv[1], "endpoints": [], "count": 0, "confirmed_count": 0, "has_upload": False, "upload_tech": []}, open(sys.argv[2], "w", encoding="utf-8"), indent=2)' \
    "$URL" "$TMP/1c_c2_upload_surface.json"

echo "[C2] done → $TMP/1c_c2_sensitive.txt + $TMP/1c_c2_feroxbuster.txt + $TMP/1c_c2_upload_surface.json"
```

### C3-SSL（原 Group 2D）

> 输入：`$HOST` / `$URL`
> 产出：`$TMP/1c_c3_ssl.json`（merge → `$SHARED/ssl.json`）
> 人读摘要：`$SHARED/01_ssl_headers.md`
>
> ⚠️ 纯 TLS 版本过低/证书自签名属**垃圾洞**，只在 JSON 留证，不进最终报告漏洞列表。
> 真正要报的是「安全响应头缺失导致的实际可利用面」（如无 CSP 配合 XSS、无 HSTS 配合降级）。

```bash
echo "[wave1c] ====== C3-SSL ====="
source scripts/discover_tools.sh
# 行数统计 —— 文件缺失时返回 0 且不返回非 0（set -e 下 $() 里的失败会杀掉脚本）
count() { if [ -f "$1" ]; then wc -l < "$1" 2>/dev/null | tr -d ' \r'; else echo 0; fi; }

TESTSSL="${HACKPROBE_TESTSSL:-testssl}"
OPENSSL="${HACKPROBE_OPENSSL:-openssl}"
: > "$TMP/1c_c3_ssl_raw.json"

{
  echo "# SSL/TLS & Headers"
  echo ""
  echo "## SSL/TLS Audit"
  echo '```'
} > "$SHARED/01_ssl_headers.md"

# ---------- 1. testssl 审计 ----------
if command -v "$TESTSSL" >/dev/null 2>&1; then
  "$TESTSSL" --quiet --color 0 --jsonfile "$TMP/1c_c3_ssl_raw.json" "$HOST" 2>&1 | \
    head -80 >> "$SHARED/01_ssl_headers.md"
elif command -v "$OPENSSL" >/dev/null 2>&1; then
  # 回退：取证书 subject/issuer/有效期 + 协商到的协议版本
  # ⚠️ 443 未开放时 openssl 必然非 0 → 必须逐条 || true，否则 set -e 直接杀掉 C3
  {
    echo "--- openssl fallback ---"
    ( "$OPENSSL" s_client -connect "${HOST}:443" -servername "$HOST" </dev/null 2>/dev/null | \
      "$OPENSSL" x509 -noout -subject -issuer -dates 2>/dev/null ) || \
      echo "(openssl 无法连接 ${HOST}:443 — 目标可能未开 TLS)"
    echo "-- negotiated protocol --"
    ( "$OPENSSL" s_client -connect "${HOST}:443" -servername "$HOST" </dev/null 2>&1 | \
      { grep -iE 'Protocol|Cipher' || true; } | head -4 ) || true
  } >> "$SHARED/01_ssl_headers.md" 2>/dev/null || true
else
  echo "testssl / openssl 均不可用 — TLS 层跳过（纯 TLS 版本号属垃圾洞，不影响主流程）" \
    >> "$SHARED/01_ssl_headers.md"
fi
echo '```' >> "$SHARED/01_ssl_headers.md"

# ---------- 2. 安全响应头 + 可报性判定 ----------
{
  echo ""
  echo "## Security Headers"
  echo "| Header | Status |"
  echo "|--------|--------|"
} >> "$SHARED/01_ssl_headers.md"

python3 - "$TMP/1c_c3_ssl.json" "$HOST" "$URL" "$TMP/1c_c3_ssl_raw.json" <<'PYEOF'
import json, os, subprocess, sys

out_path, host, url, raw_ts = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4]

def curl(args, timeout=15):
    try:
        r = subprocess.run(["curl"] + args, capture_output=True, timeout=timeout, text=True)
        return r.stdout or ""
    except Exception:
        return ""

raw = curl(["-sk", "-I", "-L", "--max-redirs", "5", "-A", "Mozilla/5.0",
            url, "--max-time", "12"])

hdrs = {}
for line in raw.splitlines():
    if ":" in line and not line.startswith("HTTP/"):
        k, v = line.split(":", 1)
        hdrs[k.strip().lower()] = v.strip()

CHECK = ["strict-transport-security", "content-security-policy", "x-frame-options",
         "x-content-type-options", "referrer-policy", "permissions-policy",
         "x-xss-protection", "cross-origin-opener-policy"]

present = {h: (h in hdrs) for h in CHECK}
missing = [h for h in CHECK if not present[h]]

# curl 完全失败（连不上）→ 不把「全缺失」当结论，避免假阳性
reachable = bool(hdrs) or "200" in raw or "30" in raw

# testssl JSON 里只挑 HIGH/CRITICAL（纯协议版本/自签证书归 info，不进漏洞列表）
ssl_issues = []
try:
    with open(raw_ts, encoding="utf-8") as f:
        ts = json.load(f)
    scan = ts.get("scanResult", ts) if isinstance(ts, dict) else {}
    for entry in (scan.get("vulnerabilities") or []) + (scan.get("protocols") or []):
        if isinstance(entry, dict) and entry.get("severity") in ("HIGH", "CRITICAL"):
            ssl_issues.append({"id": entry.get("id"), "finding": entry.get("finding"),
                               "severity": entry.get("severity")})
except Exception:
    pass

result = {
    "host": host,
    "url": url,
    "reachable": reachable,
    "status_probe": raw.splitlines()[0].strip() if raw.splitlines() else "",
    "server_header": hdrs.get("server"),
    "x_powered_by": hdrs.get("x-powered-by"),
    "headers_all": hdrs,
    "headers_present": [h for h in CHECK if present[h]],
    "headers_missing": missing,
    "info_leaks": {k: hdrs[k] for k in ("server", "x-powered-by", "x-aspnet-version",
                                        "x-generator", "via") if k in hdrs},
    "ssl_high": ssl_issues,
    # 可报性判定：给 Stage 6 用。纯 TLS 版本号 / 自签名证书降为 info，不算 exploited
    "exploitable": reachable and (bool([h for h in missing
                                        if h in ("content-security-policy",
                                                 "strict-transport-security",
                                                 "x-frame-options")]) or bool(ssl_issues)),
    # 有 CSP 吗？Wave 3 的 XSS 探针据此判断「XSS 是否可直接武器化」
    "has_csp": "content-security-policy" in hdrs,
    "csp_value": hdrs.get("content-security-policy", ""),
}
with open(out_path, "w", encoding="utf-8") as f:
    json.dump(result, f, indent=2, ensure_ascii=False)

# 人读表
with open(out_path + ".md", "w", encoding="utf-8") as f:
    f.write("| Header | Status |\n|--------|--------|\n")
    for h in CHECK:
        f.write(f"| {h} | {'Present' if present[h] else 'MISSING'} |\n")
    for k, v in result["info_leaks"].items():
        f.write(f"| {k} | INFO LEAK: {v} |\n")
    if not reachable:
        f.write("| (note) | 目标不可达 —— headers 结果无效 |\n")

print(f"[C3] reachable={reachable} headers missing: {len(missing)} | ssl HIGH: {len(ssl_issues)}")
PYEOF

# 文件可能不存在（Python 写失败时）—— 必须 || true，否则 set -e 会杀掉脚本
[ -f "$TMP/1c_c3_ssl.json.md" ] && cat "$TMP/1c_c3_ssl.json.md" >> "$SHARED/01_ssl_headers.md" 2>/dev/null || true
rm -f "$TMP/1c_c3_ssl.json.md" "$TMP/1c_c3_ssl_raw.json"

# 无 testssl 且 curl 失败时也要有可解码 JSON
[ -s "$TMP/1c_c3_ssl.json" ] || \
  python3 -c 'import json,sys; json.dump({"host": sys.argv[1], "headers_missing": [], "reachable": False, "exploitable": False, "has_csp": False}, open(sys.argv[2], "w", encoding="utf-8"), indent=2)' \
    "$HOST" "$TMP/1c_c3_ssl.json"

echo "[C3] done → $TMP/1c_c3_ssl.json"
```

### Wave 1c 完成信号
```bash
for f in 1c_c1_defaults.json 1c_c2_sensitive.txt 1c_c3_ssl.json; do
  [ -f "$TMP/$f" ] || echo "[WARN] $f missing"
done
bash scripts/merge_results.sh --wave 1c
```

---

## 2.5A/C — CVE 映射（与 Wave 1 并行）

```bash
# 写入: $TMP/1c_cve.json   ← 必须用这个名字，merge_results.sh 的 1c 分支会合并它
#       （旧版写 1c_cve.json 但 merge 只认 2_d2_cve.json，导致 Wave 1 的 CVE 产物无人合并）
# product:version → OSV.dev API + searchsploit read-only
#
# 与 Wave 2 的 D2-CVE 关系：
#   Wave 1 这里做的是「快速映射」（httpx 拿到的版本号 → OSV 查询），与 Wave 1 并行跑；
#   Wave 2 的 D2-CVE 是「深度映射」（nuclei 结果 + 更多指纹）。
#   两者产出同名文件的不同部分，merge 时按 JSON 数组合并去重。
```

---

## Wave 1 完成 → 资产入库（★ 接线点）

> **每个活子域一个 target，每条带参 URL 一个 endpoint。**
> 这是"多子域不漏测"的落地点 —— 后续 Wave 3 从资产库取 endpoint 逐个打，
> 而不是只打主域。

**步骤 1：为每个活子域调 `asset_create_target`**

数据源 `$SHARED/subs_all.txt`（或 `subs_all.json`）。对 HTTP 探活为
200/301/302/401/403 的子域，构造完整 URL（优先 `https://{sub}`，失败降级 `http://`），
逐个调用：

| 参数 | 值 |
|------|-----|
| `url` | `"https://{sub}"` |
| `scope` | `"in-scope"` |
| `auth_mode` | `"unauthenticated"` |

把返回的 `target_id` 汇总成 host→id 映射，落盘供后续 Wave 使用：

```bash
# 期望产出 $SHARED/sub_target_map.json = {"admin.t.com": 2, "api.t.com": 3, ...}
```

**步骤 2：为每条 URL 调 `asset_inject_endpoint`**

读 `$SHARED/urls_all.txt`，按 host 归属到对应 `target_id`
（主域用 `$SHARED/target_id.txt`，子域查 `sub_target_map.json`）：

| 参数 | 值 |
|------|-----|
| `target_id` | 该 URL 所属 host 的 id |
| `path` | URL 的 path + query（不含 scheme/host） |
| `method` | `"GET"` |
| `params` | **JSON 字符串**，如 `"[\"id\",\"q\"]"` |
| `risk_tags` | **JSON 字符串**，如 `"[\"sqli\",\"xss\"]"` |

> ⚠️ **`params` / `risk_tags` 必须传 JSON 字符串**，不能传数组字面量。
> MCP schema 把它们声明为 `"type":"string"`，handler 内部 `json.loads` 解析。

**步骤 3：注入量控制**（`urls_all.txt` 可能上万条，按此裁剪）

- 保留所有含 query 参数的 URL（有价值）
- 保留非 2xx 但非 404 的路径
- **丢弃静态资源**：`.js .css .png .jpg .jpeg .gif .woff .woff2 .ttf .map .svg .ico`
- 纯 200 无参数的 HTML 页面，只保留前 200 条

产出 `$SHARED/ingest_report.json` = `{"targets_created": N, "endpoints_injected": M}`。

> `inject_endpoint` 按 `(target_id, method, path)` 去重，重复注入会**合并**
> 新的 params/risk_tags（不会丢数据），可安全重跑。

---

## Wave 1 完成 → Gate 1

```bash
echo "[wave1] All 3 sub-waves complete. Running Gate 1..."
# signals.json v1 已在 Wave 1b merge 时生成
cat $SHARED/signals.json | python3 -m json.tool 2>/dev/null

# 检查脆弱子域和 Host 碰撞结果（影响 Gate 1 决策）
FRAGILE_COUNT=$(python3 -c "import json;d=json.load(open('$SHARED/fragile_subs.json'));print(d.get('fragile_count',0))" 2>/dev/null || echo 0)
HOSTCOLLISION_HITS=$(python3 -c "import json;d=json.load(open('$SHARED/hostcollision.json'));print(d.get('high_value_count',0))" 2>/dev/null || echo 0)
echo "[gate1] Fragile subs: $FRAGILE_COUNT | Host collision high-value: $HOSTCOLLISION_HITS"

# Gate 1: 6 问 + 2 自动决策（详见 infra/decision_gates.md）
# 自动决策:
#   - FRAGILE_COUNT > 0 → "高价值子域存在" = YES
#   - HOSTCOLLISION_HITS >= 3 → "高价值子域存在" = YES  
source infra/decision_gates.md  # runs Gate 1 logic → $SHARED/decisions/gate1.json
```

---
