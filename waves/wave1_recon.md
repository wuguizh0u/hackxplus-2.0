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

### A1-OSINT 关键修改
```bash
# 原: echo "...">> results/01_osint.md
# 改: echo "...">> "$TMP/1a_a1_osint.txt"
# 其余 WebSearch + theHarvester 逻辑完全不变
```

### A2-Subdomain 关键修改
```bash
# 原: echo "$FULL" >> subdomains.txt
# 改: echo "$FULL" >> "$TMP/1a_a2_subdomains.txt"
# 
# 原: grep -oE 'https?://...' | anew all_urls.txt
# 改: | anew "$TMP/1a_a2_urls.txt"   (只写自己的文件)
#
# oneforall + crt.sh + 上下文字典 + DNS + HTTP 探活逻辑不变
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

### A3-PortScan 关键修改
```bash
# 原: cp 直接写 _shared/ports.json
# 改: cp "$TMP/1a_a3_ports.json"  （merge 时原子复制到 _shared/）
# naabu → nmap -sV → Python banner 确认 → wafw00f 逻辑不变
```

### A4-DomainIntel 关键修改
```bash
# 原: echo "..." >> results/01_domain.md
# 改: echo "..." >> "$TMP/1a_a4_domain.txt"
# WHOIS/RDAP + DNS + SPF/DMARC/DKIM 逻辑不变
```

### A5-HostCollision — Host 碰撞（A2 + A3 完成后串行执行）

```bash
echo "[wave1] ====== A5-HostCollision ====="
if [ -f "$HACKPROBE_TOOLS_ROOT/hostscan/hostscan.exe" ] && [ -f "$TMP/1a_a2_subdomains.txt" ] && [ -f "$TMP/1a_a3_ports.json" ]; then
  "$HACKPROBE_TOOLS_ROOT/hostscan/hostscan.exe" -D "$TMP/1a_a2_subdomains.txt" -I "$TMP/1a_a3_ips.txt" -O "$TMP/1a_a5_hostcollision.txt" -T 8 -t 5 2>&1
  echo "[A5] Host碰撞完成 → $TMP/1a_a5_hostcollision.txt"
else
  echo "[A5] SKIP: hostscan 或依赖文件缺失"
  echo '{"result":"manual_only","hits":[]}' > "$TMP/1a_a5_hostcollision.json"
fi
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

### B1-TechStack 关键修改
```bash
# 原: httpx ... | tee results/_shared/httpx.json
# 改: httpx ... | tee "$TMP/1b_b1_httpx.json"
# 原: echo "..." >> results/01_techstack.md
# 改: echo "..." >> "$TMP/1b_b1_techstack.txt"
# httpx tech-detect + HTML source 分析 + 第三方服务识别逻辑不变
# 读 _shared/subs_all.json 对所有活子域做 httpx 探测
```

### B2-URLs 关键修改
```bash
# 原: echo "$URL" | anew all_urls.txt
# 改: echo "$URL" | anew "$TMP/1b_b2_urls.txt"
# 原: dirsearch 结果直接 >> all_urls.txt
# 改: dirsearch 结果 >> "$TMP/1b_b2_dirsearch.txt"
# URLFinder + Wayback + 首页爬取 + dirsearch + 参数分类逻辑不变
# 上下文感知目录字典生成 → 写到 $TMP/1b_b2_custom_dirs.txt
```

### B3-Secrets 关键修改
```bash
# 原: trufflehog results >> results/02_secrets.md
# 改: trufflehog results >> "$TMP/1b_b3_secrets.txt"
# 原: grep AWS key 直接追写 all_urls.txt
# 改: JWT tokens → "$TMP/1b_b3_jwt_tokens.txt"
# trufflehog --only-verified + 手动正则 + JWT 解码逻辑不变
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

### C1-Defaults 关键修改
```bash
# 读 _shared/ports.json 验证后的端口
# nmap NSE http-default-accounts + 手动默认凭证
# DB 空密码检查（MySQL/Redis/PostgreSQL/MongoDB/ES/Memcached/ClickHouse）
# 结果 → "$TMP/1c_c1_defaults.json"
```

### C2-Sensitive 关键修改
```bash
# feroxbuster 结果 → "$TMP/1c_c2_feroxbuster.txt"
# 敏感文件 curl 探针结果 → "$TMP/1c_c2_sensitive.txt"
# Upload attack surface detection → "$TMP/1c_c2_upload_surface.json"
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
# 写入: results/02.5_cve_mapping.md / $TMP/1c_cve.json
# 原脚本: SKILL.md.bak L1600-L1727 (Group 2.5A) + L1823-L1918 (Group 2.5C)
# product:version → OSV.dev API + searchsploit read-only
# 逻辑完全不变，仅输出路径改 $TMP
```

---

## Wave 1 完成 → Gate 1

```bash
echo "[wave1] All 3 sub-waves complete. Running Gate 1..."
# signals.json v1 已在 Wave 1b merge 时生成
cat results/_shared/signals.json | python3 -m json.tool 2>/dev/null

# 检查脆弱子域和 Host 碰撞结果（影响 Gate 1 决策）
FRAGILE_COUNT=$(python3 -c "import json;d=json.load(open('results/_shared/fragile_subs.json'));print(d.get('fragile_count',0))" 2>/dev/null || echo 0)
HOSTCOLLISION_HITS=$(python3 -c "import json;d=json.load(open('results/_shared/hostcollision.json'));print(d.get('high_value_count',0))" 2>/dev/null || echo 0)
echo "[gate1] Fragile subs: $FRAGILE_COUNT | Host collision high-value: $HOSTCOLLISION_HITS"

# Gate 1: 6 问 + 2 自动决策（详见 infra/decision_gates.md）
# 自动决策:
#   - FRAGILE_COUNT > 0 → "高价值子域存在" = YES
#   - HOSTCOLLISION_HITS >= 3 → "高价值子域存在" = YES  
source infra/decision_gates.md  # runs Gate 1 logic → results/_shared/decisions/gate1.json
```

---
