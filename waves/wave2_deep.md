# Wave 2 — 深层挖掘与发现

> ⚠️ **条件激活。** Gate 1 判定有 ≥1 高价值子域才跑完整版。0 → SKIP 整个 Wave 2。
> 每个 Agent 写 `results/tmp/2_<agent>_<output>.<ext>`，完成后 `merge_results.sh --wave 2`。

---

## Preamble

```bash
source scripts/discover_tools.sh 2>/dev/null  # 确保 $HACKPROBE_* 可用
record_failure() { source infra/failure_handling.md 2>/dev/null; record_failure "$@"; }
source infra/directory_setup.md 2>/dev/null  # heartbeat
export WAVE_NAME="2"
heartbeat "wave2" "START" ""
```

---

## 激活判断

```bash
# 读 Gate 1 决策（路径经 argv 传入 —— 含中文的绝对路径不能展开进 Python 源码，
# 否则 git-bash 按 GBK 处理会把路径写坏，导致静默 KeyError 回落为 0）
read_gate1() {
  python3 -c 'import json,sys
try:
    d = json.load(open(sys.argv[1], encoding="utf-8"))["decisions"]["Q6_HIGH_VALUE_SUBS"]
    print(d.get("total", 0) if sys.argv[2] == "total" else d.get("WAVE2_SCOPE", "FULL"))
except Exception:
    print(0 if sys.argv[2] == "total" else "FULL")' "$SHARED/decisions/gate1.json" "$1"
}

# 字段名必须是 total —— decision_gates.md:81 写的就是 total
# （旧代码读 'count' 会 KeyError → 被 || echo 0 吞掉 → HIGH_VALUE 恒为 0 → Wave 2 永远跳过）
HIGH_VALUE=$(read_gate1 total)

if [ "${HIGH_VALUE:-0}" -eq 0 ]; then
  echo "[wave2] ⏭ SKIPPED — No high-value subdomains."
  echo "[wave2] Still need Gate 2 (reduced signals) before Wave 3."
  exit 0
fi

MODE=$(read_gate1 scope)
echo "[wave2] Activated: MODE=$MODE ($HIGH_VALUE high-value subs)"
```

---

## Agent 清单

| Agent | 原 Group | 模式 FULL | 模式 REDUCED | 输出 TMP 文件 | 原脚本位置 |
|-------|---------|-----------|-------------|--------------|-----------|
| **D1-Nuclei** | 原 2.5B | ✅ | ✅ | `$TMP/2_d1_nuclei.txt` | SKILL.md.bak L1729-L1821 |
| **D2-CVE** | 原 2.5C | ✅ | ✅ | `$TMP/2_d2_cve.json` | SKILL.md.bak L1823-L1918 |
| **D3-DeepSubs** | 原 2.6A | ✅ | ❌ | `$TMP/2_d3_subs.txt` | SKILL.md.bak L1925-L2040 |
| **D4-DeepDirs** | 原 2.6B | ✅ | ❌ | `$TMP/2_d4_dirs.txt` | SKILL.md.bak L2042-L2117 |
| **D5-JSDeep** | 原 2.6C | ✅ | ❌ | `$TMP/2_d5_js_endpoints.txt` | SKILL.md.bak L2119-L2236 |
| **D6-Password** | 原 2.6F | ✅ | ✅(top-50) | `$TMP/2_d6_passwords.json` | SKILL.md.bak L2516-L3226 |

---

## 关键修改（竞态修复）

### 工具优先级（$HACKPROBE_* 变量）

| 步骤 | 首选 | 备选 | 全不可用时 |
|------|------|------|-----------|
| D1-Nuclei | `$HACKPROBE_NUCLEI` | - | curl 手工探针 (skip) |
| D2-CVE | `$HACKPROBE_SEARCHSPLOIT` | OSV.dev API | skip |
| D3-DeepSubs | `$HACKPROBE_ONEFORALL` / `$HACKPROBE_SUBFINDER` | `$HACKPROBE_GOON` | crt.sh + dns 爆破 |
| D4-DeepDirs | `$HACKPROBE_DIRSEARCH` + `$HACKPROBE_YJDIRSCAN` | `$HACKPROBE_FEROXBUSTER` | curl HEAD 爆破 |
| D5-JSDeep | `$HACKPROBE_URLFINDER` | `$HACKPROBE_VUESCAN` / `$HACKPROBE_WEBFINDER_NEXT` | 手动 grep JS bundle |
| D6-Password | `$HACKPROBE_WEEKPASSWD` | curl POST 手动探测 | skip |

### D3-DeepSubs 修改
```bash
# 原: 4 tools 都追写 deep_subdomains_all.txt
# 改: 每个 tool 写到独立的 TMP 子文件
#   oneforall → "$TMP/2_d3_ofa.txt"
#   tide     → "$TMP/2_d3_tide.txt"
#   golin    → "$TMP/2_d3_golin.txt"
#   goon     → "$TMP/2_d3_goon.txt"
# merge 时 sort -u 合并到 _shared/deep_subs.txt
```

### D4-DeepDirs 修改
```bash
# 原: dirsearch + 御剑同时写目录结果
# 改: dirsearch → "$TMP/2_d4_dirsearch.txt"
#      御剑    → "$TMP/2_d4_yujian.txt"
```

### D5-JSDeep 修改
```bash
# 原: URLFinder + webfinder-next + vuescan + webpackscan 结果混写
# 改: 各写各的 → "$TMP/2_d5_js_{tool}.txt"
```

### D6-Password 修改
```bash
# 原: weak cred findings 直接写入 $SHARED/passwords.json
# 改: "$TMP/2_d6_passwords.json"
# merge 时 → _shared/passwords.json
# 弱口令命中自动写入 gate2.md 的 WEAK_CREDS 字段
```

---

## WAF 降级逻辑

```bash
# Read STRONG_WAF decision from Gate 1 structured output (gate1.json)
# gate1.json 的 decisions 是 **对象** 不是数组: {"Q1_STRONG_WAF": {"value": 0|1, ...}}
# 旧代码把 decisions 当数组遍历取 dec['id']/dec['decision_value'] → 永远失败 → 降级不生效
STRONG_WAF=$(python3 -c 'import json,sys
try:
    d = json.load(open(sys.argv[1], encoding="utf-8"))
    print(1 if d.get("decisions", {}).get("Q1_STRONG_WAF", {}).get("value") else 0)
except Exception:
    print(0)' "$SHARED/decisions/gate1.json" 2>/dev/null)

if [ "$STRONG_WAF" = "1" ]; then
  echo "[wave2] WAF detected — reducing intensity:"
  echo "  D1-Nuclei: reduced to 100 templates"
  echo "  D6-Password: top-50 only"
  
  # D1 executes with -max-template 100
  # D6 runs with head -50 on password dictionary
fi
```

---

## Wave 2 完成 → merge

```bash
echo "[wave2] All agents done/skipped. Merging..."
bash scripts/merge_results.sh --wave 2

# Update signals.json with newly discovered deep assets
echo "[wave2] Updating signals.json with Wave 2 discoveries..."
python3 -c "
import json, os

# Load existing signals
signals = {}
if os.path.exists('$SHARED/signals.json'):
    with open('$SHARED/signals.json') as f:
        signals = json.load(f)

# Add Wave 2 discoveries
new_subs = []
if os.path.exists('$SHARED/deep_subs.txt'):
    with open('$SHARED/deep_subs.txt') as f:
        new_subs = [l.strip() for l in f if l.strip()]
        # Check for high-value new subs
        for s in new_subs:
            if any(k in s.lower() for k in ['admin','api','dev','staging','internal','test','uat','ops']):
                signals.setdefault('attack_surface', {})['has_new_internal'] = True
                signals.setdefault('new_targets', []).append(s)

signals['wave2_complete'] = True
signals['wave2_new_subs'] = len(new_subs)

with open('$SHARED/signals.json', 'w') as f:
    json.dump(signals, f, indent=2)

print(f'[wave2] signals.json updated: {len(new_subs)} new subs, {len(signals.get(\"new_targets\",[]))} high-value')
"
```

---

## Gate 2 → Wave 3 策略

```bash
echo "[wave2] Running Gate 2..."
# 详见 infra/decision_gates.md Gate 2 部分
# 输出: $SHARED/decisions/gate2.md

# 核心决策:
# NEW_TARGETS=N   → Wave 3 注入范围追加
# WEAK_CREDS=1    → Wave 3 Step 0 登录
# AUTO_REGISTER=1 → Wave 3 Step 0 注册
# WAF_SKIP=1      → Wave 3 减少 sqlmap
```

---
