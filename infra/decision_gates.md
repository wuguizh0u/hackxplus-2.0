# Decision Gates — 策略决策门

> 每个 Gate 输出 `gate1.json` + `gate1.md` 到 `$SHARED/decisions/`。JSON 机器可读（下游消费），MD 人类速览。

---

## Gate 1 — Wave 1 后执行

```bash
# === Q1: 强 WAF/CDN? ===
WAF_DETECTED=0
WAF_EVIDENCE=$(grep -oiE "Cloudflare|Akamai|Imperva|F5|FortiWeb|Barracuda|Sucuri|Incapsula|AWSALB" \
  $SHARED/01_infra.md 2>/dev/null | sort -u | tr '\n' ',' | sed 's/,$//')
[ -n "$WAF_EVIDENCE" ] && WAF_DETECTED=1

# === Q2: 纯静态站? ===
# 优先读 Wave 0 target_profile，比 URL count 更可靠
PROFILED_TYPE=$(python3 -c "import json;print(json.load(open('$SHARED/target_profile.json')).get('classification',{}).get('type','unknown'))" 2>/dev/null || echo "unknown")
if [ "$PROFILED_TYPE" = "static" ]; then
  STATIC_SITE=1
  echo "[gate1] Wave 0 confirmed static site — STATIC_SITE=1"
else
  URL_COUNT=$(wc -l < $SHARED/urls_all.txt 2>/dev/null | tr -d ' ')
  HAS_DYNAMIC=1
  ! grep -qiE '/login|/api/|/admin|\.php|\.asp|graphql' $SHARED/urls_all.txt 2>/dev/null && HAS_DYNAMIC=0
  STATIC_SITE=0
  [ "${URL_COUNT:-0}" -lt 20 ] && [ "$HAS_DYNAMIC" -eq 0 ] && STATIC_SITE=1
fi

# === Q3: API 密集? ===
API_COUNT=$(grep -ciE '/api/|/graphql|/v[0-9]/' $SHARED/urls_all.txt 2>/dev/null || echo 0)
API_SUBS=$(grep -ciE 'api\.|graphql\.|service\.' $SHARED/subs_all.txt 2>/dev/null || echo 0)
API_HEAVY=0
[ "${API_COUNT:-0}" -gt 5 ] || [ "${API_SUBS:-0}" -gt 0 ] && API_HEAVY=1

# === Q4: 登录/注册? ===
HAS_LOGIN=0; HAS_REGISTER=0
grep -qiE '/login|/signin|/auth' $SHARED/urls_all.txt 2>/dev/null && HAS_LOGIN=1
grep -qiE '/register|/signup|/create-account' $SHARED/urls_all.txt 2>/dev/null && HAS_REGISTER=1

# === Q5: 技术栈 ===
STACK_LABEL=$(python3 -c "
import json
try:
  d=json.load(open('$SHARED/techstack.json'))
  parts=[v for v in [d.get('cms',''),d.get('backend',''),d.get('server',''),d.get('language','')] if v]
  print('|'.join(parts) if parts else 'unknown')
except: print('unknown')
" 2>/dev/null)

# === Q6: 高价值子域? ===
# 从三个来源综合判断：关键词匹配 + 脆弱子域标记 + Host 碰撞命中
HIGH_VALUE_COUNT=$(grep -ciE 'admin|dev|api|staging|internal|test|uat|ops|manage|portal|console|dashboard|grafana|jenkins|gitlab' \
  $SHARED/subs_all.txt 2>/dev/null || echo 0)

# 脆弱子域补充（old, temp, dev, test, abandoned, stage, qa, admin, manage 等）
FRAGILE_COUNT=$(python3 -c "import json;print(json.load(open('$SHARED/fragile_subs.json')).get('fragile_count',0))" 2>/dev/null || echo 0)
CRITICAL_FRAGILE=$(python3 -c "import json;d=json.load(open('$SHARED/fragile_subs.json'));print(d.get('critical_count',0))" 2>/dev/null || echo 0)

# Host 碰撞高价值命中
HOSTCOLLISION_HITS=$(python3 -c "import json;print(json.load(open('$SHARED/hostcollision.json')).get('high_value_count',0))" 2>/dev/null || echo 0)

# 综合高价值评分
HIGH_VALUE_TOTAL=$((HIGH_VALUE_COUNT + FRAGILE_COUNT + HOSTCOLLISION_HITS))
if [ "$HIGH_VALUE_TOTAL" -ge 3 ] || [ "$CRITICAL_FRAGILE" -ge 1 ] || [ "$HOSTCOLLISION_HITS" -ge 1 ]; then WAVE2_SCOPE="FULL"
elif [ "$HIGH_VALUE_TOTAL" -ge 1 ]; then WAVE2_SCOPE="REDUCED"
else WAVE2_SCOPE="SKIP"; fi

# === 输出 gate1.json（机器可读）===
mkdir -p $SHARED/decisions
python3 << PYEOF > $SHARED/decisions/gate1.json
import json, os
gate1 = {
  "timestamp": "$(date -Iseconds)",
  "decisions": {
    "Q1_STRONG_WAF": {"value": $WAF_DETECTED, "evidence": "$WAF_EVIDENCE", "effects": ["Wave2 D6→top50","Wave3 sqlmap→manual","nuclei→safe-only"] if $WAF_DETECTED else []},
    "Q2_STATIC_SITE": {"value": $STATIC_SITE, "evidence": {"urls": $URL_COUNT, "dynamic": $HAS_DYNAMIC}, "effects": ["Wave2 SKIP","Wave3 Tier1 only"] if $STATIC_SITE else []},
    "Q3_API_HEAVY": {"value": $API_HEAVY, "evidence": {"api_urls": $API_COUNT, "api_subs": $API_SUBS}, "effects": ["Wave3 API-fuzz priority","NoSQL/PP/HiddenParams extra budget"] if $API_HEAVY else []},
    "Q4_AUTH": {"HAS_LOGIN": $HAS_LOGIN, "HAS_REGISTER": $HAS_REGISTER, "effects": (["Wave3 Step0 auto-register"] if $HAS_REGISTER else []) + (["Wave2 D6 full brute"] if $HAS_LOGIN else [])},
    "Q5_TECH_STACK": {"label": "$STACK_LABEL"},
    "Q6_HIGH_VALUE_SUBS": {"keyword_match": $HIGH_VALUE_COUNT, "fragile_subs": $FRAGILE_COUNT, "critical_fragile": $CRITICAL_FRAGILE, "hostcollision_hits": $HOSTCOLLISION_HITS, "total": $HIGH_VALUE_TOTAL, "WAVE2_SCOPE": "$WAVE2_SCOPE"}
  }
}
print(json.dumps(gate1, indent=2, ensure_ascii=False))
PYEOF

# === 输出 gate1.md（人类速览）===
cat > $SHARED/decisions/gate1.md << EOF
## Gate 1 — $(date +%H:%M:%S)

| # | 问题 | 结果 | 影响 |
|---|------|------|------|
| Q1 | WAF/CDN? | $( [ "$WAF_DETECTED" = 1 ] && echo "⚠ $WAF_EVIDENCE" || echo "无") | $( [ "$WAF_DETECTED" = 1 ] && echo "sqlmap→手动, 密码爆破→top50" || echo "-") |
| Q2 | 静态站? | $( [ "$STATIC_SITE" = 1 ] && echo "⚠ 是" || echo "否") | $( [ "$STATIC_SITE" = 1 ] && echo "Wave2 跳过" || echo "-") |
| Q3 | API 密集? | $( [ "$API_HEAVY" = 1 ] && echo "⚠ $API_COUNT 端点" || echo "否") | $( [ "$API_HEAVY" = 1 ] && echo "API fuzz 优先" || echo "-") |
| Q4 | 认证入口? | Login=$HAS_LOGIN Register=$HAS_REGISTER | $( [ "$HAS_REGISTER" = 1 ] && echo "自动注册" || [ "$HAS_LOGIN" = 1 ] && echo "密码爆破" || echo "未认证") |
| Q5 | 技术栈 | $STACK_LABEL | - |
| Q6 | 高价值子域 | 关键词:$HIGH_VALUE_COUNT 脆弱:$FRAGILE_COUNT 碰撞:$HOSTCOLLISION_HITS → $HIGH_VALUE_TOTAL | Wave2: $WAVE2_SCOPE |
EOF

echo "[gate1] WAVE2_SCOPE=$WAVE2_SCOPE (keywords=$HIGH_VALUE_COUNT fragile=$FRAGILE_COUNT collision=$HOSTCOLLISION_HITS)"
```

---

## Gate 2 — Wave 2 后执行

```bash
# === Q1: 新深层资产? ===
NEW_SUBS=$(wc -l < $SHARED/deep_subs.txt 2>/dev/null | tr -d ' ')
NEW_DIRS=$(wc -l < $SHARED/deep_dirs.txt 2>/dev/null | tr -d ' ')
NEW_TARGETS=0
[ "${NEW_SUBS:-0}" -gt 0 ] || [ "${NEW_DIRS:-0}" -gt 0 ] && NEW_TARGETS=1

# === Q2: 弱口令命中? ===
WEAK_CREDS=$(grep -c "SUCCESS" $SHARED/passwords.json 2>/dev/null || echo 0)

# === Q3 & Q4: 读 gate1.json（不 grep markdown）===
HAS_REGISTER_G2=$(python3 -c "import json;d=json.load(open('$SHARED/decisions/gate1.json'));print(d['decisions']['Q4_AUTH']['HAS_REGISTER'])" 2>/dev/null || echo 0)
WAF_SKIP_G2=$(python3 -c "import json;d=json.load(open('$SHARED/decisions/gate1.json'));print(d['decisions']['Q1_STRONG_WAF']['value'])" 2>/dev/null || echo 0)

AUTO_REGISTER=0; WAF_SKIP=0
[ "$HAS_REGISTER_G2" = "1" ] && AUTO_REGISTER=1
[ "$WAF_SKIP_G2" = "1" ] && WAF_SKIP=1

# === 输出 gate2.json ===
python3 << PYEOF > $SHARED/decisions/gate2.json
import json
gate2 = {
  "timestamp": "$(date -Iseconds)",
  "decisions": {
    "Q1_NEW_TARGETS": {"value": $NEW_TARGETS, "new_subs": $NEW_SUBS, "new_dirs": $NEW_DIRS},
    "Q2_WEAK_CREDS": {"value": $WEAK_CREDS, "effects": ["Wave3 Step0 login with creds"] if $WEAK_CREDS > 0 else []},
    "Q3_AUTO_REGISTER": {"value": $AUTO_REGISTER, "source": "gate1.Q4_AUTH.HAS_REGISTER"},
    "Q4_WAF_SKIP": {"value": $WAF_SKIP, "source": "gate1.Q1_STRONG_WAF"}
  },
  "wave3_params": {
    "auth_mode": "register" if $AUTO_REGISTER else ("login" if $WEAK_CREDS > 0 else "unauthenticated"),
    "sqli_mode": "manual-probes" if $WAF_SKIP else "full-sqlmap",
    "new_targets": bool($NEW_TARGETS)
  }
}
print(json.dumps(gate2, indent=2, ensure_ascii=False))
PYEOF

# === 输出 gate2.md ===
cat > $SHARED/decisions/gate2.md << EOF
## Gate 2 — $(date +%H:%M:%S)

| # | 问题 | 结果 | 影响 |
|---|------|------|------|
| Q1 | 新深层资产? | $( [ "$NEW_TARGETS" = 1 ] && echo "⚠ $NEW_SUBS subs + $NEW_DIRS dirs" || echo "无") | $( [ "$NEW_TARGETS" = 1 ] && echo "追加到 Wave3 注入范围" || echo "-") |
| Q2 | 弱口令? | $( [ "$WEAK_CREDS" -gt 0 ] && echo "⚠ $WEAK_CREDS 组" || echo "无") | $( [ "$WEAK_CREDS" -gt 0 ] && echo "Wave3 带 token" || echo "-") |
| Q3 | 自动注册? | $( [ "$AUTO_REGISTER" = 1 ] && echo "⚠ 是" || echo "否") | $( [ "$AUTO_REGISTER" = 1 ] && echo "Step0 注册→取 token" || echo "-") |
| Q4 | WAF 绕过? | $( [ "$WAF_SKIP" = 1 ] && echo "⚠ 需要" || echo "否") | $( [ "$WAF_SKIP" = 1 ] && echo "sqlmap 降级, 手动 bypass" || echo "-") |

**Wave3 启动参数:** auth=$([ "$AUTO_REGISTER" = 1 ] && echo "register" || [ "$WEAK_CREDS" -gt 0 ] && echo "login" || echo "none") | sqli=$([ "$WAF_SKIP" = 1 ] && echo "manual" || echo "full") | new-targets=$NEW_TARGETS
EOF

echo "[gate2] auto-register=$AUTO_REGISTER waf-skip=$WAF_SKIP new-targets=$NEW_TARGETS weak-creds=$WEAK_CREDS"
```

---
