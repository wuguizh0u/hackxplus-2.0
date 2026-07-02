#!/bin/bash
# merge_results.sh — 原子合并 Agent 私有临时文件到共享数据层
# Usage: bash scripts/merge_results.sh --wave <1a|1b|1c|2|3>

set -e

WAVE=""
WORK_DIR="${WORK_DIR:-.}"

while [[ $# -gt 0 ]]; do
  case $1 in
    --wave) WAVE="$2"; shift 2 ;;
    *) echo "Unknown: $1"; exit 1 ;;
  esac
done

[ -z "$WAVE" ] && echo "Usage: merge_results.sh --wave <1a|1b|1c|2|3>" && exit 1

TMP_DIR="$WORK_DIR/results/tmp"
SHARED_DIR="$WORK_DIR/results/_shared"
mkdir -p "$SHARED_DIR" "$SHARED_DIR/decisions"

echo "[merge] ====== Merging Wave $WAVE ======"
echo "[merge] Source: $TMP_DIR"
echo "[merge] Target: $SHARED_DIR"

# ====================================
# Wave-specific merge logic
# ====================================

merge_unique_lines() {
  local output="$1"
  shift
  local inputs=("$@")
  > "$SHARED_DIR/${output}.tmp"
  for f in "${inputs[@]}"; do
    [ -f "$f" ] && cat "$f" >> "$SHARED_DIR/${output}.tmp"
  done
  if [ -f "$SHARED_DIR/${output}.tmp" ] && [ -s "$SHARED_DIR/${output}.tmp" ]; then
    sort -u "$SHARED_DIR/${output}.tmp" > "$SHARED_DIR/$output"
    echo "[merge]   $output: $(wc -l < "$SHARED_DIR/$output" | tr -d ' ') lines (unique)"
  fi
  rm -f "$SHARED_DIR/${output}.tmp"
}

merge_json_append() {
  local output="$1"
  shift
  local inputs=("$@")
  python3 -c "
import json, sys, os
merged = []
for f in sys.argv[1:]:
    if os.path.exists(f) and os.path.getsize(f) > 0:
        try:
            with open(f) as fh:
                data = json.load(fh)
                if isinstance(data, list):
                    merged.extend(data)
                elif isinstance(data, dict):
                    merged.append(data)
        except: pass
# Dedup by JSON string
seen = set()
unique = []
for item in merged:
    key = json.dumps(item, sort_keys=True)
    if key not in seen:
        seen.add(key)
        unique.append(item)
with open('$SHARED_DIR/$output', 'w') as fh:
    json.dump(unique, fh, indent=2)
print(f'[merge]   $output: {len(unique)} entries (merged from {len(merged)} raw)')
" "${inputs[@]}"
}

# ====================================
# Wave 1a — 无依赖 Agent 产出
# ====================================
if [ "$WAVE" = "1a" ]; then
  # Subdomains
  merge_unique_lines "subs_all.txt" \
    "$TMP_DIR/1a_a2_subdomains.txt"

  # Ports (structured)
  if [ -f "$TMP_DIR/1a_a3_ports.json" ]; then
    cp "$TMP_DIR/1a_a3_ports.json" "$SHARED_DIR/ports.json"
    echo "[merge]   ports.json: $(python3 -c "import json;print(len(json.load(open('$SHARED_DIR/ports.json'))))" 2>/dev/null || echo 0) verified ports"
  fi

  # Domain intelligence
  [ -f "$TMP_DIR/1a_a4_domain.txt" ] && cp "$TMP_DIR/1a_a4_domain.txt" "$SHARED_DIR/domain.json"

  # OSINT
  [ -f "$TMP_DIR/1a_a1_osint.txt" ] && cp "$TMP_DIR/1a_a1_osint.txt" "$SHARED_DIR/osint.json"

  # 🆕 Fragile subdomains
  if [ -f "$TMP_DIR/1a_a2_fragile_subs.json" ]; then
    cp "$TMP_DIR/1a_a2_fragile_subs.json" "$SHARED_DIR/fragile_subs.json"
    FRAGILE_COUNT=$(python3 -c "import json;print(json.load(open('$SHARED_DIR/fragile_subs.json')).get('fragile_count',0))" 2>/dev/null || echo 0)
    echo "[merge]   fragile_subs.json: $FRAGILE_COUNT flagged subs"
  fi

  # 🆕 Host collision
  if [ -f "$TMP_DIR/1a_a5_hostcollision.json" ]; then
    cp "$TMP_DIR/1a_a5_hostcollision.json" "$SHARED_DIR/hostcollision.json"
    HITS=$(python3 -c "import json;print(json.load(open('$SHARED_DIR/hostcollision.json')).get('high_value_count',0))" 2>/dev/null || echo 0)
    echo "[merge]   hostcollision.json: $HITS high-value hits"

    # 碰撞命中的 URL 追加到 urls_all.txt
    python3 -c "
import json, os
cf = '$SHARED_DIR/hostcollision.json'
uf = '$SHARED_DIR/urls_all.txt'
if os.path.exists(cf):
    with open(cf) as f:
        data = json.load(f)
    urls = set()
    for h in data.get('high_value_hits', []):
        urls.add(h.get('url', ''))
    # Append to urls_all.txt if exists, else create
    existing = set()
    if os.path.exists(uf):
        with open(uf) as f:
            existing = set(line.strip() for line in f if line.strip())
    new = urls - existing
    if new:
        with open(uf, 'a') as f:
            for u in sorted(new):
                f.write(u + '\n')
        print(f'[merge]   +{len(new)} URLs from host collision → urls_all.txt')
" 2>/dev/null
  fi

# ====================================
# Wave 1b — 依赖 Wave 1a 的子域/端口结果
# ====================================
elif [ "$WAVE" = "1b" ]; then
  # techstack
  [ -f "$TMP_DIR/1b_1e_techstack.json" ] && cp "$TMP_DIR/1b_1e_techstack.json" "$SHARED_DIR/techstack.json"

  # httpx (SINGLE source of HTTP truth)
  if [ -f "$TMP_DIR/1b_1e_httpx.json" ]; then
    cat "$TMP_DIR/1b_1e_httpx.json" > "$SHARED_DIR/httpx.json"
    echo "[merge]   httpx.json: $(cat "$SHARED_DIR/httpx.json" | wc -l | tr -d ' ') lines"
  fi

  # URLs
  merge_unique_lines "urls_all.txt" \
    "$TMP_DIR/1b_1c_urls.txt" \
    "$TMP_DIR/1b_1c_dirsearch.txt"

  # URL classification (params for injection stages)
  if [ -s "$SHARED_DIR/urls_all.txt" ]; then
    grep -E '\?[^=]+=' "$SHARED_DIR/urls_all.txt" 2>/dev/null | sort -u > "$SHARED_DIR/params_all.txt"
    grep -iE '\?.*(url|redirect|dest|target|proxy|uri|path)=' "$SHARED_DIR/urls_all.txt" 2>/dev/null | sort -u > "$SHARED_DIR/params_redirect.txt"
    grep -iE '\?.*(id|uid|user_id|uuid)=' "$SHARED_DIR/urls_all.txt" 2>/dev/null | sort -u > "$SHARED_DIR/params_idor.txt"
    echo "[merge]   params_all.txt: $(wc -l < "$SHARED_DIR/params_all.txt" | tr -d ' ') URLs with params"
  fi

  # Secrets
  [ -f "$TMP_DIR/1b_2c_secrets.txt" ] && cp "$TMP_DIR/1b_2c_secrets.txt" "$SHARED_DIR/secrets.json"

# ====================================
# Wave 1c — 自动化检测
# ====================================
elif [ "$WAVE" = "1c" ]; then
  merge_json_append "defaults.json" \
    "$TMP_DIR/1c_2a_defaults.json"

  merge_unique_lines "sensitive_files.txt" \
    "$TMP_DIR/1c_2b_sensitive.txt"

  [ -f "$TMP_DIR/1c_2d_ssl.json" ] && cp "$TMP_DIR/1c_2d_ssl.json" "$SHARED_DIR/ssl.json"

# ====================================
# Wave 2 — 条件激活
# ====================================
elif [ "$WAVE" = "2" ]; then
  [ -f "$TMP_DIR/2_d1_nuclei.txt" ] && cp "$TMP_DIR/2_d1_nuclei.txt" "$SHARED_DIR/nuclei.json"

  merge_unique_lines "deep_subs.txt" \
    "$TMP_DIR/2_d3_subs.txt"

  merge_unique_lines "deep_dirs.txt" \
    "$TMP_DIR/2_d4_dirs.txt"

  merge_unique_lines "deep_js_endpoints.txt" \
    "$TMP_DIR/2_d5_js_endpoints.txt"

  [ -f "$TMP_DIR/2_d6_passwords.json" ] && cp "$TMP_DIR/2_d6_passwords.json" "$SHARED_DIR/passwords.json"
  [ -f "$TMP_DIR/2_cve_mapping.json" ] && cp "$TMP_DIR/2_cve_mapping.json" "$SHARED_DIR/cve_mapping.json"

# ====================================
# Wave 3 — 探针结果 + 深度利用汇总
# ====================================
elif [ "$WAVE" = "3" ]; then
  [ -f "$TMP_DIR/3_probe_hits.json" ] && cp "$TMP_DIR/3_probe_hits.json" "$SHARED_DIR/probe_hits.json"

  # 深度利用产出 → 直接复制到 _shared/ 供 Wave 4 读取
  for f in "$TMP_DIR"/3_exploit_*.md; do
    [ -f "$f" ] && cp "$f" "$SHARED_DIR/"
  done
fi

# ====================================
# Post-merge: 生成/更新 signals.json
# ====================================
if [ "$WAVE" = "1b" ] || [ "$WAVE" = "2" ]; then
  echo "[merge] Generating signals.json..."
  python3 -c "
import json, os

signals = {'tech':{}, 'attack_surface':{}, 'infra':{}}

# Tech signals from techstack
if os.path.exists('$SHARED_DIR/techstack.json'):
    try:
        with open('$SHARED_DIR/techstack.json') as f:
            ts = json.load(f)
        signals['tech'] = {
            'language': ts.get('language'),
            'backend': ts.get('backend') or ts.get('server'),
            'server': ts.get('server'),
            'frontend': ts.get('frontend'),
            'cms': ts.get('cms'),
            'template_engine': ts.get('template_engine'),
            'database': ts.get('database', [])
        }
    except: pass

# Attack surface from URLs + subs
if os.path.exists('$SHARED_DIR/urls_all.txt'):
    with open('$SHARED_DIR/urls_all.txt') as f:
        urls = f.read().lower()
    signals['attack_surface'] = {
        'has_login': bool('login' in urls or 'signin' in urls),
        'has_register': bool('register' in urls or 'signup' in urls),
        'has_graphql': bool('graphql' in urls),
        'has_xml_api': False,  # Wave 3 probes discover this
        'has_json_api': bool('/api/' in urls),
        'has_payment': bool('payment' in urls or 'checkout' in urls or 'billing' in urls),
        'has_websocket': bool('ws:' in urls or 'wss:' in urls),
        'has_multitenant': bool('/org/' in urls or '/tenant/' in urls),
    }

with open('$SHARED_DIR/signals.json', 'w') as f:
    json.dump(signals, f, indent=2)
print('[merge]   signals.json written')
" 2>/dev/null || echo "[merge]   signals.json: skipped (Python error)"
fi

echo "[merge] ====== Wave $WAVE merge complete ======"
echo ""
