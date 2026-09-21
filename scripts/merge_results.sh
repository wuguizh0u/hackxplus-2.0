#!/bin/bash
# merge_results.sh — 原子合并 Agent 私有临时文件到共享数据层
# Usage: bash scripts/merge_results.sh --wave <1a|1b|1c|2|3> [--partial]
#
#   --partial  容许输入文件缺失（超时/失败的 Agent 数据不全时用）。
#              不带此标志时，缺失文件只会告警，不会中断（见下方 WARN）。
#              同时会拾取 $SHARED/partial/ 下保全的部分数据。

set -e

WAVE=""
PARTIAL=0
WORK_DIR="${WORK_DIR:-.}"

while [[ $# -gt 0 ]]; do
  case $1 in
    --wave)    WAVE="$2"; shift 2 ;;
    --partial) PARTIAL=1; shift ;;
    *) echo "Unknown: $1"; exit 1 ;;
  esac
done

[ -z "$WAVE" ] && echo "Usage: merge_results.sh --wave <1a|1b|1c|2|3> [--partial]" && exit 1

# 路径基准统一：优先用 init_hackprobe_dir 导出的 $TMP/$SHARED。
# 下面的 results/ 回退**仅用于未 init 的独立调用**（如单元测试）——
# 正常流程必须先调 init_hackprobe_dir，那时 $SHARED 已指向 {WORK_ROOT}/shared。
TMP_DIR="${TMP:-$WORK_DIR/results/tmp}"
SHARED_DIR="${SHARED:-$WORK_DIR/results/_shared}"
mkdir -p "$SHARED_DIR" "$SHARED_DIR/decisions"

echo "[merge] ====== Merging Wave $WAVE ======"
echo "[merge] Source: $TMP_DIR"
echo "[merge] Target: $SHARED_DIR"

# ====================================
# Wave-specific merge logic
# ====================================

# --partial 时把 $SHARED/partial/ 下同 basename 的文件也纳入输入
# （超时 Agent 的部分数据由 record_failure 保全到那里）
with_partial() {
  local out=()
  for f in "$@"; do
    out+=("$f")
    if [ "$PARTIAL" = "1" ]; then
      local p="$SHARED_DIR/partial/$(basename "$f")"
      [ -f "$p" ] && out+=("$p")
    fi
  done
  printf '%s\n' "${out[@]}"
}

merge_unique_lines() {
  local output="$1"
  shift
  local inputs=()
  while IFS= read -r line; do inputs+=("$line"); done < <(with_partial "$@")
  > "$SHARED_DIR/${output}.tmp"
  for f in "${inputs[@]}"; do
    [ -f "$f" ] && cat "$f" >> "$SHARED_DIR/${output}.tmp"
  done
  if [ -f "$SHARED_DIR/${output}.tmp" ] && [ -s "$SHARED_DIR/${output}.tmp" ]; then
    sort -u "$SHARED_DIR/${output}.tmp" > "$SHARED_DIR/$output"
    echo "[merge]   $output: $(wc -l < "$SHARED_DIR/$output" | tr -d ' ') lines (unique)"
  else
    # 无任何输入时也要建空文件 —— 下游会读，缺失会导致 FileNotFoundError
    : > "$SHARED_DIR/$output"
    echo "[merge]   $output: 0 lines (no input)"
  fi
  rm -f "$SHARED_DIR/${output}.tmp"
}

merge_json_append() {
  local output="$1"
  shift
  local inputs=("$@")
  # 路径经 argv 传入（见 signals.json 处的说明：中文路径不能展开进源码）
  python3 -c '
import json, sys, os
out_path = sys.argv[1]
merged = []
# ★ 先读现有输出文件 —— 这个函数是"追加"语义，跨 Wave 多次调用时
#   必须保留前一次的结果（否则 Wave 2 的 D2-CVE 会覆盖 Wave 1 的 2.5A/C）
if os.path.exists(out_path) and os.path.getsize(out_path) > 0:
    try:
        with open(out_path, encoding="utf-8") as fh:
            prev = json.load(fh)
            if isinstance(prev, list):
                merged.extend(prev)
    except Exception:
        pass
for f in sys.argv[2:]:
    if os.path.exists(f) and os.path.getsize(f) > 0:
        try:
            with open(f, encoding="utf-8") as fh:
                data = json.load(fh)
                if isinstance(data, list):
                    merged.extend(data)
                elif isinstance(data, dict):
                    merged.append(data)
        except Exception as e:
            sys.stderr.write(f"[merge] WARN: {f} 解析失败: {e}\n")
# Dedup by JSON string
seen, unique = set(), []
for item in merged:
    key = json.dumps(item, sort_keys=True)
    if key not in seen:
        seen.add(key)
        unique.append(item)
# 输入全空时也要建空数组 —— 下游会读，缺失会导致 FileNotFoundError
os.makedirs(os.path.dirname(out_path) or ".", exist_ok=True)
with open(out_path, "w", encoding="utf-8") as fh:
    json.dump(unique, fh, indent=2, ensure_ascii=False)
print(f"[merge]   {os.path.basename(out_path)}: {len(unique)} entries (merged from {len(merged)} raw)")
' "$SHARED_DIR/$output" "${inputs[@]}"
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
    echo "[merge]   ports.json: $(python3 -c 'import json,sys;print(len(json.load(open(sys.argv[1],encoding="utf-8"))))' "$SHARED_DIR/ports.json" 2>/dev/null || echo 0) verified ports"
  fi

  # Domain intelligence
  [ -f "$TMP_DIR/1a_a4_domain.txt" ] && cp "$TMP_DIR/1a_a4_domain.txt" "$SHARED_DIR/domain.json"

  # OSINT
  [ -f "$TMP_DIR/1a_a1_osint.txt" ] && cp "$TMP_DIR/1a_a1_osint.txt" "$SHARED_DIR/osint.json"

  # 🆕 Fragile subdomains
  if [ -f "$TMP_DIR/1a_a2_fragile_subs.json" ]; then
    cp "$TMP_DIR/1a_a2_fragile_subs.json" "$SHARED_DIR/fragile_subs.json"
    FRAGILE_COUNT=$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1],encoding="utf-8")).get("fragile_count",0))' "$SHARED_DIR/fragile_subs.json" 2>/dev/null || echo 0)
    echo "[merge]   fragile_subs.json: $FRAGILE_COUNT flagged subs"
  fi

  # 🆕 Host collision
  if [ -f "$TMP_DIR/1a_a5_hostcollision.json" ]; then
    cp "$TMP_DIR/1a_a5_hostcollision.json" "$SHARED_DIR/hostcollision.json"
    HITS=$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1],encoding="utf-8")).get("high_value_count",0))' "$SHARED_DIR/hostcollision.json" 2>/dev/null || echo 0)
    echo "[merge]   hostcollision.json: $HITS high-value hits"

    # 碰撞命中的 URL 追加到 urls_all.txt（路径经 argv 传入，避免中文路径被破坏）
    python3 -c '
import json, os, sys
cf, uf = sys.argv[1], sys.argv[2]
if os.path.exists(cf):
    with open(cf, encoding="utf-8") as f:
        data = json.load(f)
    urls = {h.get("url", "") for h in data.get("high_value_hits", []) if h.get("url")}
    existing = set()
    if os.path.exists(uf):
        with open(uf, encoding="utf-8") as f:
            existing = {line.strip() for line in f if line.strip()}
    new = urls - existing
    if new:
        with open(uf, "a", encoding="utf-8") as f:
            for u in sorted(new):
                f.write(u + "\n")
        print(f"[merge]   +{len(new)} URLs from host collision -> urls_all.txt")
' "$SHARED_DIR/hostcollision.json" "$SHARED_DIR/urls_all.txt" 2>/dev/null
  fi

# ====================================
# Wave 1b — 依赖 Wave 1a 的子域/端口结果
# ====================================
elif [ "$WAVE" = "1b" ]; then
  # B1-TechStack
  [ -f "$TMP_DIR/1b_b1_techstack.json" ] && cp "$TMP_DIR/1b_b1_techstack.json" "$SHARED_DIR/techstack.json"

  # httpx (SINGLE source of HTTP truth)
  if [ -f "$TMP_DIR/1b_b1_httpx.json" ]; then
    cat "$TMP_DIR/1b_b1_httpx.json" > "$SHARED_DIR/httpx.json"
    echo "[merge]   httpx.json: $(cat "$SHARED_DIR/httpx.json" | wc -l | tr -d ' ') lines"
  fi

  # B2-URLs (爬取 + dirsearch 轻扫 + 上下文字典产出的 URL)
  merge_unique_lines "urls_all.txt" \
    "$TMP_DIR/1b_b2_urls.txt" \
    "$TMP_DIR/1b_b2_dirsearch.txt"

  # URL classification (params for injection stages)
  if [ -s "$SHARED_DIR/urls_all.txt" ]; then
    grep -E '\?[^=]+=' "$SHARED_DIR/urls_all.txt" 2>/dev/null | sort -u > "$SHARED_DIR/params_all.txt"
    grep -iE '\?.*(url|redirect|dest|target|proxy|uri|path)=' "$SHARED_DIR/urls_all.txt" 2>/dev/null | sort -u > "$SHARED_DIR/params_redirect.txt"
    grep -iE '\?.*(id|uid|user_id|uuid)=' "$SHARED_DIR/urls_all.txt" 2>/dev/null | sort -u > "$SHARED_DIR/params_idor.txt"
    echo "[merge]   params_all.txt: $(wc -l < "$SHARED_DIR/params_all.txt" | tr -d ' ') URLs with params"
  fi

  # B3-Secrets (trufflehog + 手动正则 + JWT)
  [ -f "$TMP_DIR/1b_b3_secrets.txt" ] && cp "$TMP_DIR/1b_b3_secrets.txt" "$SHARED_DIR/secrets.json"
  # JWT tokens —— P20/P21 消费
  merge_unique_lines "jwt_tokens.txt" \
    "$TMP_DIR/1b_b3_jwt_tokens.txt"

# ====================================
# Wave 1c — 自动化检测
# ====================================
elif [ "$WAVE" = "1c" ]; then
  # C1-Defaults
  merge_json_append "defaults.json" \
    "$TMP_DIR/1c_c1_defaults.json"

  # 2.5A/C — CVE 映射（Wave 1 并行产出；Wave 2 的 D2-CVE 会追加到同一文件）
  merge_json_append "cve_mapping.json" \
    "$TMP_DIR/1c_cve.json"

  # C2-Sensitive (feroxbuster 结果也是 URL，一并并入 sensitive_files)
  merge_unique_lines "sensitive_files.txt" \
    "$TMP_DIR/1c_c2_sensitive.txt" \
    "$TMP_DIR/1c_c2_feroxbuster.txt"

  # C2-Upload 攻击面检测 → P27 消费
  [ -f "$TMP_DIR/1c_c2_upload_surface.json" ] && cp "$TMP_DIR/1c_c2_upload_surface.json" "$SHARED_DIR/upload_surface.json"

  # C3-SSL
  [ -f "$TMP_DIR/1c_c3_ssl.json" ] && cp "$TMP_DIR/1c_c3_ssl.json" "$SHARED_DIR/ssl.json"

# ====================================
# Wave 2 — 条件激活
# ====================================
elif [ "$WAVE" = "2" ]; then
  [ -f "$TMP_DIR/2_d1_nuclei.txt" ] && cp "$TMP_DIR/2_d1_nuclei.txt" "$SHARED_DIR/nuclei.json"

  # D3-DeepSubs —— 4 个工具各写私有子文件，此处合并
  merge_unique_lines "deep_subs.txt" \
    "$TMP_DIR/2_d3_subs.txt" \
    "$TMP_DIR/2_d3_ofa.txt" \
    "$TMP_DIR/2_d3_tide.txt" \
    "$TMP_DIR/2_d3_golin.txt" \
    "$TMP_DIR/2_d3_goon.txt"

  # D4-DeepDirs —— dirsearch + 御剑 双引擎合并
  merge_unique_lines "deep_dirs.txt" \
    "$TMP_DIR/2_d4_dirs.txt" \
    "$TMP_DIR/2_d4_dirsearch.txt" \
    "$TMP_DIR/2_d4_yujian.txt"

  # D5-JSDeep —— URLFinder + webfinder-next + vuescan + webpackscan
  merge_unique_lines "deep_js_endpoints.txt" \
    "$TMP_DIR/2_d5_js_endpoints.txt" \
    "$TMP_DIR/2_d5_js_urlfinder.txt" \
    "$TMP_DIR/2_d5_js_webfinder.txt" \
    "$TMP_DIR/2_d5_js_vuescan.txt" \
    "$TMP_DIR/2_d5_js_webpack.txt"

  [ -f "$TMP_DIR/2_d6_passwords.json" ] && cp "$TMP_DIR/2_d6_passwords.json" "$SHARED_DIR/passwords.json"

  # D2-CVE — 追加到 Wave 1 的 2.5A/C 结果（不能 cp，会覆盖 Wave 1 的映射）
  merge_json_append "cve_mapping.json" \
    "$TMP_DIR/2_d2_cve.json"

# ====================================
# Wave 3 — 探针结果 + 深度利用汇总
# ====================================
elif [ "$WAVE" = "3" ]; then
  [ -f "$TMP_DIR/3_probe_hits.json" ] && cp "$TMP_DIR/3_probe_hits.json" "$SHARED_DIR/probe_hits.json"

  # 深度利用产出（$SHARED/04_<skill>.md）由 wave3 Step 4 直写共享层，无需中转。
  # 这里只在旧版布局残留时做一次兜底搬运。
  for f in "$TMP_DIR"/04_*.md "$TMP_DIR"/3_exploit_*.md; do
    [ -f "$f" ] && cp "$f" "$SHARED_DIR/" 2>/dev/null
  done
  ls "$SHARED_DIR"/04_*.md >/dev/null 2>&1 && \
    echo "[merge]   deep-exploitation: $(ls "$SHARED_DIR"/04_*.md 2>/dev/null | wc -l | tr -d ' ') files"
fi

# ====================================
# Post-merge: 生成/更新 signals.json
# ====================================
if [ "$WAVE" = "1b" ] || [ "$WAVE" = "2" ]; then
  echo "[merge] Generating signals.json..."
  # 注意: 路径必须经 sys.argv 传入, 不能在源码字符串里展开 "$SHARED_DIR"
  # 原因: git-bash 无 LANG 时按 GBK 处理, 含中文的路径展开进 Python 源码会被破坏
  python3 - "$SHARED_DIR" <<'PYEOF' || echo "[merge]   signals.json: skipped (Python error)"
import json, os, re, sys

sd = sys.argv[1]
signals = {'tech': {}, 'attack_surface': {}, 'infra': {}}

# Tech signals from techstack
ts_path = os.path.join(sd, 'techstack.json')
if os.path.exists(ts_path):
    try:
        with open(ts_path, encoding='utf-8') as f:
            ts = json.load(f)
        signals['tech'] = {
            'language': ts.get('language'),
            'backend': ts.get('backend') or ts.get('server'),
            'server': ts.get('server'),
            'frontend': ts.get('frontend'),
            'cms': ts.get('cms'),
            'template_engine': ts.get('template_engine'),
            'database': ts.get('database', []),
        }
    except Exception as e:
        sys.stderr.write(f'[merge] WARN: techstack 解析失败: {e}\n')

# Attack surface from URLs
urls_path = os.path.join(sd, 'urls_all.txt')
if os.path.exists(urls_path):
    with open(urls_path, encoding='utf-8') as f:
        urls = f.read().lower()
    signals['attack_surface'] = {
        'has_login': bool('login' in urls or 'signin' in urls),
        'has_register': bool('register' in urls or 'signup' in urls),
        'has_graphql': bool('graphql' in urls),
        'has_xml_api': False,   # Wave 3 probes discover this
        'has_json_api': bool('/api/' in urls),
        'has_payment': bool('payment' in urls or 'checkout' in urls or 'billing' in urls),
        'has_websocket': bool('ws:' in urls or 'wss:' in urls),
        'has_multitenant': bool('/org/' in urls or '/tenant/' in urls),
    }

# has_upload / has_jwt —— 从 Wave 1c 的产物推断（之前缺失导致这两个信号恒为 None）
if os.path.exists(os.path.join(sd, 'upload_surface.json')):
    signals['attack_surface']['has_upload'] = True
elif os.path.exists(urls_path) and re.search(r'/(upload|file|attach|avatar|import)', urls):
    signals['attack_surface']['has_upload'] = True

jwt_path = os.path.join(sd, 'jwt_tokens.txt')
if os.path.exists(jwt_path) and os.path.getsize(jwt_path) > 0:
    signals['attack_surface']['has_jwt'] = True

# infra 基础字段
signals['infra'].setdefault('open_ports', [])
ports_path = os.path.join(sd, 'ports.json')
if os.path.exists(ports_path):
    try:
        with open(ports_path, encoding='utf-8') as f:
            p = json.load(f)
        tcp = p.get('tcp', p) if isinstance(p, dict) else {}
        signals['infra']['open_ports'] = sorted(
            int(k) for k in tcp.keys() if str(k).isdigit())
    except Exception:
        pass

# ★ 合并而非覆盖 —— signal_router.md 会往同一个文件追加 matched_skills。
#   直接写会把它的结果冲掉（两者都在 Wave 3 前后写这一份）。
sig_path = os.path.join(sd, 'signals.json')
existing = {}
if os.path.exists(sig_path):
    try:
        with open(sig_path, encoding='utf-8') as f:
            existing = json.load(f)
    except Exception:
        existing = {}
for k, v in signals.items():
    if isinstance(v, dict) and isinstance(existing.get(k), dict):
        merged = dict(v)
        for kk, vv in existing[k].items():
            if vv not in (None, '', [], {}):
                merged[kk] = vv      # 已存在且非空的值优先（不覆盖 signal_router 的检测）
        existing[k] = merged
    elif k not in existing or existing[k] in (None, '', [], {}):
        existing[k] = v

with open(sig_path, 'w', encoding='utf-8') as f:
    json.dump(existing, f, indent=2, ensure_ascii=False)
print('[merge]   signals.json written (merged)')
PYEOF
fi

echo "[merge] ====== Wave $WAVE merge complete ======"
echo ""
