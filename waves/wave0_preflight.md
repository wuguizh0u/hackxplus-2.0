# Wave 0 — Pre-flight 威胁建模（10-15 秒，不阻塞 Wave 1）

> Wave 1 Agent 启动后读 `_shared/target_profile.json`，存在就用，不存在按默认策略。

## Step 0a — 首页特征 + 0b 技术栈 + 0c DNS/WAF

```bash
# $HACKPROBE_* 已由 discover_tools.sh 导出，缺少则降级
URL="<URL>"; HOST="<HOST>"
WORK_DIR="${WORK_ROOT:-$(pwd)/${HOST}}"
TMP="${TMP:-${WORK_DIR}/_work/tmp}"
SHARED="${SHARED:-${WORK_DIR}/_work/shared}"
mkdir -p "$TMP" "$SHARED"

# 抓首页 (curl always available)
curl -sk -L --connect-timeout 5 --max-time 10 -D "$TMP/0a_homepage_headers.txt" -o "$TMP/0a_homepage.html" "$URL" 2>/dev/null

# 技术栈指纹: httpx → whatweb fallback → 手动 HTML 分析
if [ -n "$HACKPROBE_HTTPX" ]; then
  "$HACKPROBE_HTTPX" -u "$URL" -tech-detect -json -timeout 10 -silent 2>/dev/null > "$TMP/0b_httpx.json" || echo '{}' > "$TMP/0b_httpx.json"
else
  echo '[wave0] httpx not found — using HTML manual fingerprint' > "$TMP/0b_httpx.json"
fi

# DNS: dig → nslookup → python socket
if [ "$HACKPROBE_DIG" = "dig" ] 2>/dev/null; then
  HOST_IP=$(dig +short "$HOST" 2>/dev/null | head -1)
  CNAME=$(dig CNAME "$HOST" +short 2>/dev/null | head -1)
elif command -v nslookup >/dev/null 2>&1; then
  HOST_IP=$(nslookup "$HOST" 2>/dev/null | grep -E "^Address" | tail -1 | awk '{print $NF}')
  CNAME=""  # nslookup 不直接给 CNAME
else
  HOST_IP=$(python3 -c "import socket;print(socket.gethostbyname('$HOST'))" 2>/dev/null)
  CNAME=""
fi
```

## 汇总 → target_profile.json

```bash
python3 << 'PYEOF'
import json, os, re

WORK_DIR = os.environ.get("WORK_ROOT", os.getcwd())
TMP = os.environ.get("TMP", f"{WORK_DIR}/_work/tmp")
SHARED = os.environ.get("SHARED", f"{WORK_DIR}/_work/shared")
HOST = os.environ.get("HOST", ""); URL = os.environ.get("URL", "")

html = open(f"{TMP}/0a_homepage.html", errors='ignore').read()[:30000] if os.path.exists(f"{TMP}/0a_homepage.html") else ""
hdrs = open(f"{TMP}/0a_homepage_headers.txt", errors='ignore').read() if os.path.exists(f"{TMP}/0a_homepage_headers.txt") else ""
hdrs_lower = hdrs.lower(); html_lower = html.lower()

# httpx tech
httpx_tech = []
if os.path.exists(f"{TMP}/0b_httpx.json"):
    for line in open(f"{TMP}/0b_httpx.json"):
        try: httpx_tech = json.loads(line).get("tech", []); break
        except: pass

# CDN (top 5)
cdn = "none"
for h, p in [("cf-ray","Cloudflare"),("x-amz-cf-id","AWS"),("x-cache-hits","Fastly"),("x-aliyun-cdn","Aliyun"),("akamai-origin-hop","Akamai")]:
    if h in hdrs_lower: cdn = p; break
cname = os.environ.get("CNAME","")
if cname:
    for pat, p in [("cloudfront.net","AWS"),("akamai","Akamai"),("fastly.net","Fastly")]:
        if pat in cname.lower(): cdn = p

# WAF
waf = any(s in (hdrs_lower + html_lower[:5000]) for s in [
    'cloudflare','akamai','imperva','f5','fortiweb','sucuri','incapsula','awsalb','tencent cloud waf','wallarm'
])

# Forms
has_form = bool(re.search(r'<form\b', html, re.I))
has_login = bool(re.search(r'<form[^>]*?(?:login|signin|sign-in)', html, re.I))
has_register = bool(re.search(r'<form[^>]*?(?:register|signup|sign-up)', html, re.I))

# SPA detection
body = re.search(r'<body[^>]*>(.*?)</body>', html, re.I | re.S)
body_text = re.sub(r'<[^>]+>', '', body.group(1) if body else html).strip()
js_bundles = len(re.findall(r'(?:\.js|chunk|bundle)["\']', html[:5000]))
is_spa = bool(('<div id="root">' in html or '<div id="app">' in html) and len(body_text) < 200 and js_bundles >= 1)

# API evidence
has_api = bool(re.search(r'fetch\(|XMLHttpRequest|/api/|/graphql', html[:10000], re.I))

# Auth cookies
has_auth_cookie = bool(re.search(r'set-cookie:.*(?:session|auth|token|jwt|sid|jsessionid|phpsessid)', hdrs, re.I | re.M))

# === Classification ===
# static: ALL 5 checks must pass
static_checks = (len(body_text) > 100 and not has_form and not has_api and not has_auth_cookie)
is_static_gen = any(s in html_lower[:5000] for s in ['hugo','jekyll','github.io','gitlab.io','netlify','vercel'])

if is_static_gen and static_checks: target_type = "static"
elif is_spa: target_type = "spa"
elif has_api and len(body_text) < 200: target_type = "api-only"
elif any(k in HOST.lower() for k in ['bank','pay','wallet','finance','loan','trade']): target_type = "fintech"
else: target_type = "unknown"

profile = {
    "classification": {"type": target_type, "confidence": "medium" if target_type=="unknown" else "high", "is_spa": is_spa},
    "infra": {"waf_likely": waf, "cdn": cdn, "host_ip": os.environ.get("HOST_IP","")},
    "features": {"has_login": has_login, "has_register": has_register, "has_api_evidence": has_api, "has_form": has_form, "has_set_cookie": has_set_cookie},
    "httpx_tech": httpx_tech,
}
with open(f"{SHARED}/target_profile.json", "w") as f:
    json.dump(profile, f, indent=2)

print(f"[wave0] type={target_type} cdn={cdn} waf={'YES' if waf else 'no'} spa={is_spa} login={has_login} register={has_register}")
print(f"[wave0] → {SHARED}/target_profile.json")
PYEOF
```

## 类型驱动策略速查

| Type | Wave 1 调整 | Wave 2 | Wave 3 |
|------|------------|--------|--------|
| **static** | A3 仅 80/443 | SKIP | headers+CORS only |
| **spa** | A2 加 api/docs/dev 字典 | FULL + JS 端点 | API fuzz 优先 |
| **cms** | A2 加 CMS 插件字典 | FULL + CVE | CMS 专杀优先 |
| **fintech** | A3 限速 | REDUCED | 手动 bypass 优先 |
| **unknown** | 全默认策略 | 正常 | 正常 |

> **SPA ≠ Static.** 5 条全满足才是 static：①可见文本>100字符 ②无 `<form>` ③无 XHR/fetch ④无 auth cookie ⑤技术栈确认为静态生成器。
