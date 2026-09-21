# Signal Router — 信号→技能映射表

> **Wave 3 Step 2 执行。** 从 Wave 1/2 产出提取信号，匹配 hack-skills。信号→探针的触发逻辑在 `probes/tier2_signal.md` 的 `run_probes_tier2()` 中以 bash 条件直接处理。通用探针见 `probes/tier1_universal.md`。

---

## 信号→技能映射（hack-skills 深度利用）

### 技术栈信号

| 信号 | 匹配条件 | 加载的 hack-skills |
|------|---------|-------------------|
| Java | server 含 Tomcat/Jetty/WebLogic/JBoss/WildFly/GlassFish/Resin | `deserialization-insecure` `ghost-bits-cast-attack` `jndi-injection` `expression-language-injection` |
| Spring Boot | header 含 `X-Application-Context` 或 server "Spring Boot" | `deserialization-insecure` `jndi-injection` `401-403-bypass-techniques` |
| PHP | `X-Powered-By: PHP` 或 PHP 文件扩展 | `type-juggling` `deserialization-insecure` `path-traversal-lfi` |
| .NET/IIS | server IIS/ASP.NET 或 `X-AspNet-Version` | `deserialization-insecure` `xslt-injection` |
| Laravel | `laravel_session` cookie 或 `.env` 可访问 | `path-traversal-lfi` `upload-insecure-files` |
| Django | `csrftoken` + `django_language` cookie | `csrf-cross-site-request-forgery` `idor-broken-object-authorization` |
| WordPress | `wp-content` / `wp-login.php` / `xmlrpc.php` | `upload-insecure-files` `authbypass-authentication-flaws` |
| Node/Express | server "Express" 或 `X-Powered-By: Express` | `prototype-pollution` `nosql-injection` |
| Next.js | HTML 含 `__NEXT_DATA__` / `_next/static` | `path-traversal-lfi` |
| Nuxt.js | HTML 含 `__NUXT__` | `path-traversal-lfi` |

### 模板引擎信号

| 信号 | 匹配条件 | 加载 |
|------|---------|------|
| Jinja2 / Twig / EJS / Pug / Smarty | 各自语法特征在响应中出现 | `ssti-server-side-template-injection` |
| Thymeleaf | `${` + Spring Boot 特征 | `ssti-server-side-template-injection` `expression-language-injection` |
| 任意 SSTI | 探针 P3 命中 (响应中出现 `49`) | `ssti-server-side-template-injection` |

### 攻击面信号

| 信号 | 匹配条件 | 加载 |
|------|---------|------|
| 有登录/注册 | `/login` `/signin` `/register` `/signup` `/auth` | `authbypass-authentication-flaws` `csrf-cross-site-request-forgery` `race-condition` |
| 有 JWT | JS/URL/localStorage 含 `eyJ` token | `jwt-oauth-token-attacks` |
| 有 OAuth | `/oauth` `/oidc` `/openid` `/saml` | `oauth-oidc-misconfiguration` `saml-sso-assertion-attacks` |
| 有文件上传 | `upload_surface.json` 或 `/upload` `/file` `/import` | `upload-insecure-files` |
| 有 GraphQL | `/graphql` `/gql` 返回 `__typename` | `graphql-and-hidden-parameters` |
| 有支付页 | `/payment` `/checkout` `/billing` `/subscribe` | `business-logic-vulnerabilities` `race-condition` `csrf-cross-site-request-forgery` |
| 有 CSV/Excel 导出 | URL 含 `csv` `excel` `export` `download` | `csv-formula-injection` |
| 有 WebSocket | 页面源码含 `ws://` 或 `wss://` | `websocket-security` |
| 多租户 | `/org/{id}` `/tenant/{id}` `/workspace/{id}` | `idor-broken-object-authorization` `business-logic-vulnerabilities` |

### 基础设施信号

| 信号 | 匹配条件 | 加载 |
|------|---------|------|
| CNAME→云服务 | 子域 CNAME 指向 CloudFront/Heroku/Azure/S3 | `subdomain-takeover` |
| SCM 暴露 | `/.git/HEAD` 或 `/.svn/entries` 或 `/.env` | `insecure-source-code-management` |
| /actuator 暴露 | Spring Boot actuator 端点可达 | `deserialization-insecure` `401-403-bypass-techniques` |
| CDN/WAF 存在 | Cloudflare/Akamai/Imperva/F5 | `waf-bypass-techniques` `http2-specific-attacks` |
| CORS 有发现 | 任意 Origin 反射 + credentials | `cors-cross-origin-misconfiguration` |
| 邮件安全缺失 | SPF/DMARC/DKIM 缺失 | `email-header-injection` |
| 反向代理 | Nginx/Apache/Traefik | `http-host-header-attacks` `request-smuggling` |

### 探针反馈信号

| 触发条件 | 新信号 | 追加技能 |
|---------|--------|---------|
| P3 SSTI 命中 | 模板引擎存在 | `ssti-server-side-template-injection` |
| P8 Java Deser 命中 | Java 反序列化可触达 | `ghost-bits-cast-attack` `jndi-injection` |
| P9 PHP Deser 命中 | PHP 反序列化可触达 | `deserialization-insecure` (PHP 链) |
| P26 LFI 读到 `/proc/self/environ` | 环境变量可读 | `cmdi-command-injection` |
| P29 SCM 泄露确认 | 源码完全可读 | 搜索 hardcoded secrets |
| GraphQL 暴露 dev mutation | GraphQL 有危险操作 | `business-logic-vulnerabilities` |
| SSRF 可达内部 metadata | 云环境 SSRF 可用 | `dns-rebinding-attacks` |

---

### 隐式框架检测（不依赖 Server 头）

> 生产环境 Server 头经常被 strip/伪造/隐藏。隐式检测从 Cookie、错误消息、HTML 特征推断，准确度更高。

| 检测方法 | 信号 | 推断 | 可信度 |
|---------|------|------|--------|
| Cookie 名 | `JSESSIONID` | Java (Tomcat/Jetty/JBoss) | High |
| Cookie 名 | `PHPSESSID` | PHP | High |
| Cookie 名 | `ASP.NET_SessionId` | .NET/IIS | High |
| Cookie 名 | `laravel_session` | Laravel (PHP) | High |
| Cookie 名 | `csrftoken` + `django_language` | Django (Python) | Medium |
| Cookie 名 | `connect.sid` | Express/Node.js | Medium |
| 错误页面 | `org.springframework` 报错 | Java/Spring Boot | High |
| 错误页面 | `PDOException` `Fatal error: Uncaught` | PHP | High |
| 错误页面 | `Object reference not set` `Server Error in '/' Application` | .NET | High |
| 错误页面 | `Traceback (most recent call last)` | Python (Flask/Django) | High |
| HTML meta | `<meta name="generator" content="WordPress` | WordPress | High |
| HTML script | `/_next/static` | Next.js | High |
| HTML script | `__NUXT__` | Nuxt.js | High |
| HTML link | `/wp-content/themes` | WordPress | High |
| 响应特征 | `X-Drupal-` 头 | Drupal | High |

---

## 信号收集脚本（Wave 3 Step 2 执行）

读 `_shared/` 产出，匹配 hack-skills → 写入 `signals.json`。

```bash
# 路径经 argv 传入（quoted heredoc 不展开 shell 变量；直接内联 $SHARED 又会因
# 中文路径被 git-bash 的 GBK 破坏）
python3 - "$SHARED" "$TMP" << 'PYEOF'
import json, os, re, sys

SHARED, TMP = sys.argv[1], sys.argv[2]

# ====== PART A: Implicit framework detection ======
def detect_implicit_lang():
    """Detect language/framework from cookies, error pages, HTML without Server header"""
    detected = {'language': None, 'framework': None, 'cms': None, 'evidence': []}
    
    # Read HTTP headers from httpx or homepage
    headers = ""
    for f in [f'{SHARED}/httpx.json', f'{TMP}/0a_homepage_headers.txt']:
        if os.path.exists(f):
            try:
                with open(f, errors='ignore') as fh:
                    headers += fh.read()[:5000]
            except: pass
    
    headers_lower = headers.lower()
    
    # Cookie-based detection (does NOT rely on Server header)
    if 'jsessionid' in headers_lower:
        detected['language'] = 'java'
        detected['framework'] = 'Java Servlet (Tomcat/Jetty/JBoss)'
        detected['evidence'].append('Set-Cookie: JSESSIONID')
    if 'phpsessid' in headers_lower:
        detected['language'] = 'php'
        detected['evidence'].append('Set-Cookie: PHPSESSID')
    if 'asp.net_sessionid' in headers_lower:
        detected['language'] = '.net'
        detected['framework'] = 'ASP.NET/IIS'
        detected['evidence'].append('Set-Cookie: ASP.NET_SessionId')
    if 'laravel_session' in headers_lower:
        detected['language'] = 'php'
        detected['framework'] = 'Laravel'
        detected['evidence'].append('Set-Cookie: laravel_session')
    if 'connect.sid' in headers_lower:
        detected['language'] = 'javascript'
        detected['framework'] = 'Express/Node.js'
        detected['evidence'].append('Set-Cookie: connect.sid')
    if 'csrftoken' in headers_lower and 'django' in headers_lower:
        detected['language'] = 'python'
        detected['framework'] = 'Django'
        detected['evidence'].append('Django: csrftoken + django_language cookie')
    
    # HTML-based detection
    homepage = ""
    for f in [f'{TMP}/0a_homepage.html']:
        if os.path.exists(f):
            try:
                with open(f, 'r', encoding='utf-8', errors='ignore') as fh:
                    homepage = fh.read()[:20000]
            except: pass
    
    homepage_lower = homepage.lower()
    
    # CMS detection from HTML
    if 'wp-content' in homepage_lower or 'wp-includes' in homepage_lower:
        detected['cms'] = 'WordPress'
        detected['language'] = detected['language'] or 'php'
        detected['evidence'].append('HTML: WordPress signatures')
    if 'drupal' in homepage_lower and ('sites/default' in homepage_lower or 'x-drupal' in headers_lower):
        detected['cms'] = 'Drupal'
        detected['language'] = detected['language'] or 'php'
        detected['evidence'].append('HTML: Drupal signatures')
    if 'joomla' in homepage_lower:
        detected['cms'] = 'Joomla'
        detected['language'] = detected['language'] or 'php'
        detected['evidence'].append('HTML: Joomla signatures')
    if 'magento' in homepage_lower or 'mage/' in homepage_lower:
        detected['cms'] = 'Magento'
        detected['language'] = detected['language'] or 'php'
        detected['evidence'].append('HTML: Magento signatures')
    
    # SPA framework detection
    if '/_next/static' in homepage_lower or '__NEXT_DATA__' in homepage:
        detected['framework'] = detected['framework'] or 'Next.js'
        detected['evidence'].append('HTML: Next.js')
    if '__NUXT__' in homepage or '/_nuxt/' in homepage_lower:
        detected['framework'] = detected['framework'] or 'Nuxt.js'
        detected['evidence'].append('HTML: Nuxt.js')
    if 'ng-app' in homepage_lower or 'ng-version' in homepage_lower:
        detected['framework'] = detected['framework'] or 'Angular'
        detected['evidence'].append('HTML: Angular')
    
    # Error-page language detection
    for f in os.listdir('results'):
        if not f.endswith('.txt') and not f.endswith('.html'): continue
        fpath = os.path.join(SHARED, f)
        try:
            with open(fpath, 'r', encoding='utf-8', errors='ignore') as fh:
                content = fh.read()[:5000]
            content_lower = content.lower()
            
            if not detected['language'] or detected['language'] == 'unknown':
                if 'org.springframework' in content or 'java.lang.' in content:
                    detected['language'] = 'java'
                    detected['framework'] = detected['framework'] or 'Spring Boot'
                    detected['evidence'].append(f'Error: Java stack trace in {f}')
                if 'pdoexception' in content_lower or 'fatal error: uncaught' in content_lower:
                    detected['language'] = 'php'
                    detected['evidence'].append(f'Error: PHP error in {f}')
                if 'object reference not set' in content_lower or "server error in '/' application" in content_lower:
                    detected['language'] = '.net'
                    detected['framework'] = detected['framework'] or 'ASP.NET'
                    detected['evidence'].append(f'Error: .NET stack trace in {f}')
                if 'traceback (most recent call last)' in content_lower:
                    detected['language'] = 'python'
                    detected['evidence'].append(f'Error: Python traceback in {f}')
        except: pass
    
    return detected

implicit = detect_implicit_lang()
print(f"[signals] Implicit detection: lang={implicit['language']} framework={implicit['framework']} cms={implicit['cms']}")
for e in implicit['evidence']:
    print(f"  → {e}")

# ====== PART B: Signal extraction & hack-skills matching ======
signals = {'tech': {}, 'attack_surface': {}, 'infra': {}, 'matched_skills': []}
if os.path.exists(f'{SHARED}/signals.json'):
    with open(f'{SHARED}/signals.json') as f:
        pre = json.load(f)
        signals['tech'] = pre.get('tech', {})
        signals['attack_surface'] = pre.get('attack_surface', {})
        signals['infra'] = pre.get('infra', {})

# Override tech signals with implicit detection if httpx-based detection is null
if not signals['tech'].get('language') and implicit['language']:
    signals['tech']['language'] = implicit['language']
    signals['tech']['_detection_source'] = 'implicit'
    print(f"[signals] Override: language={implicit['language']} (implicit detection)")
if not signals['tech'].get('framework') and implicit['framework']:
    signals['tech']['framework'] = implicit['framework']
if not signals['tech'].get('cms') and implicit['cms']:
    signals['tech']['cms'] = implicit['cms']

matched = set()
lang = signals['tech'].get('language', '').lower()
server = (signals['tech'].get('server') or signals['tech'].get('backend', '')).lower()

if 'java' in lang or any(s in server for s in ['tomcat','jetty','weblogic','jboss','wildfly','glassfish','resin']):
    matched.update(['deserialization-insecure', 'ghost-bits-cast-attack', 'jndi-injection', 'expression-language-injection'])
if 'spring boot' in server or 'spring' in server:
    matched.update(['deserialization-insecure', 'jndi-injection', '401-403-bypass-techniques'])
if 'php' in lang or 'php' in server:
    matched.update(['type-juggling', 'deserialization-insecure', 'path-traversal-lfi'])
if '.net' in server or 'asp.net' in server or 'iis' in server:
    matched.update(['deserialization-insecure', 'xslt-injection'])
if 'laravel' in server:
    matched.update(['path-traversal-lfi', 'upload-insecure-files'])
if 'express' in server or 'node.js' in server:
    matched.update(['prototype-pollution', 'nosql-injection'])

te = signals['tech'].get('template_engine', '')
if te: matched.add('ssti-server-side-template-injection')
if te and 'thymeleaf' in str(te).lower(): matched.add('expression-language-injection')

as_ = signals.get('attack_surface', {})
if as_.get('has_login') or as_.get('has_register'):
    matched.update(['authbypass-authentication-flaws', 'csrf-cross-site-request-forgery', 'race-condition'])
if as_.get('has_jwt') or signals.get('has_jwt'): matched.add('jwt-oauth-token-attacks')
if as_.get('has_graphql'): matched.add('graphql-and-hidden-parameters')
if as_.get('has_payment'): matched.update(['business-logic-vulnerabilities', 'race-condition'])
if as_.get('has_upload') or os.path.exists(f'{SHARED}/upload_surface.json'): matched.add('upload-insecure-files')
if as_.get('has_multitenant'): matched.update(['idor-broken-object-authorization', 'business-logic-vulnerabilities'])
if as_.get('has_xml_api'): matched.update(['xxe-xml-external-entity', 'xslt-injection'])
if as_.get('has_json_api'): matched.update(['api-authorization-and-bola', 'http-parameter-pollution'])

infra = signals.get('infra', {})
if infra.get('cname_to_cloud'): matched.add('subdomain-takeover')
if infra.get('scm_exposed'): matched.add('insecure-source-code-management')
if infra.get('waf_present') or infra.get('cdn_present'): matched.update(['waf-bypass-techniques', 'http2-specific-attacks'])
if infra.get('exposed_actuator'): matched.update(['deserialization-insecure', '401-403-bypass-techniques'])
if not infra.get('email_security', {}).get('spf') or not infra.get('email_security', {}).get('dmarc'): matched.add('email-header-injection')
if os.path.exists(f'{SHARED}/ssl.json'): matched.add('cors-cross-origin-misconfiguration')
if os.path.exists(f'{SHARED}/urls_all.txt'):
    with open(f'{SHARED}/urls_all.txt') as f: urls = f.read()
    if re.search(r'/(csv|excel|export|download\.(csv|xls))', urls, re.I): matched.add('csv-formula-injection')
    if re.search(r'(ws://|wss://)', urls, re.I): matched.add('websocket-security')

signals['matched_skills'] = sorted(matched)
with open(f'{SHARED}/signals.json', 'w') as f:
    json.dump(signals, f, indent=2)

print(f'[signals] {len(matched)} matched hack-skills:')
for s in sorted(matched): print(f'  → {s}')
PYEOF
```
