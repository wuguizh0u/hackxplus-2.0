#!/usr/bin/env python3
"""Context-aware directory dictionary generator for hackprobe.
Generates target-specific directory wordlist based on:
- Business naming rules
- Tech stack detection
- Observed API format patterns

Usage: python3 gen_custom_dirs.py [options]
  --host HOST           Target host
  --url URL             Target base URL
  --company COMPANY     Company short name
  --urls-file FILE      File with already-collected URLs (all_urls.txt)
  --output FILE         Output wordlist (default: custom_dirs.txt)
"""

import argparse
import os
import re
import sys


def generate(host, url, company_short, urls_file=None):
    domain = host.replace('www.', '')
    company_words = company_short.replace('-', ' ').replace('_', ' ').split()
    
    custom = []
    
    # === 1. Business keyword extraction ===
    business_keywords = {
        'med': ['medical', 'doctor', 'patient', 'clinic', 'hospital', 'health', 'pharmacy',
                 'nurse', 'lab', 'radiology', 'imaging', 'report', 'detect', 'diagnose',
                 'prescription', 'ehr', 'emr', 'his', 'appointment', 'consultation', 'surgery', 'treatment'],
        'health': ['medical', 'doctor', 'patient', 'clinic', 'hospital', 'health', 'pharmacy',
                    'nurse', 'lab', 'report', 'prescription', 'ehr', 'emr'],
        'pay': ['payment', 'pay', 'billing', 'invoice', 'wallet', 'finance', 'accounting',
                 'ledger', 'settle', 'transaction', 'checkout', 'subscription', 'plan', 'pricing',
                 'refund', 'charge', 'balance'],
        'fin': ['payment', 'pay', 'billing', 'invoice', 'wallet', 'finance', 'accounting',
                 'ledger', 'transaction', 'checkout', 'subscription', 'pricing'],
        'bank': ['payment', 'finance', 'account', 'ledger', 'transaction', 'checkout', 'balance'],
        'shop': ['shop', 'store', 'mall', 'cart', 'order', 'product', 'goods', 'merchant',
                  'vendor', 'catalog', 'category', 'inventory', 'promotion', 'coupon', 'review',
                  'rating', 'wishlist'],
        'store': ['shop', 'store', 'cart', 'order', 'product', 'catalog', 'category', 'inventory'],
        'edu': ['course', 'class', 'student', 'teacher', 'exam', 'training', 'lms', 'campus',
                 'enrollment', 'curriculum', 'grade', 'assignment', 'quiz', 'certificate'],
        'cloud': ['dashboard', 'console', 'admin', 'manage', 'service', 'platform', 'module',
                   'plugin', 'integration', 'connector', 'webhook', 'workflow', 'automation',
                   'pipeline', 'deploy'],
        'api': ['dashboard', 'console', 'admin', 'manage', 'service', 'platform', 'api',
                 'integration', 'connector', 'webhook', 'pipeline', 'deploy'],
        'media': ['article', 'post', 'category', 'tag', 'author', 'publish', 'feed', 'channel',
                   'album', 'gallery', 'playlist', 'episode', 'show', 'live', 'stream'],
        'news': ['article', 'post', 'category', 'tag', 'author', 'publish', 'feed', 'channel'],
        'blog': ['article', 'post', 'category', 'tag', 'author', 'publish', 'feed'],
    }
    
    business_prefixes = []
    for w in company_words:
        wl = w.lower()
        for keyword, prefixes in business_keywords.items():
            if keyword in wl:
                business_prefixes.extend(prefixes)
    
    # === 2. Tech stack specific paths ===
    tech_paths = [
        # Next.js
        '/_next', '/_next/static', '/_next/data', '/_next/image', '/__nextjs_original-stack-frame',
        # Nuxt
        '/__nuxt', '/_nuxt', '/__nuxt_error',
        # React
        '/static/js', '/static/css', '/static/media', '/asset-manifest.json', '/service-worker.js',
        # Vue
        '/js/app.js', '/css/app.css', '/manifest.json',
        # Angular
        '/main.js', '/polyfills.js', '/styles.css', '/assets/',
        # Laravel
        '/storage', '/storage/logs', '/storage/framework', '/vendor', '/artisan', '/routes', '/bootstrap/cache',
        # Django
        '/static/admin', '/static/rest_framework', '/media', '/admin', '/api-auth', '/__debug__',
        # Spring Boot
        '/actuator', '/actuator/health', '/actuator/info', '/actuator/env', '/actuator/mappings',
        '/actuator/beans', '/actuator/metrics', '/actuator/loggers', '/actuator/heapdump', '/actuator/threaddump',
        # Express / Node
        '/package.json', '/node_modules', '/server.js', '/app.js', '/routes', '/middleware', '/views', '/public',
        # WordPress
        '/wp-admin', '/wp-content', '/wp-includes', '/wp-json', '/wp-login.php', '/xmlrpc.php',
        '/wp-cron.php', '/wp-config.php', '/wp-content/uploads',
        # Drupal
        '/user/login', '/user/register', '/admin/content', '/admin/config', '/node', '/sites/default/files',
        # PHP general
        '/phpinfo.php', '/info.php', '/test.php', '/phpmyadmin', '/pma', '/vendor/phpunit',
        '/composer.json', '/composer.lock', '/.env', '/.env.local', '/.env.production',
        '/config.php', '/config.yml', '/config.yaml',
        # Java general
        '/WEB-INF', '/META-INF', '/pom.xml', '/build.gradle', '/application.properties',
        '/application.yml', '/log4j', '/struts', '/seam', '/faces',
        # Python general
        '/requirements.txt', '/setup.py', '/Pipfile', '/pyproject.toml', '/wsgi.py', '/asgi.py',
        # Go general
        '/go.mod', '/go.sum', '/main.go', '/cmd',
        # Nginx/Apache
        '/nginx.conf', '/nginx_status', '/server-status', '/server-info', '/.htaccess', '/.htpasswd',
    ]
    custom.extend(tech_paths)
    
    # === 3. API format pattern inference from observed URLs ===
    observed_paths = []
    if urls_file and os.path.exists(urls_file):
        try:
            with open(urls_file, 'r') as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith('#'):
                        continue
                    m = re.match(r'https?://[^/]+(/[^?#]*)', line)
                    if m:
                        path = m.group(1)
                        if path and path != '/':
                            observed_paths.append(path)
        except Exception:
            pass
    
    api_patterns = set()
    for p in observed_paths:
        vm = re.search(r'/(v\d+(?:\.\d+)?)/', p)
        if vm:
            api_patterns.add(vm.group(1))
        parts = [x for x in p.split('/') if x and not re.match(r'^\d+$', x) and len(x) < 36]
        if parts:
            api_patterns.add(parts[0])
    
    print(f'[+] Detected API path patterns from {len(observed_paths)} observed URLs: {list(api_patterns)[:20]}')
    
    for base in list(api_patterns)[:10]:
        for suffix in ['list', 'create', 'update', 'delete', 'detail', 'search', 'export',
                       'import', 'batch', 'count', 'stats', 'history', 'log', 'status',
                       'config', 'setting', 'meta', 'schema']:
            custom.append(f'/{base}/{suffix}')
            custom.append(f'/{base}/get{suffix.capitalize()}')
            custom.append(f'/{base}/{suffix}s')
    
    # === 4. Business-specific directory names ===
    business_dirs = set()
    for w in company_words:
        if len(w) >= 3:
            business_dirs.add(f'/{w}')
            business_dirs.add(f'/{w}s')
            business_dirs.add(f'/{w}-admin')
            business_dirs.add(f'/{w}-manage')
            business_dirs.add(f'/{w}-api')
            business_dirs.add(f'/{w}-dev')
            business_dirs.add(f'/{w}-test')
    
    for bp in set(business_prefixes):
        business_dirs.add(f'/{bp}')
        business_dirs.add(f'/{bp}s')
        business_dirs.add(f'/{bp}-list')
        business_dirs.add(f'/{bp}-detail')
        business_dirs.add(f'/{bp}-manage')
        business_dirs.add(f'/api/{bp}')
        business_dirs.add(f'/api/v1/{bp}')
        business_dirs.add(f'/api/v2/{bp}')
        business_dirs.add(f'/admin/{bp}')
    
    custom.extend(business_dirs)
    
    # === 5. Common API/interface naming conventions ===
    cn_api_patterns = [
        '/login', '/logout', '/register', '/signup', '/signin', '/signout', '/auth', '/oauth', '/sso',
        '/captcha', '/verify', '/verification', '/sms', '/email', '/send-code', '/send_sms',
        '/upload', '/download', '/export', '/import', '/batch', '/sync',
        '/user', '/users', '/userInfo', '/user_info', '/profile', '/account', '/accounts',
        '/role', '/roles', '/permission', '/permissions', '/menu', '/menus', '/dept', '/org',
        '/dict', '/dictionary', '/config', '/setting', '/settings', '/system', '/sys',
        '/notice', '/announcement', '/message', '/msg', '/notification', '/inbox',
        '/file', '/files', '/image', '/images', '/video', '/audio', '/attachment',
        '/log', '/logs', '/logger', '/monitor', '/health', '/status', '/ping',
        '/api', '/api/v1', '/api/v2', '/api/v3', '/openapi', '/swagger', '/swagger-ui',
        '/doc', '/docs', '/api-docs', '/redoc', '/graphql', '/graphiql',
        '/backup', '/bak', '/temp', '/tmp', '/cache', '/test', '/tests',
        '/debug', '/dev', '/development', '/staging', '/uat', '/sandbox',
        '/admin', '/administrator', '/manage', '/management', '/manager', '/panel', '/cms',
        '/dashboard', '/console', '/control', '/cp', '/backend', '/backstage',
        '/cron', '/task', '/job', '/schedule', '/scheduler', '/queue',
        '/webhook', '/callback', '/hook', '/event', '/trigger',
        '/search', '/elasticsearch', '/solr', '/sphinx',
        '/sql', '/query', '/db', '/database', '/phpmyadmin', '/adminer',
        '/jenkins', '/gitlab', '/sonar', '/nexus', '/harbor', '/registry',
        '/prometheus', '/grafana', '/kibana', '/zabbix', '/nagios',
        '/.git', '/.svn', '/.hg', '/.bzr', '/.DS_Store',
        '/robots.txt', '/sitemap.xml', '/crossdomain.xml', '/favicon.ico',
        '/server-status', '/server-info', '/phpinfo.php', '/info.php',
        '/actuator', '/env', '/heapdump', '/threaddump', '/jolokia',
        '/druid', '/druid/index.html', '/druid/login.html',  # Alibaba Druid
        '/nacos', '/nacos/v1/auth/login',  # Alibaba Nacos
        '/sentinel',  # Alibaba Sentinel
        '/eureka', '/eureka/apps',  # Netflix Eureka
        '/config', '/config-server',  # Spring Cloud Config
        '/gateway', '/zuul',  # API Gateway
    ]
    custom.extend(cn_api_patterns)
    
    # === 6. File extension specific paths (source code leaks) ===
    ext_paths = [
        '/.git/config', '/.git/HEAD', '/.git/index',
        '/.svn/entries', '/.svn/wc.db',
        '/.DS_Store', '/.env', '/.env.example', '/.env.backup',
        '/backup.sql', '/backup.zip', '/backup.tar.gz', '/dump.sql',
        '/wwwroot.zip', '/web.zip', '/code.zip', '/source.zip',
        '/admin.php', '/admin.asp', '/admin.aspx', '/admin.jsp',
    ]
    custom.extend(ext_paths)
    
    # === 7. Versioned paths ===
    for v in ['v1', 'v2', 'v3', 'v4', 'v5', 'v1.0', 'v2.0', 'v3.0']:
        custom.append(f'/api/{v}')
        custom.append(f'/{v}')
    
    # === 8. Deduplicate, filter, write ===
    seen = set()
    filtered = []
    for item in custom:
        item = item.strip()
        if item in seen:
            continue
        if not item.startswith('/'):
            item = '/' + item
        if len(item) < 2 or len(item) > 80:
            continue
        seen.add(item)
        filtered.append(item)
    
    return filtered


def main():
    parser = argparse.ArgumentParser(description='Generate context-aware directory wordlist')
    parser.add_argument('--host', required=True, help='Target host')
    parser.add_argument('--url', default='', help='Target base URL')
    parser.add_argument('--company', required=True, help='Company short name')
    parser.add_argument('--urls-file', help='File with collected URLs')
    parser.add_argument('--output', default='custom_dirs.txt', help='Output wordlist file')
    args = parser.parse_args()
    
    dirs = generate(args.host, args.url, args.company, args.urls_file)
    
    with open(args.output, 'w') as f:
        for d in dirs:
            f.write(d + '\n')
    
    print(f'[+] Generated {len(dirs)} custom directories → {args.output}')


if __name__ == '__main__':
    main()
