#!/usr/bin/env python3
"""Deep dictionary generator for hackprobe Wave 2 (deep dive recon).
Generates 3rd/4th-level subdomain dictionary and deep directory dictionary
based on framework-specific deep paths and observed patterns.

Usage: python3 gen_deep_dicts.py [options]
  --host HOST             Target host
  --company COMPANY       Company short name
  --existing-subs FILE    File with all discovered subdomains
  --targets-file FILE     File with high-value targets
  --output-subs FILE      Output subdomain wordlist
  --output-dirs FILE      Output directory wordlist
"""

import argparse
import os
import re
import sys


def generate_subdomains(host, company_short, existing_subs_file=None):
    """Generate 3rd-level subdomain dictionary from observed patterns."""
    domain = host.replace('www.', '')
    domain_parts = domain.split('.')
    domain_root = domain_parts[0]
    company_words = company_short.replace('-', ' ').replace('_', ' ').split()
    
    custom = []
    
    # Collect base names from existing subdomains
    base_names = set()
    if existing_subs_file and os.path.exists(existing_subs_file):
        try:
            with open(existing_subs_file, 'r') as f:
                existing = [l.strip() for l in f if l.strip() and not l.startswith('#')]
            env_suffixes = ['-dev', '-test', '-staging', '-uat', '-qa', '-demo', '-prod',
                            '-beta', '-alpha', 'dev-', 'test-', 'staging-', 'uat-',
                            'qa-', 'demo-', 'prod-', 'beta-', 'alpha-']
            for sub in existing:
                name = sub.split('.')[0]
                for env_suf in env_suffixes:
                    name = name.replace(env_suf, '')
                if len(name) >= 2:
                    base_names.add(name)
        except Exception:
            pass
    
    # Deep subdomain patterns
    envs = ['dev', 'test', 'staging', 'uat', 'qa', 'demo', 'pre', 'beta',
            'alpha', 'sandbox', 'dr', 'prod', 'admin', 'manage', 'dashboard']
    regions = ['bj', 'sh', 'gz', 'sz', 'cd', 'hz', 'nj', 'wh', 'xa', 'tj',
               'cn', 'hk', 'tw', 'sg', 'jp', 'kr', 'us', 'eu', 'ap', 'na']
    
    # Combine base names with env/region
    for bn in list(base_names)[:20]:
        for env in envs[:8]:
            custom.append(f'{bn}-{env}')
            custom.append(f'{env}-{bn}')
            custom.append(f'{bn}{env}')
        for region in regions[:5]:
            custom.append(f'{bn}-{region}')
            custom.append(f'{region}-{bn}')
    
    # Generate from company words
    for w in company_words[:3]:
        if len(w) >= 2:
            for env in envs[:5]:
                custom.append(f'{w}-{env}')
                custom.append(f'{env}-{w}')
    
    # Deduplicate + filter
    seen = set()
    filtered = []
    for item in custom:
        item = item.strip().lower()
        if item in seen:
            continue
        if not re.match(r'^[a-z0-9][a-z0-9\-_]{2,49}$', item):
            continue
        if '--' in item or '__' in item or '..' in item:
            continue
        if item.startswith('-') or item.endswith('-'):
            continue
        seen.add(item)
        filtered.append(item)
    
    return filtered


def generate_directories(host, company_short):
    """Generate deep directory dictionary with framework-specific paths."""
    domain_root = host.replace('www.', '').split('.')[0]
    company_words = company_short.replace('-', ' ').replace('_', ' ').split()
    
    custom = []
    
    # === Framework-specific deep paths ===
    deep_paths = [
        # NestJS
        '/swagger', '/swagger-json', '/swagger-ui',
        '/api-json', '/api-docs', '/api-docs.json',
        '/explorer', '/graphql/schema',
        
        # Next.js deep paths
        '/_next/webpack-hmr', '/_next/on-demand-entries-ping',
        '/_next/data/development', '/api/auth/[...nextauth]',
        '/api/auth/session', '/api/auth/csrf', '/api/auth/signin',
        
        # Spring Boot deep paths
        '/actuator/conditions', '/actuator/configprops',
        '/actuator/scheduledtasks', '/actuator/httptrace',
        '/actuator/caches', '/actuator/sessions',
        '/actuator/flyway', '/actuator/liquibase',
        '/actuator/jolokia', '/actuator/hawtio',
        
        # Laravel deep paths
        '/.env.example', '/.env.production', '/.env.local',
        '/storage/logs/laravel.log', '/storage/framework/views',
        '/storage/framework/sessions', '/storage/framework/cache',
        '/_ignition/health-check', '/_ignition/execute-solution',
        '/telescope/requests', '/horizon/dashboard',
        
        # Django deep paths
        '/admin/login/', '/admin/auth/user/', '/admin/auth/group/',
        '/api/auth/token/', '/api/auth/refresh/',
        '/graphql', '/swagger/', '/redoc/',
        '/staticfiles/', '/mediafiles/',
    ]
    custom.extend(deep_paths)
    
    # === Generic API deep paths ===
    generic_api = [
        # Versioned
        '/api/v1/users', '/api/v1/auth', '/api/v1/config',
        '/api/v2/users', '/api/v2/auth',
        '/api/v3/users', '/api/v3/auth',
        # Resource patterns
        '/api/users/list', '/api/users/create', '/api/users/update',
        '/api/users/delete', '/api/users/search',
        '/api/admin/users', '/api/admin/config',
        '/api/internal/health', '/api/internal/metrics',
        '/api/internal/config', '/api/internal/debug',
        # Auth
        '/api/auth/login', '/api/auth/register', '/api/auth/refresh',
        '/api/auth/logout', '/api/auth/reset-password', '/api/auth/forgot-password',
        '/api/auth/verify-email', '/api/auth/me', '/api/auth/profile',
        # File/upload
        '/api/upload', '/api/upload/image', '/api/upload/file',
        '/api/download', '/api/export/csv', '/api/export/excel',
        # Search
        '/api/search', '/api/search/global', '/api/search/advanced',
        # Notification
        '/api/notifications', '/api/notifications/unread',
        '/api/notifications/settings',
    ]
    custom.extend(generic_api)
    
    # === Internal/dev-only paths ===
    internal = [
        '/internal/', '/internal/health', '/internal/metrics',
        '/internal/status', '/internal/version',
        '/dev/', '/dev/api', '/dev/console',
        '/debug/', '/debug/vars', '/debug/pprof/',
        '/test/', '/test/api',
        '/local/', '/local/api',
        '/.well-known/', '/.well-known/security.txt',
        '/phpinfo', '/phpinfo.php', '/info.php',
        '/server-status', '/server-info',
        '/status', '/health', '/healthz', '/readyz', '/livez',
        '/metrics', '/prometheus',
        '/version', '/build', '/build-info',
    ]
    custom.extend(internal)
    
    # === Deduplicate + filter ===
    seen = set()
    filtered = []
    for item in custom:
        item = item.strip()
        if item in seen:
            continue
        if not item.startswith('/'):
            item = '/' + item
        if len(item) < 2 or len(item) > 100:
            continue
        seen.add(item)
        filtered.append(item)
    
    return filtered


def main():
    parser = argparse.ArgumentParser(description='Deep dictionary generator for hackprobe Wave 2')
    parser.add_argument('--host', required=True, help='Target host')
    parser.add_argument('--company', required=True, help='Company short name')
    parser.add_argument('--existing-subs', help='File with all discovered subdomains')
    parser.add_argument('--targets-file', help='File with high-value targets')
    parser.add_argument('--output-subs', default='deep_subs.txt', help='Output subdomain wordlist')
    parser.add_argument('--output-dirs', default='deep_dirs.txt', help='Output directory wordlist')
    args = parser.parse_args()
    
    # Generate subdomains
    subs = generate_subdomains(args.host, args.company, args.existing_subs)
    with open(args.output_subs, 'w') as f:
        for s in subs:
            f.write(s + '\n')
    print(f'[+] Generated {len(subs)} deep subdomains → {args.output_subs}')
    
    # Generate directories
    dirs = generate_directories(args.host, args.company)
    with open(args.output_dirs, 'w') as f:
        for d in dirs:
            f.write(d + '\n')
    print(f'[+] Generated {len(dirs)} deep directories → {args.output_dirs}')


if __name__ == '__main__':
    main()
