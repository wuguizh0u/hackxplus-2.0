#!/usr/bin/env python3
"""Context-aware subdomain dictionary generator for hackprobe.
Generates target-specific subdomain wordlist based on business naming rules,
asset characteristics, and API format patterns.

Usage: python3 gen_custom_subdomains.py [options]
  --host HOST           Target host (e.g. example.com)
  --company COMPANY     Company short name
  --existing-subs FILE  File with existing discovered subdomains (optional)
  --output FILE         Output wordlist file (default: custom_subs.txt)
"""

import argparse
import os
import re
import sys

def generate(host, company_short, existing_subs_file=None):
    domain = host.replace('www.', '')
    company_words = company_short.replace('-', ' ').replace('_', ' ').split()
    domain_parts = domain.split('.')
    domain_root = domain_parts[0]
    
    custom = []
    
    # === 1. Company name variants ===
    for w in company_words:
        if len(w) >= 3:
            for env in ['dev', 'test', 'staging', 'uat', 'qa', 'demo', 'pre', 'beta', 'alpha',
                        'sandbox', 'dr', 'prod', 'admin', 'manage', 'dashboard', 'console']:
                custom.append(f'{w}-{env}')
                custom.append(f'{env}-{w}')
                custom.append(f'{w}{env}')
            # Full name + common env
            custom.append(w)
    
    # Short abbreviations
    if len(company_words) >= 2:
        abbr = ''.join(w[0] for w in company_words if w).lower()
        if len(abbr) >= 2:
            for env in ['dev', 'test', 'staging', 'uat', 'qa', 'demo', 'pre', 'beta', 'alpha']:
                custom.append(f'{abbr}-{env}')
                custom.append(f'{env}-{abbr}')
                custom.append(f'{abbr}{env}')
            custom.append(abbr)
    
    # === 2. Business semantics from domain keywords ===
    business_map = {
        'med': ['medical', 'doctor', 'patient', 'clinic', 'hospital', 'health', 'pharmacy',
                 'nurse', 'lab', 'radiology', 'imaging', 'report', 'detect', 'diagnose',
                 'prescription', 'ehr', 'emr', 'his', 'appointment', 'consultation', 'surgery', 'treatment'],
        'health': ['medical', 'doctor', 'patient', 'clinic', 'hospital', 'health', 'pharmacy',
                    'nurse', 'lab', 'radiology', 'report', 'detect', 'prescription', 'ehr', 'emr'],
        'pay': ['payment', 'pay', 'billing', 'invoice', 'wallet', 'finance', 'accounting',
                 'ledger', 'settle', 'transaction', 'checkout', 'subscription', 'plan', 'pricing',
                 'refund', 'charge', 'balance'],
        'fin': ['payment', 'pay', 'billing', 'invoice', 'wallet', 'finance', 'accounting',
                 'ledger', 'transaction', 'checkout', 'subscription', 'plan', 'pricing'],
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
        for keyword, prefixes in business_map.items():
            if keyword in wl:
                business_prefixes.extend(prefixes)
    
    # Generate subdomains from business prefixes
    for bp in set(business_prefixes):
        custom.append(bp)
        custom.append(f'{bp}-{domain_root}')
        custom.append(f'{domain_root}-{bp}')
    
    # === 3. Tech stack suffixes ===
    tech_suffixes = [
        'api', 'apis', 'rest', 'graphql', 'ws', 'websocket',
        'auth', 'sso', 'oauth', 'login', 'signin', 'register',
        'cdn', 'static', 'assets', 'media', 'img', 'images', 'files',
        'upload', 'download', 'docs', 'doc', 'wiki', 'help', 'support',
        'status', 'health', 'monitor', 'metrics', 'logs', 'log',
        'mail', 'email', 'smtp', 'imap', 'webmail',
        'chat', 'im', 'messaging', 'push', 'notification',
        'search', 'elastic', 'solr',
        'db', 'mysql', 'postgres', 'mongo', 'redis', 'memcache',
        'queue', 'rabbitmq', 'kafka', 'nats',
        'git', 'gitlab', 'github', 'bitbucket', 'jenkins', 'ci',
        'docker', 'k8s', 'kubernetes', 'swarm',
        'vpn', 'remote', 'bastion', 'jump',
        's3', 'storage', 'backup', 'archive',
        'analytics', 'data', 'bi', 'reporting',
        'crm', 'erp', 'hr', 'finance', 'payroll',
    ]
    for ts in tech_suffixes:
        custom.append(ts)
        custom.append(f'{ts}-{domain_root}')
    
    # === 4. Naming convention patterns from observed subdomains ===
    if existing_subs_file and os.path.exists(existing_subs_file):
        try:
            with open(existing_subs_file, 'r') as f:
                existing = [l.strip() for l in f if l.strip() and not l.startswith('#')]
            
            # Detect naming convention
            has_hyphen = any('-' in s.split('.')[0] for s in existing)
            has_underscore = any('_' in s.split('.')[0] for s in existing)
            has_camel = any(re.search(r'[a-z][A-Z]', s.split('.')[0]) for s in existing)
            
            # Extract base names from existing subdomains (strip env suffixes)
            env_suffixes = ['-dev', '-test', '-staging', '-uat', '-qa', '-demo', '-prod',
                            '-beta', '-alpha', 'dev-', 'test-', 'staging-', 'uat-',
                            'qa-', 'demo-', 'prod-', 'beta-', 'alpha-']
            base_names = set()
            for sub in existing:
                name = sub.split('.')[0]
                for env_suf in env_suffixes:
                    if env_suf in name:
                        name = name.replace(env_suf, '')
                        break
                if len(name) >= 2:
                    base_names.add(name)
            
            for bn in base_names:
                for env in ['dev', 'test', 'staging', 'uat', 'qa', 'demo']:
                    if has_hyphen:
                        custom.append(f'{bn}-{env}')
                        custom.append(f'{env}-{bn}')
                    elif has_underscore:
                        custom.append(f'{bn}_{env}')
                        custom.append(f'{env}_{bn}')
                    else:
                        custom.append(f'{bn}{env}')
                        custom.append(f'{env}{bn}')
        except Exception:
            pass
    
    # === 5. Generate context-aware permutations ===
    # Business prefix/suffix combinations
    for bp in set(business_prefixes[:10]):
        for env in ['dev', 'test', 'staging', 'uat', 'qa']:
            custom.append(f'{bp}-{env}')
            custom.append(f'{env}-{bp}')
    
    # Tech suffix combinations
    for ts in tech_suffixes[:15]:
        for env in ['dev', 'test', 'staging']:
            custom.append(f'{ts}-{env}')
    
    # Regional/Chinese naming patterns
    cn_regions = ['bj', 'sh', 'gz', 'sz', 'cd', 'hz', 'nj', 'wh', 'xa', 'tj',
                  'cn', 'hk', 'tw', 'sg', 'jp', 'kr', 'us', 'eu']
    for bp in set(business_prefixes[:5]):
        for region in cn_regions:
            custom.append(f'{bp}-{region}')
            custom.append(f'{region}-{bp}')
    
    # Port-based naming
    for port in ['8080', '9090', '3000', '4000', '5000', '8000', '8443', '9443']:
        custom.append(f'{domain_root}-{port}')
    
    # === 6. Deduplicate + filter ===
    seen = set()
    filtered = []
    for item in custom:
        item = item.strip().lower()
        if item in seen:
            continue
        if len(item) < 3 or len(item) > 40:
            continue
        if re.search(r'[^a-z0-9\-_]', item):
            continue
        seen.add(item)
        filtered.append(item)
    
    return filtered


def main():
    parser = argparse.ArgumentParser(description='Generate context-aware subdomain dictionary')
    parser.add_argument('--host', required=True, help='Target host (e.g. example.com)')
    parser.add_argument('--company', required=True, help='Company short name')
    parser.add_argument('--existing-subs', help='File with existing discovered subdomains')
    parser.add_argument('--output', default='custom_subs.txt', help='Output wordlist file')
    args = parser.parse_args()
    
    subs = generate(args.host, args.company, args.existing_subs)
    
    with open(args.output, 'w') as f:
        for s in subs:
            f.write(s + '\n')
    
    print(f'[+] Generated {len(subs)} custom subdomains → {args.output}')
    # Print first 15 as sample
    for s in subs[:15]:
        print(f'    {s}')
    if len(subs) > 15:
        print(f'    ... and {len(subs)-15} more')


if __name__ == '__main__':
    main()
