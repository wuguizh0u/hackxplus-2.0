#!/usr/bin/env python3
"""Target-profile-aware password dictionary generator for hackprobe.
Generates ~1000 candidate passwords based on brand, product, employee names,
and tech stack. Filters generic weak passwords already covered by default scans.

Usage: python3 gen_password_dict.py [options]
  --host HOST             Target host
  --company COMPANY       Company short name
  --profile-json FILE     JSON file with target profile from Phase 1
  --output FILE           Output wordlist (default: targeted_passwords.txt)
  --max-passwords N       Max passwords to generate (default: 1000)
  --min-length N          Minimum password length (default: 6)
  --max-length N          Maximum password length (default: 16)
"""

import argparse
import itertools
import json
import os
import re
import sys
import random


# Generic weak passwords already handled by default scans — filter these out
GENERIC_WEAK = {
    '123456', '12345678', '123456789', '1234567890',
    'password', 'password1', 'password123',
    'admin', 'admin123', 'admin123456',
    'root', 'root123', 'root123456',
    'qwerty', 'qwerty123',
    'abc123', 'abcdef',
    '111111', '222222', '333333',
    'test', 'test123', 'guest', 'guest123',
    'pass', 'pass123', 'passwd',
    'letmein', 'welcome', 'monkey', 'dragon',
    'master', 'login',
}


def generate(host, company_short, profile_data=None, max_passwords=1000, min_len=6, max_len=16):
    domain = host.replace('www.', '')
    domain_parts = domain.split('.')
    
    # === Step 1: Extract brand names ===
    brands = set()
    brands.add(domain_parts[0].lower())
    
    # Remove common prefixes/suffixes
    for prefix in ['www', 'app', 'my', 'go', 'get', 'the', 'our']:
        if domain_parts[0].lower().startswith(prefix):
            core = domain_parts[0][len(prefix):]
            if len(core) >= 3:
                brands.add(core.lower())
    
    if company_short:
        brands.add(company_short.lower())
        clean = re.sub(r'[^a-zA-Z]', '', company_short)
        if len(clean) >= 3:
            brands.add(clean.lower())
    
    # Abbreviations
    words = re.findall(r'[a-zA-Z]+', company_short or host)
    if len(words) >= 2:
        abbr = ''.join(w[0].lower() for w in words)
        if len(abbr) >= 2:
            brands.add(abbr)
    for w in words:
        if len(w) >= 3:
            brands.add(w[:3].lower())
    
    # === Step 2: Extract product names from profile ===
    products = set()
    if profile_data:
        for key in ['products', 'product_names']:
            for p in profile_data.get(key, []):
                p_clean = re.sub(r'[^a-zA-Z0-9]', '', str(p))
                if 2 <= len(p_clean) <= 20:
                    products.add(p_clean.lower())
        # Tech components
        for comp in profile_data.get('tech_components', []):
            c_clean = re.sub(r'[^a-zA-Z0-9]', '', str(comp))
            if 2 <= len(c_clean) <= 15:
                products.add(c_clean.lower())
    
    # === Step 3: Extract employee names from profile ===
    employees = set()
    if profile_data:
        for emp in profile_data.get('employees', []):
            if isinstance(emp, dict):
                name = emp.get('name', '') or emp.get('username', '')
            else:
                name = str(emp)
            name_clean = re.sub(r'[^a-zA-Z]', '', name)
            if 3 <= len(name_clean) <= 20:
                employees.add(name_clean.lower())
    
    # === Step 4: Password generation ===
    passwords = set()
    years = [str(y) for y in range(2010, 2027)]
    specials = ['!', '@', '#', '$', '%', '&', '*', '.']
    common_suffixes = ['123', '1234', '12345', '1', '2024', '2025', '2026']
    case_variations = ['lower', 'upper', 'capitalize']
    
    def add_pw(pw):
        pw = pw.strip()
        if min_len <= len(pw) <= max_len and pw.lower() not in GENERIC_WEAK:
            passwords.add(pw)
    
    # === RULE 1: Brand name + year/special char/digits ===
    for brand in list(brands)[:5]:
        add_pw(brand)
        for yr in years[:3]:
            add_pw(f'{brand}{yr}')
            add_pw(f'{brand}_{yr}')
            add_pw(f'{brand}-{yr}')
            add_pw(f'{brand}{yr[-2:]}')
        for sp in specials[:4]:
            add_pw(f'{brand}{sp}')
            add_pw(f'{brand}{sp}{random.choice(years[:3])}')
        for sfx in common_suffixes[:3]:
            add_pw(f'{brand}{sfx}')
        # Capitalization
        add_pw(brand.capitalize())
        add_pw(f'{brand.capitalize()}{random.choice(years[:3])}')
    
    # === RULE 2: Abbreviation + year/special char/digits ===
    abbreviations = {b for b in brands if 2 <= len(b) <= 5 and b.isalpha()}
    for abbr in list(abbreviations)[:3]:
        for yr in years[:3]:
            add_pw(f'{abbr}{yr}')
            add_pw(f'{abbr.upper()}{yr}')
            add_pw(f'{abbr}{yr[-2:]}')
        for sp in specials[:3]:
            add_pw(f'{abbr}{sp}')
    
    # === RULE 3: Product name + year/special char/digits ===
    for prod in list(products)[:10]:
        for yr in years[:2]:
            add_pw(f'{prod}{yr}')
            add_pw(f'{prod}{yr[-2:]}')
        for sp in specials[:3]:
            add_pw(f'{prod}{sp}')
        add_pw(prod.capitalize())
        add_pw(f'{prod.capitalize()}123')
    
    # === RULE 4: Employee name + special char/digits ===
    for emp in list(employees)[:5]:
        add_pw(emp)
        add_pw(emp.capitalize())
        for sfx in common_suffixes[:2]:
            add_pw(f'{emp}{sfx}')
        for sp in specials[:2]:
            add_pw(f'{emp}{sp}')
    
    # === RULE 5: Default password variants (NOT generic — contextualized) ===
    for brand in list(brands)[:3]:
        brand_cap = brand.capitalize()
        variants = [
            f'{brand}admin', f'{brand}Admin',
            f'admin{brand}', f'Admin{brand}',
            f'{brand}root', f'root{brand}',
            f'{brand_cap}@123', f'{brand_cap}@2024', f'{brand_cap}@2025',
            f'{brand}@123', f'{brand}@2024',
            f'{brand}888', f'{brand}666', f'{brand}168',
            f'{brand}!@#', f'{brand}#$%',
        ]
        for v in variants:
            add_pw(v)
    
    # === RULE 6: Tech stack related passwords ===
    tech_defaults = {
        'tomcat': ['tomcat', 'admin', 'manager'],
        'jenkins': ['jenkins', 'admin'],
        'mysql': ['mysql', 'root', 'admin'],
        'postgres': ['postgres', 'admin'],
        'nginx': ['nginx', 'admin'],
        'apache': ['apache', 'admin'],
        'redis': ['redis', 'admin'],
        'wordpress': ['wordpress', 'admin', 'wp'],
        'drupal': ['drupal', 'admin'],
        'joomla': ['joomla', 'admin'],
        'magento': ['magento', 'admin'],
        'gitlab': ['gitlab', 'admin'],
    }
    if profile_data:
        for comp in profile_data.get('tech_components', []):
            comp_l = str(comp).lower()
            for tech, defaults in tech_defaults.items():
                if tech in comp_l:
                    for d in defaults:
                        add_pw(d)
                        add_pw(f'{d}123')
                        add_pw(f'{d}@{random.choice(years[:3])}')
                    break
    
    # === RULE 7: Case variations ===
    if brands:
        first_brand = list(brands)[0]
        add_pw(first_brand.upper())
        add_pw(first_brand.capitalize())
        add_pw(first_brand.title())
    
    # === RULE 8: Keyboard walk patterns (contextualized with brand) ===
    kb_walks = ['qwerty', 'asdfgh', 'zxcvbn', '1qaz2wsx', 'qazwsx']
    for brand in list(brands)[:2]:
        for walk in kb_walks[:3]:
            for suffix in ['', '!', '@', '123']:
                add_pw(f'{brand}{walk}{suffix}')
                add_pw(f'{walk}{brand}{suffix}')
    
    # === Post-processing: Filter and deduplicate ===
    # Filter by length
    filtered = {p for p in passwords if min_len <= len(p) <= max_len}
    
    # Remove pure generic weak passwords
    filtered -= GENERIC_WEAK
    
    # Limit to ~max_passwords, prioritizing diversity
    result = list(filtered)
    if len(result) > max_passwords:
        # Sort by length then alphabetically
        result.sort(key=lambda x: (len(x), x))
        # Take a stratified sample: spread across lengths
        step = max(1, len(result) // max_passwords)
        result = result[::step][:max_passwords]
    
    result.sort()
    return result


def main():
    parser = argparse.ArgumentParser(description='Target-profile-aware password dictionary generator')
    parser.add_argument('--host', required=True, help='Target host')
    parser.add_argument('--company', required=True, help='Company short name')
    parser.add_argument('--profile-json', help='JSON file with target profile from Phase 1')
    parser.add_argument('--output', default='targeted_passwords.txt', help='Output wordlist file')
    parser.add_argument('--max-passwords', type=int, default=1000, help='Max passwords')
    parser.add_argument('--min-length', type=int, default=6, help='Min length')
    parser.add_argument('--max-length', type=int, default=16, help='Max length')
    args = parser.parse_args()
    
    profile = None
    if args.profile_json and os.path.exists(args.profile_json):
        try:
            with open(args.profile_json, 'r') as f:
                profile = json.load(f)
        except Exception:
            pass
    
    passwords = generate(
        args.host, args.company, profile,
        args.max_passwords, args.min_length, args.max_length
    )
    
    with open(args.output, 'w') as f:
        for p in passwords:
            f.write(p + '\n')
    
    print(f'[+] Generated {len(passwords)} target-profile passwords → {args.output}')
    print(f'[+] Sample (first 20):')
    for p in passwords[:20]:
        print(f'    {p}')
    if len(passwords) > 20:
        print(f'    ... and {len(passwords) - 20} more')


if __name__ == '__main__':
    main()
