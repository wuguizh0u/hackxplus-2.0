#!/usr/bin/env python3
"""CVE mapper for hackprobe — extracts product:version pairs from scan results
and queries OSV.dev for known vulnerabilities. Read-only, no exploitation.

Usage: python3 map_cve.py [options]
  --results-dir DIR      Directory with Wave 1 result files
  --output FILE          Output markdown file
"""

import argparse
import json
import os
import re
import sys
import urllib.request
import urllib.error
import time


def extract_versions(results_dir):
    """Extract product:version pairs from Wave 1 results."""
    products = {}  # product → set of versions
    
    files_to_check = [
        '01_techstack.md', '01_infra.md', '01_ports.md', 
        '02_ssl_headers.md', '01_osint.md'
    ]
    
    for fname in files_to_check:
        fpath = os.path.join(results_dir, fname)
        if not os.path.exists(fpath):
            continue
        try:
            with open(fpath, 'r', encoding='utf-8', errors='replace') as f:
                content = f.read()
        except Exception:
            continue
        
        # Pattern: "product X.Y.Z" or "product version: X.Y.Z" or "product/X.Y.Z"
        patterns = [
            r'([a-zA-Z][a-zA-Z0-9._-]+)\s+([0-9]+\.[0-9]+(?:\.[0-9]+)?(?:[a-z]\d*)?)',
            r'([a-zA-Z][a-zA-Z0-9._-]+)[/:]([0-9]+\.[0-9]+(?:\.[0-9]+)?)',
            r'"product":\s*"([^"]+)"[^}]*"version":\s*"([^"]+)"',
        ]
        
        for pattern in patterns:
            for match in re.finditer(pattern, content, re.IGNORECASE):
                prod = match.group(1).strip().lower()
                ver = match.group(2).strip()
                # Filter noise
                if len(prod) < 2 or prod in ('http', 'https', 'www', 'com', 'org', 'net', 'the', 'and', 'for'):
                    continue
                if prod not in products:
                    products[prod] = set()
                products[prod].add(ver)
    
    return products


def query_osv(product, version, timeout=10):
    """Query OSV.dev API for a product:version pair."""
    url = 'https://api.osv.dev/v1/query'
    data = json.dumps({
        'package': {'name': product, 'ecosystem': ''},
        'version': version
    }).encode()
    
    req = urllib.request.Request(url, data=data, headers={'Content-Type': 'application/json'})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read())
    except urllib.error.HTTPError:
        return None
    except Exception:
        return None


def main():
    parser = argparse.ArgumentParser(description='Map product:version pairs to CVEs via OSV.dev')
    parser.add_argument('--results-dir', required=True, help='Directory with Wave 1 results')
    parser.add_argument('--output', default='cve_mapping.md', help='Output markdown file')
    parser.add_argument('--max-queries', type=int, default=10, help='Max API queries')
    args = parser.parse_args()
    
    products = extract_versions(args.results_dir)
    print(f'[+] Extracted {len(products)} unique products from results')
    for prod, vers in sorted(products.items())[:20]:
        print(f'    {prod}: {", ".join(sorted(vers))}')
    
    # Query OSV.dev
    findings = []
    queried = 0
    for prod, versions in sorted(products.items()):
        if queried >= args.max_queries:
            break
        for ver in sorted(versions):
            if queried >= args.max_queries:
                break
            print(f'[+] Querying OSV.dev: {prod}@{ver}...')
            result = query_osv(prod, ver)
            queried += 1
            time.sleep(0.5)  # Rate limit
            
            if result and 'vulns' in result:
                for vuln in result['vulns']:
                    cve_id = vuln.get('id', 'N/A')
                    aliases = vuln.get('aliases', [])
                    cve = next((a for a in aliases if a.startswith('CVE-')), cve_id)
                    summary = vuln.get('summary', '') or vuln.get('details', '')
                    severity = 'Unknown'
                    if 'database_specific' in vuln:
                        severity = vuln['database_specific'].get('severity', 'Unknown')
                    elif 'severity' in vuln:
                        sev_data = vuln['severity']
                        if isinstance(sev_data, list):
                            severity = sev_data[0].get('score', 'Unknown') if sev_data else 'Unknown'
                    
                    findings.append({
                        'product': prod,
                        'version': ver,
                        'cve': cve,
                        'osv_id': cve_id,
                        'summary': summary[:200] if summary else '',
                        'severity': severity,
                    })
    
    # Write output
    with open(args.output, 'w', encoding='utf-8') as f:
        f.write('## CVE Mapping (OSV.dev)\n\n')
        f.write(f'**Products analyzed:** {len(products)} | **Queries:** {queried} | **CVEs found:** {len(findings)}\n\n')
        
        if findings:
            f.write('| Product | Version | CVE | Severity | Summary |\n')
            f.write('|---------|---------|-----|----------|--------|\n')
            for finding in findings:
                f.write(f'| {finding["product"]} | {finding["version"]} | {finding["cve"]} | {finding["severity"]} | {finding["summary"]} |\n')
        else:
            f.write('No CVEs found for detected product versions.\n')
    
    print(f'[+] Wrote {len(findings)} CVE findings → {args.output}')


if __name__ == '__main__':
    main()
