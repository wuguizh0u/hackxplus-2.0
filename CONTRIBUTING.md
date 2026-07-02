# hackprobe

Black-box security audit as a Claude Code skill. Wave-driven architecture with 50-probe engine and on-demand hack-skills deep exploitation. Covers 40+ vulnerability categories.

## Quick start

```bash
# 1. Install tools (one-time)
bash install.sh

# 2. Run
/hackprobe https://target.com

# Quick scan mode (recon only, skip Wave 2-4)
export HACKPROBE_QUICK=1
```

## Architecture — 4 Waves

| Wave | Name | Purpose |
|------|------|---------|
| Wave 1 | Recon | 3 sub-waves: 1a(OSINT/subs/ports/domain) → 1b(techstack/URLs/secrets) → 1c(defaults/sensitive/SSL) |
| Wave 2 | Deep Discovery | Conditional. targeted scan, deep subs, deep dirs, JS endpoints, password brute, CVE mapping |
| Wave 3 | Exploit | 12 universal probes → 25+ signal-driven probes → merge hits with Wave 1/2 signals → on-demand hack-skills deep exploitation |
| Wave 4 | Report | vuln triage → archive PII → attack chain analysis → CVSS → business impact → REPORT.md |

## Prerequisite

`audit-rules` is auto-loaded at start of every audit. Junk findings (CORS w/o creds, Self-XSS, Sourcemap, version-only, TLS warnings) are NEVER reported.

## Key Design

- **Probes are cheap, skills are expensive** — 50 probes ~400 lines always run; hack-skills loaded only on hit
- **Signal-driven** — Wave 1/2 tech/attack_surface signals determine which hack-skills to load  
- **Wave 1 miss is NOT fatal** — Tier 1 universal probes catch what Wave 1 misses
- **Shared data layer** — httpx probes once; all agents read `_shared/*.json`
- **merge_results.sh** — agents write private tmp files, atomic merge at end of each sub-wave

## Setup

**Requirements:** macOS or Linux, Go 1.21+, Python 3

### Install tools

```bash
bash install.sh
```

Installs nmap, sqlmap, trufflehog, subfinder, and 20+ other tools via Homebrew (macOS) or apt/go/pip (Linux).

On Windows: place tools under a portable directory and use `scripts/discover_tools.sh` for path resolution.

## File Structure

```
hackprobe-main/
├── SKILL.md                     # Entry point
├── waves/                       # Wave definitions
│   ├── wave1_recon.md
│   ├── wave2_deep.md
│   ├── wave3_exploit.md
│   └── wave4_report.md
├── probes/                      # 50-probe engine (split by tier)
│   ├── 50_probes.md
│   ├── tier1_universal.md
│   ├── tier2_signal.md
│   └── tier3_feedback.md
├── infra/                       # Infrastructure
│   ├── anti_patterns.md
│   ├── shared_layer.md
│   ├── decision_gates.md
│   └── signal_router.md
└── scripts/                     # Shell scripts
    ├── discover_tools.sh
    ├── merge_results.sh
    └── ... (dictionary generators)
```

## Responsible use

This skill is for authorized security testing only.

- Only test targets you own or have written permission to test
- The skill asks for confirmation before every audit
- Use throwaway emails for registration probes
- Never submit real payment data
- CORS without credentials, Self-XSS, Sourcemap, and version-only findings are never reported (enforced by audit-rules)
- Report findings through responsible disclosure

## License

MIT
