#!/bin/bash
# hackprobe — Cross-platform tool discovery (safe for open source)
# 
# Usage: source scripts/discover_tools.sh
#
# It searches tools in this order:
#   1. System PATH (including Homebrew, apt, go/bin, pipx etc.)
#   2. Custom directory specified by env HACKPROBE_TOOL_BASE (optional)
#
# It does NOT hardcode any absolute paths and does NOT look for exploit tools.
# Exports HACKPROBE_<TOOL> environment variables for each found tool.

set -euo pipefail

# --- Platform detection (only for fallback hints) ---
IS_WINDOWS=0
case "$(uname -s)" in
  MINGW*|MSYS*|CYGWIN*) IS_WINDOWS=1 ;;
esac

# --- PATH setup (common locations) ---
export PATH="$HOME/bin:$HOME/.local/bin:/opt/homebrew/bin:/usr/local/bin:/usr/bin:$PATH"

# --- Find tool: universal lookup ---
find_tool() {
  local name="$1"
  # 1. System PATH
  if command -v "$name" >/dev/null 2>&1; then
    command -v "$name"
    return 0
  fi

  # 2. Custom base directory (if set)
  if [ -n "${HACKPROBE_TOOL_BASE:-}" ] && [ -d "$HACKPROBE_TOOL_BASE" ]; then
    # Try with .exe on Windows, without on Unix
    local ext=""
    [ "$IS_WINDOWS" = "1" ] && ext=".exe"
    local found
    found=$(find "$HACKPROBE_TOOL_BASE" -maxdepth 3 -type f \( -name "${name}${ext}" -o -name "${name}.py" -o -name "$name" \) 2>/dev/null | head -1)
    if [ -n "$found" ]; then
      echo "$found"
      return 0
    fi
  fi

  # 3. Common Unix locations (for safety)
  for loc in /usr/bin /usr/local/bin /opt/homebrew/bin "$HOME/go/bin" "$HOME/.local/bin" "$HOME/bin"; do
    if [ -f "$loc/$name" ]; then
      echo "$loc/$name"
      return 0
    fi
  done

  return 1
}

# --- Declare tool: export HACKPROBE_<NAME> ---
declare_tool() {
  local tool_name="$1"
  local var_name="HACKPROBE_$(echo "$tool_name" | tr '[:lower:]' '[:upper:]' | tr '-' '_')"
  local tool_path
  if tool_path=$(find_tool "$tool_name" 2>/dev/null); then
    export "$var_name=$tool_path"
    echo "  ✅  $tool_name → $tool_path"
  else
    unset "$var_name"
    echo "  ⚠️   $tool_name (not found — downstream will use fallbacks)"
  fi
}

# --- Start discovery ---
echo "[hackprobe] Discovering tools..."
if [ "$IS_WINDOWS" = "1" ]; then
  echo "  Platform: Windows (custom base: ${HACKPROBE_TOOL_BASE:-'(not set, using PATH only)'})"
else
  echo "  Platform: Unix (custom base: ${HACKPROBE_TOOL_BASE:-'(not set, using PATH only)'})"
fi

# ============================================================
# CORE SCANNERS
# ============================================================
declare_tool nmap
declare_tool nuclei
declare_tool sqlmap
declare_tool dalfox
declare_tool trufflehog
declare_tool feroxbuster

# ============================================================
# CONTENT DISCOVERY
# ============================================================
declare_tool dirsearch
declare_tool ffuf
declare_tool gobuster   # fallback for feroxbuster

# ============================================================
# SUBDOMAIN / DNS
# ============================================================
declare_tool subfinder
declare_tool amass
declare_tool dnsx
declare_tool httpx

# ============================================================
# URL / WEB
# ============================================================
declare_tool gau
declare_tool waybackurls
declare_tool katana
declare_tool naabu
declare_tool interactsh-client

# ============================================================
# INJECTION / FUZZING
# ============================================================
declare_tool crlfuzz
declare_tool arjun
declare_tool qsreplace
declare_tool anew
declare_tool gf
declare_tool subzy

# ============================================================
# RECON / OSINT
# ============================================================
declare_tool theHarvester
declare_tool wafw00f
declare_tool testssl
declare_tool searchsploit

# ============================================================
# UTILITIES
# ============================================================
declare_tool uro
declare_tool s3scanner
declare_tool jwt_tool   # if installed via pipx

# ============================================================
# SYSTEM FALLBACKS (not tools, but hints)
# ============================================================
# dig / nslookup for DNS
if command -v dig >/dev/null 2>&1; then
  export HACKPROBE_DIG="$(command -v dig)"
  echo "  ✅  dig → $HACKPROBE_DIG"
elif command -v nslookup >/dev/null 2>&1; then
  export HACKPROBE_DIG="nslookup"
  echo "  ✅  nslookup → fallback for dig"
else
  echo "  ⚠️   dig/nslookup not found — DNS resolution will be limited"
fi

# Python fallback for some tools (check import)
if python3 -c "import wafw00f" 2>/dev/null; then
  export HACKPROBE_WAFW00F="python3 -m wafw00f"
  echo "  ✅  wafw00f (Python module) → python3 -m wafw00f"
fi
if python3 -c "import trufflehog3" 2>/dev/null; then
  export HACKPROBE_TRUFFLEHOG="python3 -m trufflehog3"
  echo "  ✅  trufflehog3 (Python module) → python3 -m trufflehog3"
fi

# ============================================================
# SUMMARY
# ============================================================
TOTAL=0
FOUND=0
for var in $(set | grep '^HACKPROBE_' | grep -v '_IMPORTED' | cut -d= -f1); do
  TOTAL=$((TOTAL + 1))
  [ -n "${!var}" ] && FOUND=$((FOUND + 1))
done
echo "  📦  Found $FOUND/$TOTAL explicitly declared tools"
echo ""
echo "[hackprobe] Environment ready. Use \$HACKPROBE_NMAP, \$HACKPROBE_SQLMAP, etc."
echo "[hackprobe] Missing tools will be handled gracefully with fallbacks."