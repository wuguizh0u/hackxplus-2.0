#!/bin/bash
# hackprobe — Cross-platform tool discovery
# Resolves tool paths across Windows (portable tools dir), macOS (Homebrew),
# and Linux (apt/go/pipx). Exports HACKPROBE_<TOOL> variables.
#
# Usage: source scripts/discover_tools.sh [TOOL_BASE]
#   TOOL_BASE defaults to "D:/1渗透tools/fox集成工具/tools" on Windows

# --- Platform ---
IS_WINDOWS=0
case "$(uname -s)" in
  MINGW*|MSYS*|CYGWIN*) IS_WINDOWS=1 ;;
esac

TOOL_BASE="${1:-}"
if [ "$IS_WINDOWS" = "1" ] && [ -z "$TOOL_BASE" ]; then
  TOOL_BASE="D:/1渗透tools/fox集成工具/tools"
fi

# --- Additional tool roots ---
NMAP_HOME="D:/1渗透tools/nmap"          # standalone nmap install
TOOLS_ROOT="D:/1渗透tools"               # other standalone tools

export PATH="$HOME/bin:$HOME/.local/bin:$PATH"

# --- find_tool: universal lookup ---
find_tool() {
  local name="$1" win_subdir="${2:-}" win_exe="${3:-$name}"

  # A. Portable Windows tools dir (gui_scan / gui_shouji / gui_other / gui_webshell)
  if [ -n "$TOOL_BASE" ] && [ -d "$TOOL_BASE" ]; then
    for sub in gui_scan gui_shouji gui_other gui_webshell; do
      for ext in .exe .py .bat ''; do
        local candidate
        if [ -n "$win_subdir" ]; then
          candidate="$TOOL_BASE/$sub/$win_subdir/$win_exe$ext"
        else
          candidate=$(find "$TOOL_BASE/$sub" -maxdepth 2 -name "${win_exe}${ext}" -type f 2>/dev/null | head -1)
        fi
        if [ -n "$candidate" ] && [ -f "$candidate" ]; then
          echo "$candidate"; return 0
        fi
      done
    done
  fi

  # B. Standalone nmap dir
  if [ -d "$NMAP_HOME" ]; then
    for ext in .exe ''; do
      [ -f "$NMAP_HOME/${win_exe}${ext}" ] && echo "$NMAP_HOME/${win_exe}${ext}" && return 0
    done
  fi

  # C. Other standalone tools (D:/1渗透tools/)
  if [ -d "$TOOLS_ROOT" ]; then
    local found=$(find "$TOOLS_ROOT" -maxdepth 3 -name "${win_exe}.exe" -o -name "${win_exe}.py" -o -name "$win_exe" 2>/dev/null | head -1)
    [ -n "$found" ] && echo "$found" && return 0
  fi

  # D. System PATH
  if command -v "$name" >/dev/null 2>&1; then
    command -v "$name"; return 0
  fi

  # E. Common Unix locations
  for loc in /usr/bin /usr/local/bin /opt/homebrew/bin "$HOME/go/bin" "$HOME/.local/bin" "$HOME/bin"; do
    [ -f "$loc/$name" ] && echo "$loc/$name" && return 0
  done

  return 1
}

# --- declare_tool: export HACKPROBE_<NAME> ---
declare_tool() {
  local var="HACKPROBE_$(echo "$1" | tr '[:lower:]' '[:upper:]' | tr '-' '_')"
  local path=$(find_tool "$1" "${2:-}" "${3:-$1}" 2>/dev/null)
  if [ -n "$path" ]; then
    export "$var=$path"
    echo "  ✅  $1 → $path"
  else
    unset "$var"
    echo "  ⚠️   $1 (not found — downstream should skip or use fallback)"
  fi
}

echo "[hackprobe] Discovering tools..."
echo "  Platform: $(uname -s) | Tool base: ${TOOL_BASE:-'(PATH only)'}"

# ============================================================
# CORE SCANNERS
# ============================================================
declare_tool nmap
declare_tool nuclei     "nuclei"            "nuclei.exe"
declare_tool sqlmap     "sqlmap"            "sqlmap.py"
declare_tool dalfox                                           # Go — may not exist
declare_tool trufflehog                                        # may not exist

# ============================================================
# CONTENT DISCOVERY
# ============================================================
declare_tool dirsearch  "dirsearch"         "dirsearch.py"
declare_tool feroxbuster                                      # Rust — may not exist
declare_tool yjdirscan  "yjdirscanv1.1"     "御剑2.exe"
declare_tool ffuf                                              # Go — may not exist

# ============================================================
# SUBDOMAIN / DNS
# ============================================================
declare_tool subfinder                                         # Go — may not exist
declare_tool oneforall  "oneforall"         "oneforall.py"
declare_tool goon       "goon"             "goon3_win_amd64.exe"
declare_tool dnsx                                              # Go — may not exist

# ============================================================
# HTTP / URL
# ============================================================
declare_tool httpx                                             # Go — may not exist
declare_tool URLFinder  "URLFinder_Windows_x86_64" "URLFinder.exe"
declare_tool katana                                            # Go — may not exist

# ============================================================
# ADVANCED FINGERPRINTING
# ============================================================
declare_tool ehole      "ehole"            "EHole_windows_amd64.exe"
declare_tool P1finger   "P1finger"         "P1finger64.exe"
declare_tool tide       "tide"             "TideFinger_windows_amd64_v3.2.3.exe"
declare_tool golin      "golin"            "golin.exe"

# ============================================================
# JS / SOURCE ANALYSIS
# ============================================================
declare_tool vuescan    ""                 "vue_scan.exe"
declare_tool webfinder-next  ""              "webfinder-next.jar"
declare_tool webpackscan ""                 "PackerFuzzer.py"

# ============================================================
# INJECTION / FUZZING
# ============================================================
declare_tool crlfuzz                                           # Go — may not exist
declare_tool arjun                                             # pip — may not exist
declare_tool jwt_tool   "jwt_tool-2.3.0"   "jwt_tool.py"

# ============================================================
# RECON / OSINT
# ============================================================
declare_tool naabu                                              # Go — may not exist
declare_tool interactsh-client                                  # Go — may not exist
declare_tool subzy                                              # Go — may not exist

# ============================================================
# UTILITIES
# ============================================================
declare_tool wafw00f                                            # pip
declare_tool testssl     "testssl.sh"
declare_tool searchsploit
declare_tool bypass-403  "bypass-403-main"   "bypass-403.sh"

# ============================================================
# EXTRA TOOLS — not in original discover_tools.sh
# ============================================================
# Full-featured scanner
declare_tool tscanplus  "tscanplus"        "TscanPlus_Win_Amd64.exe"

# Framework exploit kits (all .jar, call via java -jar)
declare_tool shiro_attack  "shiro/shiro"     "shiro_attack-4.7.0-SNAPSHOT-all.jar"
declare_tool weblogic_tool "weblogic"       "WeblogicTool_1.3.jar"
declare_tool jboss_attack  "jboss"          "JavaJboss.jar"
declare_tool struts2_hyacinth "struts2"      "hyacinth.jar"
declare_tool thinkphp_gui  "thinkphp"       "ThinkphpGUI.jar"

# Spring Boot
declare_tool spring_scan  "spring"          "SpringBoot-Scan.py"
declare_tool heapdump     "heapdump"        "JDumpSpiderGUI-1.0-SNAPSHOT-full.jar"

# JNDI
declare_tool jndi_exploit "jndi"            "JNDIExploit-2.0-SNAPSHOT.jar"

# Password dictionary
declare_tool weekpasswd   "weekpasswd"      "JUBILANT-WOLF-V2.0.1.exe"

# ============================================================
# SYSTEM TOOLS (PATH or fallback)
# ============================================================
# nmap already declared above; also check for standalone version
if [ -z "$HACKPROBE_NMAP" ] && [ -f "$NMAP_HOME/nmap.exe" ]; then
  export HACKPROBE_NMAP="$NMAP_HOME/nmap.exe"
  echo "  ✅  nmap (standalone) → $HACKPROBE_NMAP"
fi
if [ -z "$HACKPROBE_NCAT" ] && [ -f "$NMAP_HOME/ncat.exe" ]; then
  export HACKPROBE_NCAT="$NMAP_HOME/ncat.exe"
fi
if [ -z "$HACKPROBE_NPING" ] && [ -f "$NMAP_HOME/nping.exe" ]; then
  export HACKPROBE_NPING="$NMAP_HOME/nping.exe"
fi

# nmap NSE scripts location
if [ -d "$NMAP_HOME/scripts" ]; then
  export HACKPROBE_NMAP_SCRIPTS="$NMAP_HOME/scripts"
elif [ -d "$TOOL_BASE/gui_scan/nmap/scripts" ]; then
  export HACKPROBE_NMAP_SCRIPTS="$TOOL_BASE/gui_scan/nmap/scripts"
fi

# SSL: testssl → nmap ssl-* scripts fallback
if [ -z "$HACKPROBE_TESTSSL" ] && [ -n "$HACKPROBE_NMAP_SCRIPTS" ]; then
  echo "  ℹ️   testssl not found — use: nmap --script ssl-enum-ciphers,ssl-cert"
fi

# DNS: dig → nslookup fallback → dnspython
if command -v dig >/dev/null 2>&1; then
  export HACKPROBE_DIG="$(command -v dig)"
elif command -v nslookup >/dev/null 2>&1; then
  export HACKPROBE_DIG="nslookup"      # fallback 1
  echo "  ℹ️   dig not found — using nslookup fallback"
elif python3 -c "import dns.resolver" 2>/dev/null; then
  export HACKPROBE_DIG="python3 -c 'import dns.resolver'" # fallback 2
  echo "  ℹ️   dig/nslookup not found — using dnspython fallback"
fi

# Port scan: naabu → nmap -p- fast sweep fallback
if [ -z "$HACKPROBE_NAABU" ] && [ -n "$HACKPROBE_NMAP" ]; then
  echo "  ℹ️   naabu not found — Wave 1 port scan will use: nmap -p- --min-rate 1000"
fi

# Subdomain enum: subfinder → oneforall + crt.sh 已覆盖
if [ -z "$HACKPROBE_SUBFINDER" ] && [ -n "$HACKPROBE_ONEFORALL" ]; then
  echo "  ℹ️   subfinder not found — covered by oneforall + crt.sh"
fi

# XSS: dalfox → 手动反射检查 (50_probes.md P2 已覆盖)
if [ -z "$HACKPROBE_DALFOX" ]; then
  echo "  ℹ️   dalfox not found — XSS limited to manual reflection probes"
fi

# ============================================================
# PYTHON / PIP TOOLS (check via import, not filesystem)
# ============================================================
# wafw00f
if python3 -c "import wafw00f" 2>/dev/null; then
  export HACKPROBE_WAFW00F="python3 -m wafw00f"
  [ -z "${HACKPROBE_WAFW00F_IMPORTED:-}" ] && echo "  ✅  wafw00f → python3 -m wafw00f" && export HACKPROBE_WAFW00F_IMPORTED=1
fi
# trufflehog3
if python3 -c "import trufflehog3" 2>/dev/null; then
  export HACKPROBE_TRUFFLEHOG="python3 -m trufflehog3"
  echo "  ✅  trufflehog3 → python3 -m trufflehog3"
fi

# ============================================================
# SUMMARY
# ============================================================
FOUND=0 TOTAL=0
for var in $(set | grep '^HACKPROBE_' | grep -v '_IMPORTED' | cut -d= -f1); do
  TOTAL=$((TOTAL + 1))
  [ -n "${!var}" ] && FOUND=$((FOUND + 1))
done
echo "  📦  Found $FOUND/$TOTAL tools"

export HACKPROBE_TOOL_BASE="$TOOL_BASE"
export HACKPROBE_NMAP_HOME="$NMAP_HOME"
export HACKPROBE_TOOLS_ROOT="$TOOLS_ROOT"
echo ""
echo "[hackprobe] Environment ready. Use \$HACKPROBE_NMAP, \$HACKPROBE_SQLMAP, etc."
echo "[hackprobe] Missing Go tools (naabu/subfinder/dalfox/httpx) will use fallbacks."
