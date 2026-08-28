#!/bin/bash
# hackprobe - Install all required security tools
# Supports macOS (Homebrew) and Linux (apt/go/pipx/cargo)

set -e

echo "=== hackprobe tool installer ==="
echo ""

OS="$(uname -s)"

# ── System packages (platform-specific, non-overlapping) ─────────────────────

if [[ "$OS" == "Darwin" ]]; then
  command -v brew >/dev/null 2>&1 || { echo "Install Homebrew first: https://brew.sh"; exit 1; }

  echo "[1/5] Installing Homebrew packages..."
  brew install nmap sqlmap testssl feroxbuster trufflehog amass pipx exploitdb 2>/dev/null || true
  echo "  Done"

elif [[ "$OS" == "Linux" ]]; then
  echo "[1/5] Installing system packages..."
  sudo apt-get update -qq
  sudo apt-get install -y -qq nmap testssl.sh sqlmap whois dnsutils pipx exploitdb 2>/dev/null || true

  # trufflehog - binary install on Linux
  if ! command -v trufflehog >/dev/null 2>&1; then
    echo "  Installing trufflehog..."
    curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh | sudo sh -s -- -b /usr/local/bin 2>/dev/null || true
  fi

  # feroxbuster - cargo on Linux
  if command -v cargo >/dev/null 2>&1; then
    echo "  Installing feroxbuster via cargo..."
    cargo install feroxbuster 2>/dev/null || true
  else
    echo "  Skipping feroxbuster (install Rust from https://rustup.rs/)"
  fi

  # amass via Go
  echo "  Installing amass via Go..."
  go install github.com/owasp-amass/amass/v4/...@master 2>/dev/null || true

  echo "  Done"
else
  echo "Unsupported OS: $OS"
  echo "hackprobe supports macOS and Linux."
  exit 1
fi

# ── Go tools (cross-platform, canonical source for all Go-based tools) ───────

echo "[2/5] Installing Go tools..."
command -v go >/dev/null 2>&1 || { echo "  Go not found. Install Go 1.21+ from https://go.dev/dl/"; exit 1; }

# ProjectDiscovery tools
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest 2>/dev/null || true
go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest 2>/dev/null || true
go install github.com/projectdiscovery/httpx/cmd/httpx@latest 2>/dev/null || true
go install github.com/projectdiscovery/katana/cmd/katana@latest 2>/dev/null || true
go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest 2>/dev/null || true
go install github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest 2>/dev/null || true

# URL collection and processing
go install github.com/lc/gau/v2/cmd/gau@latest 2>/dev/null || true
go install github.com/tomnomnom/waybackurls@latest 2>/dev/null || true
go install github.com/tomnomnom/gf@latest 2>/dev/null || true
go install github.com/tomnomnom/qsreplace@latest 2>/dev/null || true
go install github.com/tomnomnom/anew@latest 2>/dev/null || true

# Scanners
go install github.com/hahwul/dalfox/v2@latest 2>/dev/null || true
go install github.com/ffuf/ffuf/v2@latest 2>/dev/null || true
go install github.com/PentestPad/subzy@latest 2>/dev/null || true
go install github.com/dwisiswant0/crlfuzz/cmd/crlfuzz@latest 2>/dev/null || true

# N-day detection — nuclei (safe template scanner)
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest 2>/dev/null || true

echo "  Done"

# ── Python tools (via pipx - isolated envs, no PEP 668 conflicts) ────────────

echo "[3/5] Installing Python packages..."
command -v pipx >/dev/null 2>&1 || { echo "  pipx not found, falling back to pip3..."; USE_PIP=1; }

if [ "${USE_PIP:-}" = "1" ]; then
  pip3 install --user --break-system-packages uro s3scanner wafw00f theHarvester arjun 2>&1 | tail -1 || true
  pip3 install --user --break-system-packages jwt-tool 2>&1 | tail -1 || true
else
  pipx install uro 2>/dev/null || true
  pipx install s3scanner 2>/dev/null || true
  pipx install wafw00f 2>/dev/null || true
  pipx install theHarvester 2>/dev/null || true
  pipx install arjun 2>/dev/null || true

  # jwt_tool needs special handling - clone and symlink
  if ! command -v jwt_tool 2>/dev/null && ! command -v jwt_tool.py 2>/dev/null; then
    JWT_DIR="$HOME/.local/share/jwt_tool"
    if [ ! -d "$JWT_DIR" ]; then
      git clone --quiet https://github.com/ticarpi/jwt_tool.git "$JWT_DIR" 2>/dev/null || true
      pip3 install --user --break-system-packages -r "$JWT_DIR/requirements.txt" 2>/dev/null || true
    fi
    mkdir -p "$HOME/.local/bin"
    ln -sf "$JWT_DIR/jwt_tool.py" "$HOME/.local/bin/jwt_tool" 2>/dev/null || true
    chmod +x "$HOME/.local/bin/jwt_tool" 2>/dev/null || true
  fi
fi

echo "  Done"

# ── N-day databases (nuclei templates + searchsploit DB) ────────────────────

echo "[4/7] Updating N-day databases..."

# Update searchsploit (Exploit-DB) local database — read-only, no exploits downloaded
if command -v searchsploit >/dev/null 2>&1; then
  searchsploit -u 2>/dev/null || true
  echo "  searchsploit DB updated"
else
  echo "  searchsploit not installed — skipping"
fi

# Update nuclei templates
if command -v nuclei >/dev/null 2>&1; then
  nuclei -update-templates 2>/dev/null || true
  echo "  nuclei templates updated"
else
  echo "  nuclei not installed — skipping"
fi

echo "  Done"

# ── gf patterns ──────────────────────────────────────────────────────────────

echo "[5/7] Installing gf patterns..."
GF_DIR="$HOME/.gf"
mkdir -p "$GF_DIR"
if [ ! -f "$GF_DIR/sqli.json" ]; then
  git clone --quiet https://github.com/1ndianl33t/Gf-Patterns.git /tmp/gf-patterns 2>/dev/null || true
  cp /tmp/gf-patterns/*.json "$GF_DIR/" 2>/dev/null || true
  rm -rf /tmp/gf-patterns
fi
echo "  Done"

# ── Local / portable tools (not installed by this script) ─────────────────
# These tools are used by hackprobe but must be obtained separately:
#   - oneforall     — Subdomain suite (https://github.com/shmilylty/OneForAll)
#   - URLFinder     — JS endpoint/API extractor (https://github.com/pingc0y/URLFinder)
#   - 御剑 (yjdirscan) — Chinese directory scanner
#   - ehole         — Tech stack fingerprint (https://github.com/EdgeSecurityTeam/EHole)
#   - P1finger      — Advanced fingerprinting
#   - tide          — Multi-recon (subdomain + 1800 fingerprint rules)
#   - golin         — Multi-recon (sub, port, web, vuln)
#   - goon          — Subdomain brute-force engine
#   - webpackscan   — .map file → JS source recovery
#   - vuescan       — Vue.js route/component extract
#   - bypass-403    — 403 bypass toolkit
#
# On Windows, place these under a portable tools directory.
# On macOS/Linux, some have Go/Homebrew alternatives (see scripts/discover_tools.sh).
# The skill gracefully falls back when a tool is not found — missing tools
# are skipped with a note, not an error.
echo ""
echo "NOTE: The following tools are NOT installed by this script and must be"
echo "      obtained separately if needed:"
echo "      oneforall, URLFinder, yjdirscan, ehole, P1finger, tide, golin,"
echo "      goon, webpackscan, vuescan, bypass-403"
echo "      See scripts/discover_tools.sh for cross-platform path resolution."
echo ""

# ── Tool Discovery (cross-platform) ────────────────────────────────────────

echo "[6/7] Running tool discovery..."
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
if [ -f "$SCRIPT_DIR/scripts/discover_tools.sh" ]; then
  source "$SCRIPT_DIR/scripts/discover_tools.sh" 2>/dev/null || true
  echo "  Tool discovery complete."
else
  echo "  scripts/discover_tools.sh not found — tools will be resolved from PATH."
fi
echo ""

# ── Verify ───────────────────────────────────────────────────────────────────

echo "[7/7] Verifying installations..."
echo ""

export PATH="$HOME/.local/bin:$HOME/go/bin:$PATH"

# Build lookup map from discover_tools.sh ($HACKPROBE_*)
declare -A HACKPROBE_MAP
for var in $(set | grep '^HACKPROBE_' | grep -v '_IMPORTED' | cut -d= -f1); do
  tool_path="${!var}"
  [ -n "$tool_path" ] && [ -f "$tool_path" ] && HACKPROBE_MAP["$var"]="$tool_path"
done
# Helper: check if tool available via PATH or HACKPROBE_*
tool_available() {
  command -v "$1" >/dev/null 2>&1 && return 0
  # Search HACKPROBE_* vars for matching tool name
  for var in "${!HACKPROBE_MAP[@]}"; do
    local name=$(echo "$var" | sed 's/^HACKPROBE_//' | tr '[:upper:]' '[:lower:]' | tr '_' '-')
    # Handle known name variants
    case "$name" in
      naabu|nmap-reg) name="nmap" ;;
      oneforall)      name="oneforall" ;;
    esac
    [ "$name" = "$1" ] && return 0
  done
  return 1
}

TOOLS="nmap sqlmap dalfox ffuf feroxbuster testssl subfinder amass dnsx httpx katana gau waybackurls trufflehog naabu gf qsreplace anew uro s3scanner wafw00f theHarvester arjun interactsh-client subzy crlfuzz nuclei searchsploit"
MISSING=""
FOUND=0
TOTAL=0

for tool in $TOOLS; do
  TOTAL=$((TOTAL + 1))
  if tool_available "$tool"; then
    echo "  ok  $tool"
    FOUND=$((FOUND + 1))
  else
    echo "  MISSING  $tool"
    MISSING="$MISSING $tool"
  fi
done

# jwt_tool check
TOTAL=$((TOTAL + 1))
if tool_available "jwt_tool" || tool_available "jwt-tool"; then
  echo "  ok  jwt_tool"
  FOUND=$((FOUND + 1))
else
  echo "  MISSING  jwt_tool"
  MISSING="$MISSING jwt_tool"
fi

echo ""
echo "=== $FOUND/$TOTAL tools installed ==="
if [ -n "$MISSING" ]; then
  echo "Missing:$MISSING"
  echo ""
  echo "Re-run the script or install missing tools manually."
  echo "Go tools need network access. Python tools need pipx."
fi

# ── hackxplus MCP server dependencies (server/ 代码层) ──────────────────────
echo ""
echo "=== hackxplus MCP server dependencies ==="

# 核心: asset_store/gate_chain/probe_engine/signal_router/runner 零第三方依赖
# 仅 mcp 库 (把核心逻辑包成 MCP 工具给 Claude Code 调用) + 可选 requests/playwright
if python3 -c "import mcp" 2>/dev/null; then
  echo "  ok  mcp"
else
  echo "  Installing mcp (MCP protocol server) ..."
  python3 -m pip install --user --break-system-packages "mcp[cli]" 2>&1 | tail -1 || true
fi

if python3 -c "import requests" 2>/dev/null; then
  echo "  ok  requests"
else
  echo "  Installing requests ..."
  python3 -m pip install --user --break-system-packages requests 2>&1 | tail -1 || true
fi

# Playwright 可选: 未装则 browser.py 降级纯 HTTP 探测 (不阻塞)
if python3 -c "import playwright" 2>/dev/null; then
  echo "  ok  playwright"
else
  echo "  [optional] playwright 未安装 — browser.py 将降级为纯 HTTP 探测."
  echo "  需要浏览器深度探索时:  pip install playwright && playwright install chromium"
fi

echo ""
echo "=== hackxplus server 就绪 ==="
echo "  启动 MCP server:  python3 server/mcp_server.py"
echo "  核心逻辑自测:     python3 server/mcp_server.py --self-test"
echo "  (Python 脚本在 server/ 下运行, 资产库默认存 hackxplus.db)"
