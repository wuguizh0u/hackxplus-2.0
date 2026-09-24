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

# --- 可执行性预检 ---
# ⚠️ 关键：校验工具身份时必须先确认「它真能跑」。
# 失败时 shell 报错信息形如 "<path>: Permission denied"，而 **path 里就含工具名**，
# 会让后续的 `*xray*` / `*-json*` 之类特征匹配被自己的路径污染而误判通过。
# 所以先拦掉执行失败，再看特征。
_tool_runs() {
  local path="$1" out
  out=$("$path" --version 2>&1) || out=$("$path" -version 2>&1) || \
  out=$("$path" -h 2>&1)        || out=$("$path" --help 2>&1) || true
  case "$out" in
    *"Permission denied"*|*"No such file"*|*"command not found"*|*"cannot execute"*|*"not recognized"*)
      return 1 ;;
  esac
  return 0
}

# --- Validation: reject same-name-different-tool collisions ---
# 只对已知会撞名的工具校验，其余一律放行（避免误伤）。
_tool_is_valid() {
  local name="$1" path="$2"
  case "$name" in
    httpx|xray)
      _tool_runs "$path" || return 1   # 跑不起来的直接否掉，不进特征匹配
      ;;
  esac
  case "$name" in
    httpx)
      # 真 ProjectDiscovery httpx: 帮助含 -json / -version 打印 projectdiscovery 横幅
      # 假 Python httpx CLI:      -h 报 "Option '-h' requires 2 arguments"，两者皆无
      local out
      out=$("$path" -h 2>&1 || true)
      case "$out" in *"-json"*) return 0 ;; esac
      out=$("$path" -version 2>&1 || true)
      case "$out" in *rojectdiscovery*) return 0 ;; esac
      return 1
      ;;
    xray)
      # ⚠️ xray 是最危险的撞名：v2ray 代理套件的 `xray.exe` 与长亭 xray 扫描器同名。
      # 误用会把代理当成扫描器。真扫描器叫 xray_windows_amd64.exe。
      #
      # 必须是白名单校验：执行失败（Permission denied / 被 AV 拦截）**不等于**通过。
      # 黑名单写法（默认放行）会让不可执行的文件混进来 —— 已踩过。
      local out
      out=$("$path" -version 2>&1 || true)
      case "$out" in *"Penetrates Everything"*) return 1 ;; esac  # v2ray 代理，明确拒绝
      # 长亭 xray 特征：输出含 "xray"（大小写不限）或版本号形态
      case "$out" in
        *xray*|*Xray*)
          case "$out" in
            *xpired*|*license*) return 1 ;;   # license 过期，等于不可用
          esac
          return 0
          ;;
      esac
      return 1   # 执行失败或输出不可识别 → 一律不放行
      ;;
  esac
  return 0
}

# --- Search a single base dir at configured depth ---
# 返回全部匹配（非 head -1），便于跳过未过校验的命中继续找下一个。
_search_base() {
  local base="$1" name="$2" ext="$3"
  local maxdepth="${HACKPROBE_TOOL_MAXDEPTH:-3}"
  [ -d "$base" ] || return 0
  find "$base" -maxdepth "$maxdepth" -type f \
    \( -name "${name}${ext}" -o -name "${name}.py" -o -name "$name" \) 2>/dev/null
}

# --- Find tool: universal lookup ---
find_tool() {
  local name="$1"
  local ext=""
  [ "$IS_WINDOWS" = "1" ] && ext=".exe"

  # 1. System PATH（须过校验 —— 防 httpx 被解析成 Python 同名包）
  local p
  if p=$(command -v "$name" 2>/dev/null); then
    if _tool_is_valid "$name" "$p"; then
      echo "$p"
      return 0
    fi
    echo "  [skip] $name: PATH 命中 $p 但未通过校验（同名异工具），继续搜索" >&2
  fi

  # 2. 自定义目录（支持多目录：Windows 用 ';'，Unix 用 ':' 分隔）
  if [ -n "${HACKPROBE_TOOL_BASE:-}" ]; then
    local sep=';' bases base found
    [ "$IS_WINDOWS" = "1" ] || sep=':'
    local _old_ifs="$IFS"
    IFS="$sep" read -ra bases <<< "$HACKPROBE_TOOL_BASE"
    IFS="$_old_ifs"
    for base in ${bases[@]+"${bases[@]}"}; do
      [ -n "$base" ] || continue
      while IFS= read -r found; do
        [ -n "$found" ] || continue
        if _tool_is_valid "$name" "$found"; then
          echo "$found"
          return 0
        fi
      done < <(_search_base "$base" "$name" "$ext")
    done
  fi

  # 3. Common Unix locations (for safety)
  local loc
  for loc in /usr/bin /usr/local/bin /opt/homebrew/bin "$HOME/go/bin" "$HOME/.local/bin" "$HOME/bin"; do
    if [ -f "$loc/$name" ] && _tool_is_valid "$name" "$loc/$name"; then
      echo "$loc/$name"
      return 0
    fi
  done

  return 1
}

# --- Declare tool: export HACKPROBE_<NAME> ---
# 计数用 _DECLARED_*，供 SUMMARY 计算真实命中率
_DECLARED_TOTAL=0
_DECLARED_FOUND=0
declare_tool() {
  local tool_name="$1"
  local var_name="HACKPROBE_$(echo "$tool_name" | tr '[:lower:]' '[:upper:]' | tr '-' '_')"
  local tool_path
  _DECLARED_TOTAL=$((_DECLARED_TOTAL + 1))
  # 注意：不能加 2>/dev/null —— find_tool 的 [skip] 诊断写在 stderr，
  # 吞掉就看不到「找到了但被校验拒绝」这个关键信息。find 自身已静音。
  if tool_path=$(find_tool "$tool_name"); then
    export "$var_name=$tool_path"
    _DECLARED_FOUND=$((_DECLARED_FOUND + 1))
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
declare_tool fscan     # 内网综合扫描（端口/服务/弱口令）
declare_tool afrog     # 漏洞扫描（POC 型，nuclei 的替代）
declare_tool xray      # 长亭被动扫描器（⚠️ 可能与 v2ray 的 xray 撞名，已加校验）

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
# 分母必须是「声明的工具总数」，不能靠 set 反推 —— declare_tool 失败时会 unset，
# 那些变量从环境消失，导致分母缩水成分子，永远显示 "N/N 全找到"（旧版 bug）。
TOTAL=$_DECLARED_TOTAL
FOUND=$_DECLARED_FOUND
MISSING=$((TOTAL - FOUND))
echo "  📦  Found $FOUND/$TOTAL declared tools"
if [ "$MISSING" -gt 0 ]; then
  echo "  ⚠️   $MISSING missing — downstream uses curl/bash fallbacks (see ⚠️ lines above)"
fi
echo ""
echo "[hackprobe] Environment ready. Use \$HACKPROBE_NMAP, \$HACKPROBE_SQLMAP, etc."
echo "[hackprobe] Missing tools will be handled gracefully with fallbacks."

# 便携工具多目录时提示深度（见 README「工具发现」章节）
if [ -n "${HACKPROBE_TOOL_BASE:-}" ]; then
  echo "[hackprobe] TOOL_BASE=$HACKPROBE_TOOL_BASE  MAXDEPTH=${HACKPROBE_TOOL_MAXDEPTH:-3}"
fi