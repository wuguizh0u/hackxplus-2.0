# OAST Setup — Out-of-Band Callback 自动管理

> Wave 3 探针前启动 interactsh-client，探针后轮询 callback 并清理。失败静默降级为 time-based。

```bash
# === OAST 生命周期（单函数覆盖启/轮/停） ===

oast_lifecycle() {
  local action="${1:-start}"
  local SHARED="${SHARED:-${WORK_ROOT:-$(pwd)}/_work/shared}"
  local TMP="${TMP:-${WORK_ROOT:-$(pwd)}/_work/tmp}"
  mkdir -p "$SHARED" "$TMP"

  case "$action" in
    start)
      # 找 interactsh-client
      INTERACTSH_BIN=$(command -v interactsh-client 2>/dev/null || echo "")
      [ -z "$INTERACTSH_BIN" ] && INTERACTSH_BIN="D:/1渗透tools/fox集成工具/tools/interactsh-client.exe"
      [ ! -f "$INTERACTSH_BIN" ] && {
        echo '{"status":"unavailable","domain":""}' > "$SHARED/oast.json"
        export OAST_DOMAIN=""; return 1
      }

      "$INTERACTSH_BIN" -v > "$TMP/interactsh_output.txt" 2>&1 &
      OAST_PID=$!

      # 等 10s 解析域名
      OAST_DOMAIN=""
      for i in $(seq 1 10); do
        sleep 1
        OAST_DOMAIN=$(grep -oE '[a-z0-9]{8,30}\.oast\.(fun|live|site|online|pro)' "$TMP/interactsh_output.txt" 2>/dev/null | head -1)
        [ -n "$OAST_DOMAIN" ] && break
      done

      if [ -n "$OAST_DOMAIN" ] && kill -0 "$OAST_PID" 2>/dev/null; then
        cat > "$SHARED/oast.json" << EOF
{"status":"active","domain":"${OAST_DOMAIN}","pid":${OAST_PID},"started_at":"$(date -Iseconds)"}
EOF
        export OAST_DOMAIN OAST_PID
        echo "[oast] Domain: ${OAST_DOMAIN}"
        return 0
      else
        echo '{"status":"unavailable","domain":""}' > "$SHARED/oast.json"
        export OAST_DOMAIN=""; return 1
      fi
      ;;

    poll)
      local wait_sec="${2:-15}"
      [ -z "${OAST_DOMAIN:-}" ] && return 0
      echo "[oast] Waiting ${wait_sec}s for callbacks..."
      sleep "$wait_sec"

      # 解析 interactsh 日志中的 callback
      python3 -c "
import json, re, os
log='$TMP/interactsh_output.txt'; domain='${OAST_DOMAIN:-}'
cbs=[]
if os.path.exists(log):
    content=open(log,errors='ignore').read()
    for m in re.finditer(r'Received\s+(HTTP|DNS|SMTP|LDAP)\s+interaction\s+from\s+(\S+)', content, re.I):
        cbs.append({'type':m.group(1).upper(),'source_ip':m.group(2),'domain':domain})
    for line in content.split('\n'):
        if domain and domain in line and 'Received' in line:
            if not any(c.get('raw')==line.strip() for c in cbs): cbs.append({'raw':line.strip()[:200]})
json.dump({'domain':domain,'callback_count':len(cbs),'callbacks':cbs}, open('$SHARED/oast_callbacks.json','w'),indent=2)
print(f'[oast] {len(cbs)} callbacks')
" 2>/dev/null
      ;;

    stop)
      oast_lifecycle poll 5
      [ -n "${OAST_PID:-}" ] && kill "$OAST_PID" 2>/dev/null && wait "$OAST_PID" 2>/dev/null
      pkill -f "interactsh-client" 2>/dev/null || true
      python3 -c "import json,os;f='$SHARED/oast.json';
d=json.load(open(f)) if os.path.exists(f) else {};d['status']='completed';d['stopped_at']='$(date -Iseconds)';
cb=json.load(open('$SHARED/oast_callbacks.json')) if os.path.exists('$SHARED/oast_callbacks.json') else {};
d['callback_count']=cb.get('callback_count',0);json.dump(d,open(f,'w'),indent=2)" 2>/dev/null
      echo "[oast] Stopped"; unset OAST_DOMAIN OAST_PID
      ;;
  esac
}
```

### 降级策略

| 情况 | 行为 |
|------|------|
| interactsh-client 未安装 | `OAST_DOMAIN=""` → 探针跳过 OOB → time-based 兜底 |
| 10s 无域名 | 降级，探针 OOB 阶段跳过 |
| 0 callback | 正常输出空 callback 文件，不入漏洞 |
