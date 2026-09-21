# Failure Handling — 超时/失败降级策略

> 每个 Wave 启动时 source 此文件获取 `TIMEOUT_CORE`/`TIMEOUT_LIGHT` 和关键路径定义。

---

## 超时分级

| 级别 | 值 | 适用 Agent |
|------|-----|-----------|
| **TIMEOUT_CORE** | 360s | 关键路径 Agent：子域收集、端口扫描、技术栈识别、URL 收集、Nuclei、密码爆破、Tier1 探针 |
| **TIMEOUT_LIGHT** | 180s | 非关键 Agent：OSINT、域名情报、JS 端点、CVE 映射、深层目录、单个深度利用技能 |

## 关键路径定义

关键路径 Agent 超时 → **中断当前 Wave**（下游依赖其数据）。非关键路径 → **标记 skip，继续**。

| Wave | 关键路径 Agent | 原因 |
|------|---------------|------|
| Wave 1a | A2-Subdomain, A3-PortScan | 无子域=无 URL 来源；无端口=漏服务 |
| Wave 1b | B1-TechStack, B2-URLs | 无技术栈=信号路由失明；无 URL=探针无目标 |
| Wave 1c | C1-Defaults | 可选，非关键 |
| Wave 2 | D1-Nuclei | 漏洞基线来源 |
| Wave 3 Step1 | Tier1 全部 12 探针 | 安全网，不跑就漏洞 |
| Wave 3 Step4 | 全部深度利用技能 | 单个技能超时只影响该类别，不中断 |

## 超时检测机制

Agent 不是子进程，无法用 `timeout` 命令。检测方式：
1. Agent 启动时记录 `start_ts=$(date +%s)` 到 `$TMP/<agent>_start.txt`
2. 等待 Agent 完成后，检查 `elapsed=$(( $(date +%s) - start_ts ))`
3. 若 `elapsed > timeout` → 标记 TIME_KILL，跳过 merge
4. 定期检查 `_shared/failures.json` 看是否有新失败

## 失败记录格式

```json
{
  "wave": "1a",
  "agent": "A2-Subdomain",
  "level": "core",
  "status": "timeout",
  "elapsed_s": 365,
  "timeout_s": 360,
  "timestamp": "2026-07-01T14:32:00+08:00",
  "effect": "WAVE_ABORT" | "AGENT_SKIP",
  "note": "子域收集超时，Wave 1a 中断。后续 Wave 将使用不完整子域列表。"
}
```

`effect` 取值：
- `WAVE_ABORT` — 关键路径，中断当前 Wave，merge 已有不完整数据
- `AGENT_SKIP` — 非关键，仅标记，继续

---

## Agent 包装器（每个 Agent 调用前 wrap）

```bash
# === Agent timeout wrapper ===
# Usage: run_agent <agent_name> <level:core|light> <output_file> <cmd...>
run_agent() {
  local agent="$1" level="$2" output="$3"
  shift 3
  local timeout
  [ "$level" = "core" ] && timeout=$TIMEOUT_CORE || timeout=$TIMEOUT_LIGHT

  echo "[agent] $agent start (timeout=${timeout}s)"
  local start_ts=$(date +%s)
  echo "$start_ts" > "$TMP/${agent}_start.txt"

  # Execute agent command (foreground, blocking).
  # 每个子命令（curl/nmap/dig 等）自带 --max-time，不会无限挂。
  # 360s/180s 是总预算上限，实际正常 Agent 通常在 60-120s 内完成。
  # 超时只可能是网络极端慢或工具卡死，概率很低。
  "$@" > "$output" 2>&1
  local exit_code=$?

  local end_ts=$(date +%s)
  local elapsed=$(( end_ts - start_ts ))

  if [ $elapsed -gt $timeout ]; then
    echo "[agent] $agent TIMEOUT: ${elapsed}s > ${timeout}s"
    record_failure "$agent" "$level" "timeout" "$elapsed" "$timeout" "$output"
    return 1
  elif [ $exit_code -ne 0 ]; then
    echo "[agent] $agent FAILED: exit=$exit_code, elapsed=${elapsed}s"
    record_failure "$agent" "$level" "error" "$elapsed" "$timeout" "$output"
    return 2
  fi
  echo "[agent] $agent OK: ${elapsed}s"
  return 0
}

# Write failure to _shared/failures.json + preserve partial data
record_failure() {
  local agent="$1" level="$2" status="$3" elapsed="$4" timeout="$5" output="$6"
  local wave="${WAVE_NAME:-unknown}"
  local is_critical="false"
  case "$agent" in
    A2-Subdomain|A3-PortScan|B1-TechStack|B2-URLs|D1-Nuclei|Tier1-Probes)
      is_critical="true" ;;
  esac

  local effect="AGENT_SKIP"
  [ "$is_critical" = "true" ] && effect="WAVE_ABORT"

  # === Preserve partial data ===
  # Agent writes to TMP file as it goes. Even on timeout, partial data exists.
  # Copy it to _shared/partial/ so merge can pick it up.
  local partial_dir="$SHARED/partial"
  mkdir -p "$partial_dir"
  local partial_lines=0 partial_bytes=0
  if [ -f "$output" ] && [ -s "$output" ]; then
    partial_lines=$(wc -l < "$output" | tr -d ' ')
    partial_bytes=$(wc -c < "$output" | tr -d ' ')
    cp "$output" "$partial_dir/${agent}_partial.txt"
    echo "[failure] Partial data preserved: $partial_lines lines ($partial_bytes bytes) → $partial_dir/${agent}_partial.txt"
  else
    echo "[failure] No partial data in $output — agent produced nothing before timeout"
    partial_lines=0; partial_bytes=0
  fi

  # Capture tail of output for debugging
  local tail_output=$(tail -20 "$output" 2>/dev/null | tr '\n' ' ' | sed 's/"/\\"/g')

  python3 -c "
import json, os
f = '$SHARED/failures.json'
data = []
if os.path.exists(f):
    with open(f) as fh: data = json.load(fh)
data.append({
    'wave': '$wave', 'agent': '$agent', 'level': '$level',
    'status': '$status', 'elapsed_s': $elapsed, 'timeout_s': $timeout,
    'timestamp': '$(date -Iseconds)',
    'effect': '$effect',
    'partial_data': {'lines': $partial_lines, 'bytes': $partial_bytes, 'file': '${agent}_partial.txt'},
    'last_output': '$tail_output'[:200]
})
with open(f, 'w') as fh: json.dump(data, fh, indent=2, ensure_ascii=False)
" 2>/dev/null

  echo "[failure] Recorded: $agent → $effect ($status, ${elapsed}s)"

  if [ "$effect" = "WAVE_ABORT" ]; then
    echo "[failure] ⛔ CRITICAL PATH FAILURE — Wave $wave continues with partial data"
  fi

  # === Audit log integration ===
  # Write heartbeat line
  source infra/directory_setup.md 2>/dev/null
  heartbeat "${agent}" "FAIL" "${status} (${elapsed}s)"
  # Write human-readable failure log
  echo "[$(date +%H:%M:%S)] ❌ $agent | $status | ${elapsed}s" >> "$AUDIT_LOG/failures.log"
  [ -f "$AUDIT_LOG/agent_logs/${agent}.log" ] && {
    echo "  Last output:" >> "$AUDIT_LOG/failures.log"
    tail -3 "$AUDIT_LOG/agent_logs/${agent}.log" 2>/dev/null | sed 's/^/    /' >> "$AUDIT_LOG/failures.log"
    echo "" >> "$AUDIT_LOG/failures.log"
  }
}
```

---

## 超时/失败处理完整链路

```
Agent 执行（逐行写 TMP 文件）
  ↓
超时/非零退出
  ↓
record_failure 做两件事：
  ├── ① 保全部分数据: cp $TMP/<agent>.txt → _shared/partial/<agent>_partial.txt
  └── ② 写 failures.json: {wave, agent, status, elapsed, partial_data: {lines, bytes}}
  ↓
关键路径? ─Yes→ effect=WAVE_ABORT，merge_results 读 _shared/partial/ + 正常 TMP 文件一起合并
  ↓ No
effect=AGENT_SKIP，其他 Agent 继续，merge 时正常合并未失败的文件
  ↓
merge_results.sh --partial 合并所有可用的 TMP + partial 文件到 _shared/
  ↓
下游 Wave 读 _shared/ 数据（可能不完整）+ failures.json 判断降级
  ↓
Wave 4 REPORT.md 引用 failures.json → "未完成项" 章节标注缺失
```

**三个保证**：
1. **部分数据不丢失**——`record_failure` 自动 cp 到 `_shared/partial/`
2. **merge 不阻塞**——`--partial` 标志允许部分文件缺失
3. **报告可追溯**——REPORT.md 标注哪些数据不完整、多少行部分数据被保留

---

## 各 Wave 集成点

### Wave 1a 示例

```bash
export WAVE_NAME="1a"
source infra/failure_handling.md

# 4 agents 并行，各自写 TMP
run_agent "A1-OSINT" "light" "$TMP/1a_a1_osint.txt" \
  bash -c "..." &
run_agent "A2-Subdomain" "core" "$TMP/1a_a2_subdomains.txt" \
  bash -c "..." &
run_agent "A3-PortScan" "core" "$TMP/1a_a3_ports.json" \
  bash -c "..." &
run_agent "A4-DomainIntel" "light" "$TMP/1a_a4_domain.txt" \
  bash -c "..." &
wait

# 检查是否有 WAVE_ABORT
ABORT_COUNT=$(python3 -c "
import json
d=json.load(open('$SHARED/failures.json'))
print(sum(1 for f in d if f.get('effect')=='WAVE_ABORT'))
" 2>/dev/null || echo 0)

if [ "$ABORT_COUNT" -gt 0 ]; then
  echo "[wave] ⚠ $ABORT_COUNT critical agent(s) failed — partial data in _shared/partial/"
  ls -la $SHARED/partial/ 2>/dev/null
fi

# merge 时 --partial 允许缺失，同时读 partial/ 目录
bash scripts/merge_results.sh --wave 1a --partial
```

---

## Wave 4 报告集成

`REPORT.md` 末尾追加节：

```markdown
## 未完成项

以下测试因超时或执行失败未完成，结果可能不完整：

| Wave | Agent | 状态 | 耗时 | 影响 |
|------|-------|------|------|------|
| 1a | A2-Subdomain | timeout | 365s | ⛔ 关键路径 — 子域列表不完整 |
| 2 | D4-DeepDirs | timeout | 190s | 深层目录扫描未完成 |

**对结果的影响：** 子域列表可能遗漏部分资产，深层目录未扫描。建议后续补扫。
```

---
