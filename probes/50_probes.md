# 探针系统 — 三层索引

> **Wave 3 核心引擎。** 拆分为 3 个按需加载的 `.sh` 文件，静态站仅加载 Tier 1，节省上下文。
>
> ⚠️ **探针代码在 `.sh` 文件里**。`.md` 不能被 bash `source`（blockquote 的 `>` 会被
> 当成重定向符导致语法错误）。本文件只作索引和文档，**不要 source 它**。

---

## 文件结构

| 文件 | 内容 | 加载条件 | 探针数 |
|------|------|---------|--------|
| `tier1_universal.sh` | 通用探针 | **永远加载** | 12 (P1–P12.5，无 P9) |
| `tier2_signal.sh` | 信号驱动探针 | 非静态站 | 36 (P13–P50，缺 P31/P32) |
| `tier3_feedback.sh` | 反馈触发规则 | 深度利用完成后按需 | 11 条规则 |

对应的 `.md`（`tier1_universal.md` / `tier2_signal.md` / `tier3_feedback.md`）
是同一份内容的**文档视图**，仅供人阅读，不参与执行。

---

## 加载逻辑（与 `waves/wave3_exploit.md` 的 Step 1/2 保持一致）

```bash
# ── Tier 1 — 无条件 ──
source probes/tier1_universal.sh
run_probes_tier1

# ── Tier 2 — 条件加载：跳过静态站 ──
# 注意：静态站判定读的是 target_profile.json 的 classification.type
# （不是 signals.json —— 那里没有 classification 键，读它会恒返回 unknown）
TARGET_TYPE=$(python3 -c '
import json, sys
try:
    print(json.load(open(sys.argv[1], encoding="utf-8"))
              .get("classification", {}).get("type", "unknown"))
except Exception:
    print("unknown")' "$SHARED/target_profile.json" 2>/dev/null || echo "unknown")

if [ "$TARGET_TYPE" != "static" ] && [ -f "probes/tier2_signal.sh" ]; then
  source probes/tier2_signal.sh
  run_probes_tier2
else
  echo "[probes] Tier 2 skipped (type=$TARGET_TYPE)"
fi

# ── Tier 3 — 小文件，总是加载（提供 check_tier3_feedback 函数）──
source probes/tier3_feedback.sh
```

---

## 依赖关系

| 依赖 | 提供方 | 被谁用 |
|------|--------|--------|
| `$TMP` / `$SHARED` | `infra/directory_setup.md` 的 `init_hackprobe_dir` | 全部三个 |
| `record_hit()` | `tier1_universal.sh` | tier2 的探针调用它 |
| `HITS_FILE` | `tier1_universal.sh`（幂等初始化） | 全部三个 |
| `params_for_host()` | `tier1_universal.sh` | tier1 内部（多子域配额隔离） |

> tier2 依赖 tier1 的 `record_hit`。单独 source tier2 会告警但不会崩溃
> （计数与写入会失效，属预期降级）。

---

## 维护

- 改 Tier 1 探针 → 编辑 `tier1_universal.sh`
- 改 Tier 2 探针 → 编辑 `tier2_signal.sh`
- 改反馈规则 → 编辑 `tier3_feedback.sh`
- 新增探针 → 按类别追加到对应 tier 的 `.sh`，并在 `run_probes_tierN` 里注册调用
- **不要 source 任何 `.md`**
