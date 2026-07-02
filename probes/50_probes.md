# 50 Probes — 三层探测索引

> **Wave 3 核心引擎。** 拆分为 3 个按需加载文件，静态站仅加载 Tier 1（~15KB），节省 ~40KB 上下文。

---

## 文件结构

| 文件 | 大小 | 加载条件 | 探针数 |
|------|------|---------|--------|
| `tier1_universal.md` | ~16KB | **永远加载** | 13 (P1-P12.5) |
| `tier2_signal.md` | ~31KB | 非静态站 + signals.json 存在 | 35 (P13-P50, 缺 P31/P32) |
| `tier3_feedback.md` | ~5KB | 深度利用完成后按需 | 10 触发规则 |

## 加载逻辑（wave3_exploit.md 中）

```bash
# Tier 1 — 无条件
source probes/tier1_universal.md
run_probes_tier1

# Tier 2 — 条件加载：跳过静态站和无信号目标
if [ -f "$SHARED/signals.json" ]; then
  TARGET_TYPE=$(python3 -c "import json;d=json.load(open('$SHARED/signals.json'));print(d.get('classification',{}).get('type','unknown'))" 2>/dev/null)
  if [ "$TARGET_TYPE" != "static" ]; then
    source probes/tier2_signal.md
    run_probes_tier2
  else
    echo "[probes] Static site — skipping Tier 2 (saves ~31KB context)"
  fi
else
  echo "[probes] No signals.json — skipping Tier 2"
fi

# Tier 3 — 小文件，总是加载
source probes/tier3_feedback.md
```

## Token 节省

| 目标类型 | 原 50_probes.md | 新方案 | 节省 |
|---------|-----------------|--------|------|
| 静态站 | 54KB (~18K tokens) | 16+5=21KB (~7K tokens) | **~11K tokens** |
| 简单 API | 54KB | 16+31+5=52KB | ~2K tokens |
| 全量 CMS | 54KB | 52KB | ~2K tokens（索引开销） |

## 维护

- 修改 Tier 1 探针 → 编辑 `tier1_universal.md`
- 修改 Tier 2 探针 → 编辑 `tier2_signal.md`
- 修改反馈规则 → 编辑 `tier3_feedback.md`
- 添加新探针 → 按类别追加到对应 tier 文件
- 本文件仅作索引和文档用，不被源引（wave3 直接源引 3 个子文件）
