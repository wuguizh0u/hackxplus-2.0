# Wave 4 — AI 编排报告

> **单执行体。** 读所有 Wave 产出，关联攻击链，生成 REPORT.md。

---

## 4.1 高危发现授权确认（AskUserQuestion 弹窗）

扫描 Wave 3 全部产出（`$SHARED/04_*.md`、`$SHARED/probe_hits.json`），若发现可立即利用的高危漏洞（RCE/未授权 bypass/数据库泄露/签名密钥泄露等），**使用 AskUserQuestion 逐条弹窗确认**，等待用户回复：

> **主路径已改为 SQLite**：优先调 MCP `asset_get_asset_tree(target_id)` 读 `vulns[]`
> 中 `severity in (critical, high)` 的条目。`$SHARED/04_*.md` 作为证据附件。

**问题设置：**
- header: `"高危发现 #N"`
- question: 列出漏洞名称、来源、风险描述（50 字以内）
- options:
  - `"执行 PoC 利用"` — 自动执行 PoC，风险较高
  - `"仅报告记录"` — 不执行利用，记录漏洞存在
- 无回复则一直等待（用户常放后台，弹窗不超时）。**用户回复后再处理下一个发现。**

所有选「仅报告」的发现标记为"具备利用价值，未执行"。

完成后写 `$SHARED/decisions/vuln_triage.json` 记录决策结果。

---

## 4.2 生成 REPORT.md

**主路径：读 SQLite 资产树**（调 MCP `asset_get_asset_tree`），输出到 `$REPORT_DIR/{host}_{date}.md`：

- `vulns[]` → 漏洞清单（**已过五层门禁，直接可用**）
- `stats` → 执行摘要的数字（total_endpoints / tested / pending / vulns_found）
- `credentials[]` → 已获取凭据章节
- `endpoints[]` → 攻击面清单
- `target` / `auth_mode` → 目标概况

**辅助路径**：`$SHARED/` 下的 `04_*.md`（深度利用证据原文）、`probe_hits.json`（探针原始命中）、
`signals.json` + `target_profile.json`（技术栈/画像）、`failures.json`（未完成项）。

REPORT.md 内容：

1. **执行摘要** — 目标概况、漏洞总数、最严重问题（2-3 句）
2. **攻击面清单** — 子域/端口/技术栈/API 端点概览
3. **漏洞清单** — 每个漏洞：CVSS 评分 + 严重度 + HTTP 原始证据 + 复现步骤 + 业务影响 + 修复建议（按 P0 RCE > P1 Auth > P2 Info 排序）
4. **攻击链** — 多个低危组合成高危的链（如：JS 密钥泄露 → 未授权 API → 越权数据访问）
5. **未完成项** — 读 `failures.json` + 资产树的 `coverage.pending`，标注超时/跳过的测试及影响
6. **修复优先级** — P0（24h 修补）/ P1（1 周内）/ P2（1 月内）

**Chrome MCP 截图留证**：仅对 CVSS ≥ 8.0 的链执行浏览器验证并截图到 `_report/screenshots/`。

---

## 4.3 清理

```bash
echo "[wave4] ====== Cleanup ====="
source infra/cleanup.md 2>/dev/null
if declare -f archive_tmp &>/dev/null; then
  archive_tmp
  clean_temp
  echo "[cleanup] Done — _work/tmp/ archived, _report/REPORT.md ready"
fi
```

---

## Wave 4 完成检查清单

- [ ] 高危发现已逐条弹窗确认（或默认 B-仅报告）
- [ ] REPORT.md 包含：摘要 + 攻击面 + 漏洞清单(CVSS+证据) + 攻击链 + 未完成项 + 修复优先级
- [ ] CVSS≥8.0 链有 Chrome MCP 截图
- [ ] `_work/tmp/` 已 tar.gz 归档
