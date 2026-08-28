# Cleanup — 审计后归档清理

> Wave 4 后调用。`archive_tmp` 归档临时文件，`clean_temp` 清理纯垃圾。原则：**宁留勿删。**

```bash
archive_tmp() {
  local WORK_DIR="${WORK_ROOT:-$(pwd)}"
  local TMP="${TMP:-${WORK_DIR}/_work/tmp}"
  local ARCHIVE_DIR="${WORK_DIR}/_work"
  [ ! -d "$TMP" ] || [ -z "$(ls -A "$TMP" 2>/dev/null)" ] && return 0

  local ts=$(date +%Y%m%d_%H%M%S)
  (cd "$ARCHIVE_DIR" && tar -czf "tmp_archive_${ts}.tar.gz" "tmp/" 2>/dev/null)
  echo "[cleanup] Archived: tmp_archive_${ts}.tar.gz"
}

clean_temp() {
  local TMP="${TMP:-${WORK_ROOT:-$(pwd)}/_work/tmp}"
  [ ! -d "$TMP" ] && return 0

  # 只删已知纯临时文件：*.partial（已存 shared/partial/ 的）、空文件、interactsh raw（callback 已解析）、core dump
  rm -f "$TMP"/*.partial "$TMP"/interactsh_output.txt "$TMP"/interactsh_error.txt 2>/dev/null
  find "$TMP" -type f -empty -delete 2>/dev/null
  find "$TMP" \( -name 'core.*' -o -name '*.core' -o -name 'hs_err_pid*.log' \) -delete 2>/dev/null
  echo "[cleanup] Temp files cleaned"
}

# 白名单保护：0a_homepage.html、0b_httpx.json、OSINT 原始结果、probe_hits.json 等绝不删。
# 手动完全清理：cd _work/ && tar -tzf tmp_archive_*.tar.gz | head -20  # 先验证
#                 rm -rf tmp/  # 确认后删除
```
