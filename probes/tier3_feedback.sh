#!/usr/bin/env bash
# tier3_feedback.sh — Tier 3 反馈式探针（11 条触发规则）
#
# 用法：
#   source probes/tier3_feedback.sh
#   check_tier3_feedback <source_skill> <output_file>   # 返回追加的技能名（空格分隔）
#
# 定位：**不独立执行**，挂在 Wave 3 Step 4 每个技能深度利用完成后。
#       若深度利用输出中出现预定义的新攻击面信号，追加对应 hack-skill 到队列。
#       仅追加不递归 —— 追加的技能执行时不再触发本函数（防无限链）。
#
# 依赖：无（纯 grep 文本匹配）。$SHARED 仅被调用方用于写 tier3_escalations.json。

# ====== 触发规则表（11 条）======
#
# | 触发信号 (grep)                                        | 来源技能                        | 追加技能                            |
# |--------------------------------------------------------|--------------------------------|-------------------------------------|
# | mysql:// postgresql:// redis:// mongodb://             | sqli-sql-injection             | insecure-source-code-management     |
# | DOCUMENT_ROOT PATH_INFO HTTP_HOST                      | path-traversal-lfi             | cmdi-command-injection              |
# | ErrorLog DocumentRoot VirtualHost server.xml           | path-traversal-lfi             | 401-403-bypass-techniques           |
# | iam-instance-profile AccessKeyId SecretAccessKey       | ssrf-server-side-request-forgery| dns-rebinding-attacks               |
# | devGet devReset debugGet testLogin devLogin            | graphql-and-hidden-parameters  | authbypass-authentication-flaws     |
# | commons-collections commons-beanutils groovy           | deserialization-insecure       | deserialization-insecure (重载链)   |
# | kid.*../  kid.*/etc/passwd                             | jwt-oauth-token-attacks        | path-traversal-lfi                  |
# | __proto__ constructor.prototype 回显                   | prototype-pollution            | prototype-pollution-advanced        |
# | negative/exceeded/overdraft/超额/负数                   | race-condition                 | race-condition (20 并发重放)        |
# | multipart/form-data 且返回非 4xx                        | upload-insecure-files          | upload-insecure-files (webshell)    |
# | 10. / 172.16-31. / 192.168. 内网地址出现在响应中         | api-recon-and-docs             | ssrf-server-side-request-forgery    |
#
# ====== 闭环规则 ======
#   Step 4 技能执行
#     ↓
#   check_tier3_feedback() → 匹配到新信号?
#     ↓ Yes
#   追加到 $SHARED/tier3_escalations.json（去重：已执行过的技能不再追加）
#     ↓
#   当前 Step 4 循环继续（不中断）
#     ↓
#   Step 4 全部技能执行完后 → 读 tier3_escalations.json → 追加执行一轮
#   （追加的技能执行时**不再**触发 check_tier3_feedback）
#
#   最大 1 轮反馈。理由：第二轮增量价值极低，且防止无限链。

# check_tier3_feedback <skill> <output_file>
#   返回值(stdout): 匹配到的 skill 列表（空格分隔），无匹配输出空
check_tier3_feedback() {
  local skill="${1:-}"
  local output="${2:-}"
  local hits=""

  if [ -z "$output" ] || [ ! -f "$output" ]; then
    echo ""
    return 0
  fi

  case "$skill" in
    sqli-sql-injection)
      grep -qiE 'mysql://|postgresql://|redis://|mongodb://' "$output" 2>/dev/null && \
        hits="$hits insecure-source-code-management"
      ;;
    path-traversal-lfi)
      grep -qiE 'DOCUMENT_ROOT|PATH_INFO|HTTP_HOST' "$output" 2>/dev/null && \
        hits="$hits cmdi-command-injection"
      grep -qiE 'ErrorLog|DocumentRoot|VirtualHost|[^/]server\.xml' "$output" 2>/dev/null && \
        hits="$hits 401-403-bypass-techniques"
      ;;
    ssrf-server-side-request-forgery)
      grep -qiE 'iam-instance-profile|AccessKeyId|SecretAccessKey' "$output" 2>/dev/null && \
        hits="$hits dns-rebinding-attacks"
      ;;
    graphql-and-hidden-parameters)
      grep -qiE 'devGet|devReset|debugGet|testLogin|devLogin' "$output" 2>/dev/null && \
        hits="$hits authbypass-authentication-flaws"
      ;;
    deserialization-insecure)
      grep -qiE 'commons-collections|commons-beanutils|groovy' "$output" 2>/dev/null && \
        hits="$hits deserialization-insecure"
      ;;
    jwt-oauth-token-attacks)
      grep -qiE 'kid.*\.\./|kid.*/etc/passwd' "$output" 2>/dev/null && \
        hits="$hits path-traversal-lfi"
      ;;
    prototype-pollution)
      grep -qiE '__proto__|constructor\.prototype' "$output" 2>/dev/null && \
        hits="$hits prototype-pollution-advanced"
      ;;
    race-condition)
      grep -qiE 'negative|exceeded|overdraft|超额|负数' "$output" 2>/dev/null && \
        hits="$hits race-condition"
      ;;
    upload-insecure-files)
      grep -qiE 'multipart/form-data' "$output" 2>/dev/null && \
        grep -qvE 'HTTP/1\.[01] (4[0-9]{2})' "$output" 2>/dev/null && \
        hits="$hits upload-insecure-files"
      ;;
    api-recon-and-docs)
      grep -qiE '\b(10\.|172\.(1[6-9]|2[0-9]|3[0-1])\.|192\.168\.)' "$output" 2>/dev/null && \
        hits="$hits ssrf-server-side-request-forgery"
      ;;
  esac

  # 去重输出
  echo "$hits" | tr ' ' '\n' | sort -u | tr '\n' ' '
  return 0
}
