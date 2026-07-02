# Tier 3 — 反馈式探针

> **深度利用中发现新攻击面时追加。** 不独立执行，挂在 Step 4 每个技能利用完成后。
> 如输出中出现预定义的新攻击面信号，追加对应 hack-skill 到执行队列，**仅追加不递归**。

---

## Tier 3 — 反馈式探针（深度利用中发现新攻击面时追加）

> **不独立执行，挂在 Step 4 每个技能利用完成后。** 若深度利用的输出中出现预定义的新攻击面信号，追加对应的 hack-skill 到执行队列，**仅追加不递归**。

### Tier 3 触发条件

深度利用输出中匹配到以下预定义信号时触发：

| 触发信号（grep 模式） | 来源技能 | 追加技能 | 追加探针 |
|----------------------|---------|---------|---------|
| `mysql://` `postgresql://` `redis://` `mongodb://` | sqli-sql-injection | `insecure-source-code-management` | — |
| `DOCUMENT_ROOT` `PATH_INFO` `HTTP_HOST` | path-traversal-lfi | `cmdi-command-injection` | — |
| `ErrorLog` `DocumentRoot` `VirtualHost` `server.xml` | path-traversal-lfi | `401-403-bypass-techniques` | — |
| `iam-instance-profile` `AccessKeyId` `SecretAccessKey` | ssrf-server-side-request-forgery | `dns-rebinding-attacks` | — |
| `devGet` `devReset` `debugGet` `testLogin` `devLogin` | graphql-and-hidden-parameters | `authbypass-authentication-flaws` | — |
| `commons-collections` `commons-beanutils` `groovy` | deserialization-insecure | `deserialization-insecure` (reload versioned chains) | — |
| `kid.*\.\.\/` `kid.*/etc/passwd` | jwt-oauth-token-attacks | `path-traversal-lfi` | — |
| `__proto__` `constructor.prototype` 被回显 | prototype-pollution | `prototype-pollution-advanced` | — |
| 库存负数/超额 | race-condition | `race-condition` (20 并发重放) | — |
| `multipart/form-data` 且返回非 4xx | upload-insecure-files | `upload-insecure-files` (webshell attempt) | — |
| `10\.` `172\.` `192\.168\.` 内网地址出现在响应中 | api-recon-and-docs | `ssrf-server-side-request-forgery` | — |

### 闭环规则（防无限循环）

```
Step 4 技能执行
  ↓
check_tier3_feedback() → 匹配到新信号?
  ↓ Yes
追加到 _shared/tier3_escalations.json（去重：已执行过的技能不再追加）
  ↓
当前 Step 4 循环继续（不中断）
  ↓
Step 4 全部技能执行完后
  ↓
读 tier3_escalations.json → 追加执行一轮（不递归触发 Tier 3 检测）
```

**最大 1 轮反馈。** Tier 3 追加的技能执行时不再次触发 `check_tier3_feedback()`。理由：第二轮反馈的增量价值极低，且防止无限链。

### 执行函数

```bash
# 返回值: 匹配到的 skill 列表（空格分隔），无匹配返回空
check_tier3_feedback() {
  local skill="$1"
  local output="$2"  # 深度利用输出文件路径
  local hits=""
  
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
}

