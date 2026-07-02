# Agent Intelligence — 你不是脚本执行器

> **hackprobe 的脚本和探针是底座，真正的漏洞靠你的推理能力。**
>
> 以下技术无法用 bash 脚本自动化的——它们需要你读代码、理解业务、推断逻辑、构造请求。

---

## 1. JS Bundle 逆向 → API 发现

### 触发时机
Wave 1b URL 收集完成后，或任何时候你在 HTML 中看到 `<script src="/_next/static/chunks/...">` 或其他 JS bundle。

### 做法
```
1. 读首页 HTML → 提取所有 <script src="..."> 
2. 对每个 JS bundle curl 拉取内容
3. 搜索以下模式：
   - API 路径："/api/" '"/api/' '"/v1/' '"/v2/' '"/graphql'
   - fetch/axios 调用：fetch("/api...")  axios.get("/api...")
   - 路由表：next/dynamic, React.lazy, vue-router routes
   - 端点拼接：baseURL + "/users/" + userId
   - GraphQL：gql`...`, graphql(`, query/mutation 字符串
   - WebSocket：ws:// wss:// new WebSocket(
   - 内部管理路径：/admin /manage /console /dashboard /internal
4. 提取完整的请求 URL、method、参数名、headers
5. 追加到 urls_all.txt（通过 record_new_url 函数）
```

### 搜索模式参考
```
# API path patterns in JS
fetch\s*\(\s*["'`](/[^"'\`]{3,})            # fetch("/api/users")
axios\.(?:get|post|put|delete)\s*\(\s*["'`]  # axios.get("/api/...")
baseURL\s*[:=]\s*["'`]([^"'`]+)             # baseURL: "/api/v1"
\.create\s*\(\s*\{\s*baseURL                 # axios.create({ baseURL: "..." })
graphql\s*\(\s*["'`]                          # graphql("query { ... }")
gql\s*["'`]                                   # gql`...`
new\s+WebSocket\s*\(\s*["'`]                  # new WebSocket("ws://...")
["'`](/api/[a-zA-Z0-9/_-]{2,})["'`]          # "/api/users" in any context
["'`](/internal/[^"'`]+)["'`]               # Internal API paths
["'`](/graphql)["'`]                          # GraphQL endpoint reference
["'`](/swagger[^"'`]*)["'`]                  # Swagger/OpenAPI docs
```

### 输出
- 追加 URL 到 `$SHARED/urls_all.txt`（后续探针自动覆盖）
- 写入 `$SHARED/js_api_discovery.json` 记录发现来源

---

## 2. 参数推断与拼接

### 触发时机
JS 分析后发现字段名但不知道完整 API 路径，或 API 响应返回了相关字段名。

### 做法
```
1. 从 JS bundle 提取字段名列表：userId, orgId, fileId, projectId, workspaceId, ...
2. 从已知 API 响应提取返回字段名（JSON key 即可能参数名）
3. 对已知 endpoints 做参数追加试探：
   GET /api/users/me  →  尝试 GET /api/users/me?fields=*
   GET /api/projects   →  尝试 GET /api/projects?orgId=1
   POST /api/search    →  尝试 POST /api/search {"query":"*"}
4. 对 RESTful 资源做 CRUD 试探：
   已知 GET /api/users    →  尝试 POST /api/users（创建）
   已知 GET /api/users/1  →  尝试 PUT/PATCH/DELETE /api/users/1
```

### 参数推断规则
```
看到 "userId" 在响应中 → 添加 ?userId= 参数到请求
看到 "pageSize" "limit" "offset" → 改大值看是否返回更多数据（越权）
看到 "role" "permission" "type" → 改 admin/manager/root
看到 "isAdmin" "isSuperuser" → 改 true
看到 "status" "state" → 枚举 pending/approved/rejected/deleted
看到 "fileId" → 路径穿越 /download?fileId=../../etc/passwd
看到 "redirect" "next" "returnUrl" → 测 Open Redirect
看到 "search" "query" "q" "filter" → 测全字符集注入
```

---

## 3. IDOR 模式识别

### 触发时机
Wave 3 Step 4，有 auth token 时。

### 做法
```
1. 从 urls_all.txt 和 API 响应中提取所有含 ID/UUID 的端点
2. 按"业务对象"分类：用户/订单/项目/文件/组织/消息/设置
3. 对每种业务对象，用当前用户 token 测试：
   - 顺序遍历：自己的 ID → ID+1 → ID-1 → ID+2...
   - UUID 替换：用自己的 token 访问别人 UUID 标识的资源
   - 数组注入：?id=1 → ?id[]=1&id[]=2 (有时能绕过单值检查)
   - 批量：POST /api/users/batch {ids: [1,2,3,4,5]}
4. 对比响应大小/状态码/内容判断是否越权成功
```

### 典型 IDOR 端点模式
```
GET /api/users/{id}/profile       ← 看别人资料
GET /api/orders/{id}              ← 看别人订单
GET /api/files/{uuid}/download    ← 下载别人文件
GET /api/messages/{id}            ← 读别人私信
POST /api/invitations/{code}      ← 接受别人邀请
DELETE /api/projects/{id}         ← 删别人项目
PUT /api/users/{id}/role          ← 改别人角色
```

---

## 4. GraphQL 内省深挖

### 触发时机
P28 探测到 GraphQL 端点后。

### 做法
```
1. 拉取完整 schema（内省查询）
   curl -X POST /graphql -d '{"query":"{__schema{types{name,fields{name,args{name,type{name}}}}}}"}' 
2. 从 schema 中找：
   - 命名含 dev/debug/test/admin 的 query/mutation
   - 参数含 token/auth 的字段（可能是内部调用）
   - 返回含 password/secret/key/token 的字段
   - 废弃字段（isDeprecated: true）→ 可能没删后端逻辑
3. 对发现的 mutation 实际调用：
   - resetPassword / forgotPassword → ATO
   - devLogin / testLogin → 直接鉴权绕过
   - createAdmin / promoteUser → 提权
   - exportData / dumpDB → 数据泄露
```

---

## 5. 报错信息反推

### 做法
```
看到 stack trace → 提取文件路径、类名、方法名 → 推断框架和代码结构
看到 SQL error → 表名、列名暴露 → 构造精准注入
看到 "unauthorized" but 不同路径有不同行为 → 路径白名单推断
看到 "File not found: /var/www/..." → 绝对路径可用于 LFI
看到 "Connection refused: redis://10.x.x.x" → 内网地址泄露
看到 "User 'xxx'@'host' (using password: YES)" → DB 凭据信息
```

---

## 6. 业务逻辑推断

### 做法
```
1. 理解业务流程（不是看代码，是看行为）：
   - 注册→登录→浏览→下单→支付→收货
   - 创建项目→邀请成员→上传文件→分享链接
2. 找跳过步骤的点：
   - 直接访问 /checkout/confirm 跳过支付
   - 直接 PUT /api/orders/{id}/status=shipped
   - 修改邀请链接中的 role=member 为 role=admin
3. 找数值篡改点：
   - 价格/金额参数：改 0.01 或负数
   - 数量参数：改负数看是否退钱
   - 积分/余额：改大值
4. 找并发点：
   - 下单/领券/提现（并发 5 次看是否重复扣除）
   - 注册邀请码（同一码并发注册）
```

---

## 如何与框架协同

```
框架做的事情（你不需重复）：
  ✓ 子域名爆破（oneforall + crt.sh）
  ✓ 端口扫描（naabu + nmap）
  ✓ 目录爆破（dirsearch + 御剑）
  ✓ 50 个基础探针（SQLi/XSS/SSTI/CORS/403...）
  ✓ 信号路由（从技术栈匹配 hack-skills）
  ✓ CVE 映射（OSV.dev API）

你需要做的事情（框架做不到）：
  ✓ 读 JS bundle 找隐藏 API（上面的第 1 节）
  ✓ 从业务逻辑推断漏洞（上面的第 6 节）
  ✓ 对报错信息做反向推理（上面的第 5 节）
  ✓ 用已有 token 做 IDOR（上面的第 3 节）
  ✓ GraphQL schema 深挖 mutation（上面的第 4 节）
  ✓ 把多个低危串成攻击链（Wave 4 阶段）
  ✓ 判断"这个 403 是真的没法访问"还是"换个姿势就能绕过"
```

## 纪律

1. **不要被框架限制住** — 看到有意思的响应就手动追，不用等脚本安排
2. **你的上下文是最大的武器** — 你能看到所有 Wave 的输出，关联它们
3. **脚本跑不出来的洞才是好洞** — IDOR、业务逻辑、越权、信息泄露链都是脚本盲区
4. **不要硬怼 WAF** — 20 分钟没进展换攻击面（audit-rules 规则）
5. **每发现一个新端点，想象"如果我是开发者，我还暴露了什么？"**
