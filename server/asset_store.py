#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
asset_store.py — hackxplus 资产库 (外部记忆)

把渗透过程的全部状态外置到 SQLite, agent 通过 MCP 工具读写,
对话上下文中只保留当前任务相关数据 (参考文章: 状态外置数据库, 别依赖 compact)。

核心表:
    targets     目标管理
    endpoints   接口清单 (攻击面) + 状态
    coverage    接口 × 漏洞类型 覆盖矩阵  ← 续轮的核心依据
    credentials 已获取凭据
    traffic     HTTP 流量 (深度分析用)
    vulns       已确认漏洞 (必须过五层门禁)
    sessions    自动续轮记录

所有读写都有 DAO 封装, 便于后续从 SQLite 平滑换 MySQL。
依赖: 仅 Python 标准库 (sqlite3), 零第三方依赖。
"""

import json
import os
import sqlite3
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

# 覆盖状态机
COV_PENDING = "pending"          # 未测
COV_TESTING = "testing"          # 测试中
COV_CONFIRMED = "confirmed"      # 确认漏洞
COV_NOT_VULNERABLE = "not_vulnerable"  # 测过, 无漏洞

# 未测成的原因 —— 让报告能区分"还没轮到"和"测了但没做成"
# 空值(NULL) = 真·还没轮到；以下值 = 有明确原因
COV_REASONS = {
    "waf_blocked":          "被 WAF 拦截",
    "timeout":              "探针超时",
    "needs_auth":           "需要认证但无凭据",
    "skipped_low_priority": "主动跳过（低价值）",
    "out_of_scope":         "超出授权范围",
    "tool_missing":         "工具不可用",
    "rate_limited":         "被限流",
}

# 流量用途 —— 只记有价值的请求，普通请求不入库（否则 DB 爆炸）
TRAFFIC_PURPOSES = {
    "probe_hit":   "探针命中",
    "vuln_verify": "漏洞验证",
    "login":       "认证尝试",
    "recon":       "关键侦察响应",
}

# 漏洞置信度
CONF_CERTAIN, CONF_FIRM, CONF_TENTATIVE = "certain", "firm", "tentative"

# 漏洞类型 → 覆盖矩阵里的列 (扩展时在此追加)
VULN_TYPES = [
    "sqli", "xss", "ssti", "cmdi", "ssrf", "idor", "authbypass",
    "deserialization", "xxe", "upload", "lfi", "rce", "csrf",
    "jwt", "nosi_flow", "race_condition", "business_logic",
    "misconfig", "info_disclosure", "open_redirect",
]

_SCHEMA = """
CREATE TABLE IF NOT EXISTS targets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    url TEXT NOT NULL,
    scope TEXT,               -- "in-scope" / "out-of-scope"
    auth_mode TEXT DEFAULT 'unauthenticated',  -- register / login / unauthenticated
    root_domain TEXT DEFAULT '',   -- 根域，用于把同一战役的子域归拢 (admin.t.com → t.com)
    created_at INTEGER
);

CREATE TABLE IF NOT EXISTS endpoints (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    target_id INTEGER NOT NULL REFERENCES targets(id),
    path TEXT NOT NULL,
    method TEXT DEFAULT 'GET',
    params TEXT DEFAULT '[]',      -- JSON 数组
    func_desc TEXT,                -- 业务功能描述 (浏览器/LLM 标注)
    risk_tags TEXT DEFAULT '[]',   -- JSON 数组, 如 ["sqli","idor"]
    priority INTEGER DEFAULT 1,
    test_status TEXT DEFAULT 'pending',  -- pending / testing / done / skipped
    source TEXT DEFAULT 'manual',        -- browser / probe / manual / dirsearch ...
    host TEXT DEFAULT '',                -- ★ 该 endpoint 属于哪个子域
    first_seen_wave INTEGER DEFAULT 0,   -- ★ Wave 1 发现的还是 Wave 2 深挖的
    created_at INTEGER
);

CREATE TABLE IF NOT EXISTS coverage (
    endpoint_id INTEGER NOT NULL REFERENCES endpoints(id),
    vuln_type TEXT NOT NULL,
    status TEXT DEFAULT 'pending',
    reason TEXT DEFAULT NULL,      -- ★ 未测成的原因 (见 COV_REASONS)，NULL = 还没轮到
    tested_at INTEGER,             -- ★ 什么时候测的
    evidence_ref TEXT DEFAULT '',  -- ★ 证据指针，如 "traffic:42"
    updated_at INTEGER,
    PRIMARY KEY (endpoint_id, vuln_type)
);

CREATE TABLE IF NOT EXISTS credentials (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    target_id INTEGER,
    username TEXT,
    password TEXT,
    source TEXT DEFAULT 'manual',  -- weak_pwd / register / leak / manual / wave3_step0
    login_url TEXT,
    note TEXT,
    auth_type TEXT DEFAULT 'password',  -- password / bearer / cookie / none
    token TEXT DEFAULT '',              -- bearer token 或完整 cookie 字符串
    host TEXT DEFAULT '',               -- ★ 冗余存 host，方便直查不 JOIN
    created_at INTEGER
);

CREATE TABLE IF NOT EXISTS traffic (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    endpoint_id INTEGER,
    ts INTEGER,
    method TEXT,
    url TEXT,
    request_headers TEXT,
    request_body TEXT,
    response_status INTEGER,
    response_headers TEXT,
    response_body TEXT,
    vuln_id INTEGER DEFAULT NULL,   -- ★ 这条流量是哪个漏洞的证据
    purpose TEXT DEFAULT 'probe_hit',  -- ★ 见 TRAFFIC_PURPOSES
    truncated INTEGER DEFAULT 0     -- ★ body 是否被截断
);

CREATE TABLE IF NOT EXISTS vulns (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    endpoint_id INTEGER,
    type TEXT,
    severity TEXT,          -- critical / high / medium / low / info
    title TEXT,
    description TEXT,
    evidence TEXT DEFAULT '{}',   -- JSON: request/response/repro
    dedup_key TEXT UNIQUE,        -- Gate5 去重依据
    gate_status TEXT DEFAULT 'pending',  -- accepted / rejected
    gate_reason TEXT,
    cwe TEXT DEFAULT '',          -- ★ 如 CWE-89
    cvss REAL DEFAULT 0.0,        -- ★ CVSS 评分
    chain_id INTEGER DEFAULT NULL,-- ★ 属于哪条攻击链
    confidence TEXT DEFAULT 'firm',  -- ★ certain / firm / tentative
    created_at INTEGER
);

CREATE TABLE IF NOT EXISTS chains (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    target_id INTEGER,
    name TEXT,                    -- ★ 如 "JS密钥泄露 → 未授权API → 越权读库"
    narrative TEXT,               -- ★ 完整叙述，报告直接用
    severity TEXT,
    cvss REAL DEFAULT 0.0,
    steps TEXT DEFAULT '[]',      -- ★ JSON: [{"vuln_id":3,"role":"入口"},...]
    verified INTEGER DEFAULT 0,   -- ★ 是否用浏览器实际验证过
    created_at INTEGER
);

CREATE TABLE IF NOT EXISTS sessions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    target_id INTEGER,
    run_id TEXT,
    started_at INTEGER,
    finished_at INTEGER,
    rounds INTEGER DEFAULT 1,
    reason TEXT,             -- context_threshold / max_turns / natural_end
    last_endpoint_id INTEGER,
    context_usage REAL DEFAULT 0.0   -- ★ 上下文使用率，续轮依据
);
"""


class AssetStore:
    """SQLite 资产库. 线程安全通过 'check_same_thread=False' + 每操作独立连接保证. """

    def __init__(self, db_path: str = "hackxplus.db"):
        self.db_path = db_path
        if os.path.dirname(db_path):
            Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        # 内存库必须复用单一连接, 否则 exec 的连接和查询的连接看不到彼此
        self._single = db_path == ":memory:"
        self._init_db()

    def _conn(self) -> sqlite3.Connection:
        if self._single and getattr(self, "_mem_conn", None) is not None:
            return self._mem_conn
        conn = sqlite3.connect(self.db_path, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL;")
        if self._single:
            self._mem_conn = conn
        return conn

    def _init_db(self) -> None:
        with self._conn() as c:
            c.executescript(_SCHEMA)
            self._migrate(c)

    def _migrate(self, c: sqlite3.Connection) -> None:
        """幂等列迁移. CREATE TABLE IF NOT EXISTS 不会给已存在的表加列, 这里补. """
        migrations = {
            "targets": {
                "root_domain": "TEXT DEFAULT ''",
            },
            "endpoints": {
                "host": "TEXT DEFAULT ''",
                "first_seen_wave": "INTEGER DEFAULT 0",
            },
            "coverage": {
                "reason": "TEXT DEFAULT NULL",
                "tested_at": "INTEGER",
                "evidence_ref": "TEXT DEFAULT ''",
            },
            "credentials": {
                "auth_type": "TEXT DEFAULT 'password'",
                "token": "TEXT DEFAULT ''",
                "host": "TEXT DEFAULT ''",
            },
            "traffic": {
                "vuln_id": "INTEGER DEFAULT NULL",
                "purpose": "TEXT DEFAULT 'probe_hit'",
                "truncated": "INTEGER DEFAULT 0",
            },
            "vulns": {
                "cwe": "TEXT DEFAULT ''",
                "cvss": "REAL DEFAULT 0.0",
                "chain_id": "INTEGER DEFAULT NULL",
                "confidence": "TEXT DEFAULT 'firm'",
            },
            "sessions": {
                "context_usage": "REAL DEFAULT 0.0",
            },
        }
        for table, cols in migrations.items():
            existing = {r["name"] for r in c.execute(f"PRAGMA table_info({table})")}
            for col, decl in cols.items():
                if col not in existing:
                    c.execute(f"ALTER TABLE {table} ADD COLUMN {col} {decl}")

    # ── targets ────────────────────────────────────────────────────────────
    @staticmethod
    def root_domain_of(url: str) -> str:
        """从 URL 抽根域：https://admin.target.co.uk → target.co.uk

        用于把同一战役的子域归拢。特殊处理：
        - 纯 IP（含端口）→ 原样返回，不截断（127.0.0.1 不是 "0.1"）
        - 双段公共后缀（co.uk / com.cn / com.hk 等）
        - localhost 等无点主机
        """
        host = url.split("//", 1)[-1].split("/", 1)[0]
        host = host.split("@")[-1].split(":", 1)[0]   # 去 user:pass@ 和 :port
        if not host:
            return ""

        # 纯 IPv4：原样返回
        if all(p.isdigit() for p in host.split(".") if p) and host.count(".") == 3:
            return host

        parts = [p for p in host.split(".") if p]
        if len(parts) <= 2:
            return host          # target.com / localhost —— 已是根域

        # 双段公共后缀（co.uk / com.cn / com.hk ...）
        two_level = {"co", "com", "net", "org", "gov", "edu", "ac"}
        if len(parts) >= 3 and parts[-2] in two_level and len(parts[-1]) == 2:
            return ".".join(parts[-3:])
        return ".".join(parts[-2:])

    def create_target(self, url: str, scope: str = "in-scope",
                      auth_mode: str = "unauthenticated",
                      root_domain: str = "") -> int:
        if not root_domain:
            root_domain = self.root_domain_of(url)
        with self._conn() as c:
            cur = c.execute(
                "INSERT INTO targets(url, scope, auth_mode, root_domain, created_at)"
                " VALUES(?,?,?,?,?)",
                (url, scope, auth_mode, root_domain, int(time.time())))
            return cur.lastrowid

    def list_targets_by_root(self, root_domain: str) -> List[Dict]:
        """同一战役下的全部子域 target。"""
        with self._conn() as c:
            return [dict(r) for r in c.execute(
                "SELECT * FROM targets WHERE root_domain=?", (root_domain,))]

    def get_target(self, target_id: int) -> Optional[Dict]:
        with self._conn() as c:
            row = c.execute("SELECT * FROM targets WHERE id=?", (target_id,)).fetchone()
            return dict(row) if row else None

    # ── endpoints ──────────────────────────────────────────────────────────
    def inject_endpoint(self, target_id: int, path: str, method: str = "GET",
                        params: Optional[List[str]] = None,
                        func_desc: str = "", risk_tags: Optional[List[str]] = None,
                        priority: int = 1, source: str = "manual",
                        host: str = "", first_seen_wave: int = 0) -> int:
        """注入一个新端点. 相同 (target_id, method, path) 已存在则 **合并** 新信息.

        合并语义 (重要): 重复注入不再静默丢弃 params/risk_tags/func_desc —
        旧值与新值取并集写回, 并为新增的 risk_tags 补建 coverage pending 行.
        批量接线时同一 endpoint 会被多个 Wave 用不同元数据注入多次, 早先的
        "return row['id']" 会把这些增量全部损失掉.

        host: 该 endpoint 属于哪个子域。空值时从 target 的 url 推导。
        """
        tgt = self.get_target(target_id)
        if not tgt:
            raise ValueError(f"target {target_id} not found — 先 create_target 再 inject_endpoint")
        if not host:
            host = (tgt.get("url") or "").split("//", 1)[-1].split("/", 1)[0].split(":", 1)[0]
        with self._conn() as c:
            row = c.execute(
                "SELECT id, params, risk_tags FROM endpoints"
                " WHERE target_id=? AND method=? AND path=?",
                (target_id, method, path)).fetchone()
            if row:
                eid = row["id"]
                old_params = set(json.loads(row["params"] or "[]"))
                old_tags = set(json.loads(row["risk_tags"] or "[]"))
                merged_params = sorted(old_params | set(params or []))
                merged_tags = sorted(old_tags | set(risk_tags or []))
                c.execute(
                    "UPDATE endpoints SET params=?, risk_tags=?,"
                    " func_desc=COALESCE(NULLIF(?,''), func_desc),"
                    " priority=MAX(priority,?),"
                    " host=COALESCE(NULLIF(host,''), ?),"
                    " first_seen_wave=CASE WHEN first_seen_wave=0 THEN ? ELSE first_seen_wave END"
                    " WHERE id=?",
                    (json.dumps(merged_params), json.dumps(merged_tags),
                     func_desc, priority, host, first_seen_wave, eid))
                # 新增的 risk_tags 也要补建 coverage (否则覆盖矩阵漏项)
                for vt in sorted(set(risk_tags or []) - old_tags):
                    c.execute(
                        "INSERT OR IGNORE INTO coverage(endpoint_id, vuln_type, status, updated_at)"
                        " VALUES(?,?,?,?)", (eid, vt, COV_PENDING, int(time.time())))
                return eid
            cur = c.execute(
                "INSERT INTO endpoints(target_id, path, method, params, func_desc,"
                " risk_tags, priority, test_status, source, host, first_seen_wave, created_at)"
                " VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
                (target_id, path, method,
                 json.dumps(params or []), func_desc,
                 json.dumps(risk_tags or []), priority, "pending", source,
                 host, first_seen_wave, int(time.time())))
            eid = cur.lastrowid
            # 为新端点初始化覆盖矩阵 (全 pending)
            tags = risk_tags or ["sqli", "xss", "ssti", "cmdi", "ssrf", "idor", "lfi"]
            for vt in tags:
                c.execute(
                    "INSERT OR IGNORE INTO coverage(endpoint_id, vuln_type, status, updated_at)"
                    " VALUES(?,?,?,?)", (eid, vt, COV_PENDING, int(time.time())))
            return eid

    def list_endpoints(self, target_id: int,
                       status: Optional[str] = None) -> List[Dict]:
        with self._conn() as c:
            sql = "SELECT * FROM endpoints WHERE target_id=?"
            args: List[Any] = [target_id]
            if status:
                sql += " AND test_status=?"
                args.append(status)
            return [dict(r) for r in c.execute(sql + " ORDER BY priority DESC", args)]

    def update_endpoint(self, endpoint_id: int, **fields) -> None:
        """部分更新. fields: func_desc / risk_tags / priority / test_status ..."""
        allowed = {"func_desc", "risk_tags", "priority", "test_status", "source"}
        sets, args = [], []
        for k, v in fields.items():
            if k not in allowed:
                continue
            if isinstance(v, (list, dict)):
                v = json.dumps(v, ensure_ascii=False)
            sets.append(f"{k}=?")
            args.append(v)
        if not sets:
            return
        args.append(endpoint_id)
        with self._conn() as c:
            c.execute(f"UPDATE endpoints SET {', '.join(sets)} WHERE id=?", args)

    # ── coverage ───────────────────────────────────────────────────────────
    def update_coverage(self, endpoint_id: int, vuln_type: str, status: str,
                        reason: Optional[str] = None,
                        evidence_ref: str = "") -> None:
        """更新覆盖矩阵.

        reason: 未测成的原因 (COV_REASONS 的键)。仅 status='pending' 时有意义。
                NULL = 真·还没轮到 —— 报告据此区分"没做"和"做不了"。
        """
        assert status in (COV_PENDING, COV_TESTING, COV_CONFIRMED, COV_NOT_VULNERABLE), status
        if reason is not None:
            assert reason in COV_REASONS, f"unknown reason: {reason}"
        now = int(time.time())
        with self._conn() as c:
            # 测出结果的记 tested_at；pending 保留原值可选
            c.execute(
                "INSERT OR REPLACE INTO coverage"
                "(endpoint_id, vuln_type, status, reason, tested_at, evidence_ref, updated_at)"
                " VALUES(?,?,?,?,?,?,?)",
                (endpoint_id, vuln_type, status, reason,
                 now if status != COV_PENDING else None,
                 evidence_ref, now))

    def pending_coverage(self, endpoint_id: int) -> List[str]:
        """返回该端点仍为 pending **且无阻塞原因** 的漏洞类型 (续轮时优先补测).

        注意：被 WAF 拦/超时的那些虽然也是 pending，但不该在续轮里空转重试，
        所以这里只返回 reason IS NULL 的。
        """
        with self._conn() as c:
            rows = c.execute(
                "SELECT vuln_type FROM coverage WHERE endpoint_id=? AND status='pending'"
                " AND (reason IS NULL OR reason='')", (endpoint_id,)).fetchall()
            return [r["vuln_type"] for r in rows]

    def blocked_coverage(self, endpoint_id: int) -> Dict[str, str]:
        """返回该端点被阻塞的 {vuln_type: reason} —— 报告里"为什么没测"的来源。"""
        with self._conn() as c:
            rows = c.execute(
                "SELECT vuln_type, reason FROM coverage"
                " WHERE endpoint_id=? AND status='pending'"
                " AND reason IS NOT NULL AND reason!=''", (endpoint_id,)).fetchall()
            return {r["vuln_type"]: r["reason"] for r in rows}

    def coverage_reason_stats(self, target_id: int) -> Dict[str, int]:
        """按原因汇总整个目标的未测项 —— 报告的执行摘要直接用。"""
        with self._conn() as c:
            rows = c.execute(
                "SELECT COALESCE(NULLIF(c.reason,''), '_not_reached') AS r, COUNT(*) n"
                " FROM coverage c JOIN endpoints e ON e.id=c.endpoint_id"
                " WHERE e.target_id=? AND c.status='pending' GROUP BY r",
                (target_id,)).fetchall()
            return {r["r"]: r["n"] for r in rows}

    def coverage_matrix(self, target_id: int) -> Dict:
        """汇总整个目标的覆盖情况 → 供资产树 stats 使用. """
        with self._conn() as c:
            total = c.execute("SELECT COUNT(*) n FROM endpoints WHERE target_id=?",
                              (target_id,)).fetchone()["n"]
            hosts = c.execute(
                "SELECT COUNT(DISTINCT host) n FROM endpoints"
                " WHERE target_id=? AND host!=''", (target_id,)).fetchone()["n"]
            tested = c.execute(
                "SELECT COUNT(DISTINCT endpoint_id) n FROM coverage c"
                " JOIN endpoints e ON e.id=c.endpoint_id"
                " WHERE e.target_id=? AND c.status IN ('confirmed','not_vulnerable')",
                (target_id,)).fetchone()["n"]
            blocked = c.execute(
                "SELECT COUNT(*) n FROM coverage c JOIN endpoints e ON e.id=c.endpoint_id"
                " WHERE e.target_id=? AND c.status='pending'"
                " AND c.reason IS NOT NULL AND c.reason!=''", (target_id,)).fetchone()["n"]
            vulns = c.execute(
                "SELECT COUNT(*) n FROM vulns v JOIN endpoints e ON e.id=v.endpoint_id"
                " WHERE e.target_id=? AND v.gate_status='accepted'",
                (target_id,)).fetchone()["n"]
            return {"total_endpoints": total, "hosts": hosts, "tested": tested,
                    "pending": total - tested, "blocked": blocked,
                    "vulns_found": vulns}

    # ── credentials ────────────────────────────────────────────────────────
    def add_credential(self, target_id: int, username: str, password: str,
                       source: str = "manual", login_url: str = "", note: str = "") -> int:
        with self._conn() as c:
            cur = c.execute(
                "INSERT INTO credentials(target_id, username, password, source,"
                " login_url, note, created_at) VALUES(?,?,?,?,?,?,?)",
                (target_id, username, password, source, login_url, note, int(time.time())))
            return cur.lastrowid

    def list_credentials(self, target_id: int) -> List[Dict]:
        with self._conn() as c:
            return [dict(r) for r in c.execute(
                "SELECT * FROM credentials WHERE target_id=?", (target_id,))]

    def set_auth(self, target_id: int, auth_type: str, token: str,
                 login_url: str = "", username: str = "",
                 source: str = "wave3_step0") -> int:
        """写入/覆盖该 target 的认证凭据. auth_type: bearer / cookie / password / none.

        同一 target 已有非 none 凭据时原地更新, 避免每次续轮都插入重复行.
        """
        with self._conn() as c:
            row = c.execute(
                "SELECT id FROM credentials WHERE target_id=? AND login_url=?"
                " ORDER BY id DESC LIMIT 1", (target_id, login_url)).fetchone()
            if row:
                c.execute(
                    "UPDATE credentials SET auth_type=?, token=?, username=?, source=?"
                    " WHERE id=?", (auth_type, token, username, source, row["id"]))
                return row["id"]
            cur = c.execute(
                "INSERT INTO credentials(target_id, username, password, source,"
                " login_url, note, auth_type, token, created_at)"
                " VALUES(?,?,?,?,?,?,?,?,?)",
                (target_id, username, "", source, login_url, "",
                 auth_type, token, int(time.time())))
            return cur.lastrowid

    def get_auth_for_target(self, target_id: int) -> Dict:
        """返回该 target 可用的认证头. 无凭据时返回 {}.

        按行序取第一条有效凭据 —— 这就是 per-host 隔离的落点: 每个 target
        有自己的 target_id, 因此 A 子域的 cookie 永远不会发给 B 子域.
        """
        for c in self.list_credentials(target_id):
            at, tk = c.get("auth_type"), c.get("token")
            if at == "bearer" and tk:
                return {"Authorization": f"Bearer {tk}"}
            if at == "cookie" and tk:
                return {"Cookie": tk}
        return {}

    # ── traffic ────────────────────────────────────────────────────────────
    # ⚠️ 只记有价值的请求（探针命中/漏洞验证/认证尝试/关键侦察响应）。
    #    普通请求不要入库 —— 每个存 2KB+，全量会撑爆 DB。
    BODY_LIMIT = 20000   # 单条 body 上限，超出截断并标记

    def add_traffic(self, endpoint_id: Optional[int], method: str, url: str,
                    req_headers: Dict, req_body: str,
                    resp_status: int, resp_headers: Dict, resp_body: str,
                    purpose: str = "probe_hit", vuln_id: Optional[int] = None) -> int:
        """记录一条请求/响应作为证据。返回 traffic_id（可写进 coverage.evidence_ref）。

        purpose: probe_hit / vuln_verify / login / recon
        vuln_id: 若这条流量是某个漏洞的证据，填该漏洞 id
        """
        truncated = 0
        if len(resp_body or "") > self.BODY_LIMIT:
            resp_body = resp_body[: self.BODY_LIMIT]
            truncated = 1
        if len(req_body or "") > self.BODY_LIMIT:
            req_body = req_body[: self.BODY_LIMIT]
            truncated = 1
        with self._conn() as c:
            cur = c.execute(
                "INSERT INTO traffic(endpoint_id, ts, method, url, request_headers,"
                " request_body, response_status, response_headers, response_body,"
                " vuln_id, purpose, truncated)"
                " VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
                (endpoint_id, int(time.time()), method, url,
                 json.dumps(req_headers, ensure_ascii=False), req_body,
                 resp_status, json.dumps(resp_headers, ensure_ascii=False), resp_body,
                 vuln_id, purpose, truncated))
            return cur.lastrowid

    def list_traffic(self, endpoint_id: int, limit: int = 50) -> List[Dict]:
        with self._conn() as c:
            return [dict(r) for r in c.execute(
                "SELECT * FROM traffic WHERE endpoint_id=? ORDER BY id DESC LIMIT ?",
                (endpoint_id, limit))]

    def get_traffic(self, traffic_id: int) -> Optional[Dict]:
        """按 id 取单条流量 —— coverage.evidence_ref 的 "traffic:42" 指向它。"""
        with self._conn() as c:
            row = c.execute("SELECT * FROM traffic WHERE id=?", (traffic_id,)).fetchone()
            return dict(row) if row else None

    # ── chains (攻击链) ────────────────────────────────────────────────────
    def record_chain(self, target_id: int, name: str, narrative: str = "",
                     severity: str = "high", cvss: float = 0.0,
                     steps: Optional[List[Dict]] = None, verified: bool = False) -> int:
        """记录一条攻击链。

        steps: [{"vuln_id": 3, "role": "入口"}, {"vuln_id": 7, "role": "提权"}]
        链的整体 severity 通常高于任一单点 —— 这正是"多低危串成高危"的价值。
        """
        with self._conn() as c:
            cur = c.execute(
                "INSERT INTO chains(target_id, name, narrative, severity, cvss,"
                " steps, verified, created_at) VALUES(?,?,?,?,?,?,?,?)",
                (target_id, name, narrative, severity, cvss,
                 json.dumps(steps or [], ensure_ascii=False),
                 1 if verified else 0, int(time.time())))
            cid = cur.lastrowid
            # 回标涉及到的漏洞
            for s in (steps or []):
                vid = s.get("vuln_id")
                if vid:
                    c.execute("UPDATE vulns SET chain_id=? WHERE id=?", (cid, vid))
            return cid

    def list_chains(self, target_id: int) -> List[Dict]:
        with self._conn() as c:
            out = []
            for r in c.execute("SELECT * FROM chains WHERE target_id=?"
                               " ORDER BY cvss DESC", (target_id,)):
                d = dict(r)
                d["steps"] = json.loads(d.get("steps") or "[]")
                d["verified"] = bool(d.get("verified"))
                out.append(d)
            return out

    # ── vulns (入库前必须在调用方过 gate_chain) ─────────────────────────────
    def record_vuln(self, endpoint_id: int, vtype: str, severity: str,
                    title: str, description: str, evidence: Dict,
                    dedup_key: str, gate_status: str = "accepted",
                    gate_reason: str = "", cwe: str = "", cvss: float = 0.0,
                    confidence: str = "firm") -> int:
        with self._conn() as c:
            cur = c.execute(
                "INSERT INTO vulns(endpoint_id, type, severity, title, description,"
                " evidence, dedup_key, gate_status, gate_reason, cwe, cvss,"
                " confidence, created_at)"
                " VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (endpoint_id, vtype, severity, title, description,
                 json.dumps(evidence, ensure_ascii=False), dedup_key,
                 gate_status, gate_reason, cwe, cvss, confidence, int(time.time())))
            return cur.lastrowid

    def list_vulns(self, target_id: int, gate_status: str = "accepted") -> List[Dict]:
        with self._conn() as c:
            return [dict(r) for r in c.execute(
                "SELECT v.*, e.path, e.method FROM vulns v"
                " JOIN endpoints e ON e.id=v.endpoint_id"
                " WHERE e.target_id=? AND v.gate_status=? ORDER BY"
                " CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1"
                " WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END, v.id",
                (target_id, gate_status))]

    # ── sessions (自动续轮) ────────────────────────────────────────────────
    def open_session(self, target_id: int, run_id: str) -> int:
        with self._conn() as c:
            cur = c.execute(
                "INSERT INTO sessions(target_id, run_id, started_at, reason, rounds)"
                " VALUES(?,?,?,?,1)", (target_id, run_id, int(time.time()), "natural_end"))
            return cur.lastrowid

    def close_session(self, session_id: int, reason: str) -> None:
        with self._conn() as c:
            c.execute("UPDATE sessions SET finished_at=?, reason=? WHERE id=?",
                      (int(time.time()), reason, session_id))

    def next_pending_endpoints(self, target_id: int, limit: int = 10) -> List[Dict]:
        """续轮入口: 返回待测端点.

        只算 **无阻塞原因** 的 pending（reason IS NULL）—— 被 WAF 拦/超时的那些
        虽然也是 pending，但重试也是白跑，不该占用续轮配额。
        """
        with self._conn() as c:
            rows = c.execute(
                "SELECT e.*, COUNT(c.vuln_type) pending_types FROM endpoints e"
                " LEFT JOIN coverage c ON c.endpoint_id=e.id AND c.status='pending'"
                "   AND (c.reason IS NULL OR c.reason='')"
                " WHERE e.target_id=? AND e.test_status!='done'"
                " GROUP BY e.id HAVING pending_types > 0"
                " ORDER BY e.priority DESC, pending_types DESC LIMIT ?",
                (target_id, limit)).fetchall()
            return [dict(r) for r in rows]

    def next_pending_across_hosts(self, root_domain: str, limit: int = 20) -> List[Dict]:
        """★ 跨子域统一排序的续轮队列。

        多子域场景的关键：单 target 的优先级在各自子域内排，但"哪个子域该先打"
        需要跨 host 比。这里按 (priority DESC, pending 数 DESC) 全局排序，
        并带上 host 便于直接生成请求。
        """
        with self._conn() as c:
            rows = c.execute(
                "SELECT e.*, t.url AS target_url, COUNT(c.vuln_type) pending_types"
                " FROM endpoints e"
                " JOIN targets t ON t.id = e.target_id"
                " LEFT JOIN coverage c ON c.endpoint_id=e.id AND c.status='pending'"
                "   AND (c.reason IS NULL OR c.reason='')"
                " WHERE t.root_domain=? AND e.test_status!='done'"
                " GROUP BY e.id HAVING pending_types > 0"
                " ORDER BY e.priority DESC, pending_types DESC LIMIT ?",
                (root_domain, limit)).fetchall()
            return [dict(r) for r in rows]

    # ── 资产树 (一次调用恢复完整渗透状态) ───────────────────────────────────
    def _endpoint_view(self, ep: Dict) -> Dict:
        """单个 endpoint 的精简视图（含"为什么没测"）。"""
        return {
            "id": ep["id"],
            "path": ep["path"],
            "method": ep["method"],
            "params": json.loads(ep["params"] or "[]"),
            "func_desc": ep["func_desc"],
            "risk_tags": json.loads(ep["risk_tags"] or "[]"),
            "test_status": ep["test_status"],
            "priority": ep["priority"],
            "host": ep.get("host", ""),
            "first_seen_wave": ep.get("first_seen_wave", 0),
            # 还没测且没有阻塞原因 → 真·待测
            "pending_vuln_types": self.pending_coverage(ep["id"]),
            # ★ 被阻塞的 → 报告里"为什么没测"的来源
            "blocked_reasons": self.blocked_coverage(ep["id"]),
        }

    def asset_tree(self, target_id: int, group_by_host: bool = True) -> Dict:
        """返回精简 JSON 树, agent 一条命令恢复全部状态.

        group_by_host=True（默认）：按 host 分组返回。多子域场景下这样才看得清
        哪个子域测到哪了 —— 之前扁平返回时，前端站和后端 API 的端点混在一起，
        `pending` 只是一个总数，说不出"卡在哪个子域"。

        group_by_host=False：返回扁平列表（兼容旧调用）。
        """
        tgt = self.get_target(target_id)
        if not tgt:
            return {"error": f"target {target_id} not found"}

        endpoints = self.list_endpoints(target_id)
        vulns = self.list_vulns(target_id)
        stats = self.coverage_matrix(target_id)

        base = {
            "target": tgt["url"],
            "root_domain": tgt.get("root_domain", ""),
            "auth_mode": tgt["auth_mode"],
            "credentials": self.list_credentials(target_id),
            "vulns": vulns,
            "chains": self.list_chains(target_id),
            "stats": stats,
            # ★ 按原因汇总的未测项 —— 报告执行摘要直接可用
            "pending_by_reason": self.coverage_reason_stats(target_id),
            "next_pending": self.next_pending_endpoints(target_id, limit=5),
        }

        if not group_by_host:
            base["endpoints"] = [self._endpoint_view(ep) for ep in endpoints]
            return base

        # 按 host 分组
        hosts: Dict[str, Dict] = {}
        for ep in endpoints:
            h = ep.get("host") or "(unknown)"
            g = hosts.setdefault(h, {
                "host": h, "target_id": target_id,
                "endpoints": [], "vulns": [],
            })
            g["endpoints"].append(self._endpoint_view(ep))

        # 漏洞按 host 归属
        ep_host = {ep["id"]: (ep.get("host") or "(unknown)") for ep in endpoints}
        for v in vulns:
            h = ep_host.get(v.get("endpoint_id"), "(unknown)")
            hosts.setdefault(h, {"host": h, "target_id": target_id,
                                 "endpoints": [], "vulns": []})
            hosts[h]["vulns"].append(v)

        # 每个 host 的小结
        for h, g in hosts.items():
            ep_ids = [e["id"] for e in g["endpoints"]]
            tested = sum(1 for e in g["endpoints"]
                         if e["test_status"] in ("done", "skipped"))
            blocked = sum(len(e["blocked_reasons"]) for e in g["endpoints"])
            g["summary"] = {
                "endpoints": len(g["endpoints"]),
                "tested": tested,
                "pending": len(g["endpoints"]) - tested,
                "blocked": blocked,
                "vulns": len(g["vulns"]),
            }

        base["hosts"] = hosts
        return base


if __name__ == "__main__":
    # 冒烟自测
    store = AssetStore(":memory:")
    tid = store.create_target("http://demo.test", auth_mode="register")
    eid = store.inject_endpoint(tid, "/api/user", "GET", params=["id"], risk_tags=["sqli", "idor"])
    store.update_coverage(eid, "sqli", "not_vulnerable")
    store.update_coverage(eid, "idor", "confirmed")
    store.add_credential(tid, "admin", "admin123")
    import json as _j
    print(_j.dumps(store.asset_tree(tid), ensure_ascii=False, indent=2))
    print("smoke OK")
