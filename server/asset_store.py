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
    created_at INTEGER
);

CREATE TABLE IF NOT EXISTS coverage (
    endpoint_id INTEGER NOT NULL REFERENCES endpoints(id),
    vuln_type TEXT NOT NULL,
    status TEXT DEFAULT 'pending',
    updated_at INTEGER,
    PRIMARY KEY (endpoint_id, vuln_type)
);

CREATE TABLE IF NOT EXISTS credentials (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    target_id INTEGER,
    username TEXT,
    password TEXT,
    source TEXT DEFAULT 'manual',  -- weak_pwd / register / leak / manual
    login_url TEXT,
    note TEXT,
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
    response_body TEXT
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
    last_endpoint_id INTEGER
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

    # ── targets ────────────────────────────────────────────────────────────
    def create_target(self, url: str, scope: str = "in-scope",
                      auth_mode: str = "unauthenticated") -> int:
        with self._conn() as c:
            cur = c.execute(
                "INSERT INTO targets(url, scope, auth_mode, created_at) VALUES(?,?,?,?)",
                (url, scope, auth_mode, int(time.time())))
            return cur.lastrowid

    def get_target(self, target_id: int) -> Optional[Dict]:
        with self._conn() as c:
            row = c.execute("SELECT * FROM targets WHERE id=?", (target_id,)).fetchone()
            return dict(row) if row else None

    # ── endpoints ──────────────────────────────────────────────────────────
    def inject_endpoint(self, target_id: int, path: str, method: str = "GET",
                        params: Optional[List[str]] = None,
                        func_desc: str = "", risk_tags: Optional[List[str]] = None,
                        priority: int = 1, source: str = "manual") -> int:
        """注入一个新端点. 相同 (target_id, method, path) 已存在则返回现有 id (幂等). """
        tgt = self.get_target(target_id)
        if not tgt:
            raise ValueError(f"target {target_id} not found — 先 create_target 再 inject_endpoint")
        with self._conn() as c:
            row = c.execute(
                "SELECT id FROM endpoints WHERE target_id=? AND method=? AND path=?",
                (target_id, method, path)).fetchone()
            if row:
                return row["id"]
            cur = c.execute(
                "INSERT INTO endpoints(target_id, path, method, params, func_desc,"
                " risk_tags, priority, test_status, source, created_at)"
                " VALUES(?,?,?,?,?,?,?,?,?,?)",
                (target_id, path, method,
                 json.dumps(params or []), func_desc,
                 json.dumps(risk_tags or []), priority, "pending", source,
                 int(time.time())))
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
    def update_coverage(self, endpoint_id: int, vuln_type: str,
                        status: str) -> None:
        assert status in (COV_PENDING, COV_TESTING, COV_CONFIRMED, COV_NOT_VULNERABLE), status
        with self._conn() as c:
            c.execute(
                "INSERT OR REPLACE INTO coverage(endpoint_id, vuln_type, status, updated_at)"
                " VALUES(?,?,?,?)", (endpoint_id, vuln_type, status, int(time.time())))

    def pending_coverage(self, endpoint_id: int) -> List[str]:
        """返回该端点仍为 pending 的漏洞类型 (续轮时优先补测). """
        with self._conn() as c:
            rows = c.execute(
                "SELECT vuln_type FROM coverage WHERE endpoint_id=? AND status='pending'",
                (endpoint_id,)).fetchall()
            return [r["vuln_type"] for r in rows]

    def coverage_matrix(self, target_id: int) -> Dict:
        """汇总整个目标的覆盖情况 → 供资产树 stats 使用. """
        with self._conn() as c:
            total = c.execute("SELECT COUNT(*) n FROM endpoints WHERE target_id=?",
                              (target_id,)).fetchone()["n"]
            tested = c.execute(
                "SELECT COUNT(DISTINCT endpoint_id) n FROM coverage c"
                " JOIN endpoints e ON e.id=c.endpoint_id"
                " WHERE e.target_id=? AND c.status IN ('confirmed','not_vulnerable')",
                (target_id,)).fetchone()["n"]
            vulns = c.execute(
                "SELECT COUNT(*) n FROM vulns v JOIN endpoints e ON e.id=v.endpoint_id"
                " WHERE e.target_id=? AND v.gate_status='accepted'",
                (target_id,)).fetchone()["n"]
            return {"total_endpoints": total, "tested": tested,
                    "pending": total - tested, "vulns_found": vulns}

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

    # ── traffic ────────────────────────────────────────────────────────────
    def add_traffic(self, endpoint_id: Optional[int], method: str, url: str,
                    req_headers: Dict, req_body: str,
                    resp_status: int, resp_headers: Dict, resp_body: str) -> int:
        with self._conn() as c:
            cur = c.execute(
                "INSERT INTO traffic(endpoint_id, ts, method, url, request_headers,"
                " request_body, response_status, response_headers, response_body)"
                " VALUES(?,?,?,?,?,?,?,?,?)",
                (endpoint_id, int(time.time()), method, url,
                 json.dumps(req_headers, ensure_ascii=False), req_body,
                 resp_status, json.dumps(resp_headers, ensure_ascii=False), resp_body))
            return cur.lastrowid

    def list_traffic(self, endpoint_id: int, limit: int = 50) -> List[Dict]:
        with self._conn() as c:
            return [dict(r) for r in c.execute(
                "SELECT * FROM traffic WHERE endpoint_id=? ORDER BY id DESC LIMIT ?",
                (endpoint_id, limit))]

    # ── vulns (入库前必须在调用方过 gate_chain) ─────────────────────────────
    def record_vuln(self, endpoint_id: int, vtype: str, severity: str,
                    title: str, description: str, evidence: Dict,
                    dedup_key: str, gate_status: str = "accepted",
                    gate_reason: str = "") -> int:
        with self._conn() as c:
            cur = c.execute(
                "INSERT INTO vulns(endpoint_id, type, severity, title, description,"
                " evidence, dedup_key, gate_status, gate_reason, created_at)"
                " VALUES(?,?,?,?,?,?,?,?,?,?)",
                (endpoint_id, vtype, severity, title, description,
                 json.dumps(evidence, ensure_ascii=False), dedup_key,
                 gate_status, gate_reason, int(time.time())))
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
        """续轮入口: 返回待测端点 (覆盖矩阵里仍有 pending 类型的优先). """
        with self._conn() as c:
            rows = c.execute(
                "SELECT e.*, COUNT(c.vuln_type) pending_types FROM endpoints e"
                " LEFT JOIN coverage c ON c.endpoint_id=e.id AND c.status='pending'"
                " WHERE e.target_id=? AND e.test_status!='done'"
                " GROUP BY e.id ORDER BY e.priority DESC, pending_types DESC LIMIT ?",
                (target_id, limit)).fetchall()
            return [dict(r) for r in rows]

    # ── 资产树 (一次调用恢复完整渗透状态) ───────────────────────────────────
    def asset_tree(self, target_id: int) -> Dict:
        """返回精简 JSON 树, agent 一条命令恢复全部状态. 对应参考文章 asset_get_asset_tree. """
        tgt = self.get_target(target_id)
        if not tgt:
            return {"error": f"target {target_id} not found"}
        endpoints = self.list_endpoints(target_id)
        eps = []
        for ep in endpoints:
            eps.append({
                "id": ep["id"],
                "path": ep["path"],
                "method": ep["method"],
                "params": json.loads(ep["params"] or "[]"),
                "func_desc": ep["func_desc"],
                "risk_tags": json.loads(ep["risk_tags"] or "[]"),
                "test_status": ep["test_status"],
                "priority": ep["priority"],
                "pending_vuln_types": self.pending_coverage(ep["id"]),
            })
        return {
            "target": tgt["url"],
            "auth_mode": tgt["auth_mode"],
            "endpoints": eps,
            "credentials": self.list_credentials(target_id),
            "vulns": self.list_vulns(target_id),
            "stats": self.coverage_matrix(target_id),
            "next_pending": self.next_pending_endpoints(target_id, limit=5),
        }


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
