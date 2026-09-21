#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
mcp_server.py — hackxplus MCP Server 入口

把 asset_store / gate_chain / probe_engine / signal_router / browser / runner
包成 MCP 工具, 供 Claude Code (作为 MCP client) 按需调用.

启动:  python server/mcp_server.py
MCP 协议走 stdio (默认). 参考文章同款架构: agent 通过 MCP 工具读写资产库.

工具清单:
    asset_create_target     建目标 (每个活子域一个)
    asset_get_asset_tree    恢复/查看完整渗透状态 (续轮第一指令)
    asset_inject_endpoint   注入新发现的接口
    asset_annotate_endpoint 接口风险标注
    asset_record_vuln       漏洞入库 (触发五层门禁)
    asset_update_coverage   更新覆盖矩阵
    asset_set_auth          写入 per-host 认证凭据
    router_match            信号→技能映射
    gate_override_check     决策门覆写检测
    session_checkpoint      写续轮点
    session_resume          恢复 pending 端点

注: 探针不经 MCP 执行 —— 走 bash (probes/tier1_universal.sh 等 + run_probes_tier1/2)。
    探针命中后由 skill 层调 asset_update_coverage 回写覆盖矩阵。
"""

import argparse
import json
import sys
from typing import Dict, List, Optional

from asset_store import AssetStore
from gate_chain import GateChain, Vuln
# probe_engine 已停用：探针改回 bash（probes/*.sh + run_probes_tier1/2）。
# JSON 化路径经评估放弃 —— 声明式 schema 无法表达 bash 版的多步判定/响应头/
# 路径注入等条件，硬转会导致误报率上升（假命中把省下的 token 又吃回去）。
# 文件保留在 server/probe_engine.py 备查，不再 import。
from signal_router import route_signals, check_gate_override
from runner import Runner, RoundState

try:
    # mcp>=2.0: FastMCP 已移除, 用 lowlevel Server
    from mcp.server.lowlevel import Server  # noqa: F401
    from mcp.server.stdio import stdio_server  # noqa: F401
    from mcp.server.models import InitializationOptions  # noqa: F401
    from mcp.types import Tool, TextContent  # noqa: F401
    _HAVE_MCP = True
except ImportError:
    _HAVE_MCP = False

# 默认持久化位置: 运行时目录下 hackxplus.db (可用 --db 覆盖)
DB_PATH = "hackxplus.db"


# ── 纯函数层: 不依赖 mcp 库, 便于测试与复用 ───────────────────────────────
class HackXPlusCore:
    def __init__(self, db_path: str = DB_PATH):
        self.store = AssetStore(db_path)
        self.gate = GateChain()
        self.runner = Runner()
        self._session: Optional[RoundState] = None
        self._seen_keys: set = set()

    # 资产库
    def asset_get_asset_tree(self, target_id: int) -> Dict:
        return self.store.asset_tree(target_id)

    def asset_inject_endpoint(self, target_id: int, path: str, method: str = "GET",
                              params: Optional[List[str]] = None,
                              func_desc: str = "", risk_tags: Optional[List[str]] = None) -> Dict:
        eid = self.store.inject_endpoint(target_id, path, method, params,
                                         func_desc, risk_tags)
        return {"endpoint_id": eid}

    def asset_annotate_endpoint(self, endpoint_id: int, risk_tags: List[str],
                                priority: int = 1) -> Dict:
        self.store.update_endpoint(endpoint_id, risk_tags=risk_tags, priority=priority)
        return {"ok": True}

    def asset_record_vuln(self, endpoint_id: int, vtype: str, severity: str,
                          title: str, description: str = "",
                          evidence: Optional[Dict] = None) -> Dict:
        """漏洞入库 → 过五层门禁, 拒绝则不写入. """
        vuln = Vuln(endpoint_id=endpoint_id, type=vtype, severity=severity,
                    title=title, description=description, evidence=evidence or {})
        res = self.gate.validate(vuln)
        if not res.passed:
            return {"ok": False, "gate": res.gate, "reason": res.reason}
        vid = self.store.record_vuln(
            endpoint_id=endpoint_id, vtype=vtype, severity=severity,
            title=title, description=description, evidence=evidence or {},
            dedup_key=res.dedup_key, gate_status="accepted")
        self.store.update_coverage(endpoint_id, vtype, "confirmed")
        return {"ok": True, "vuln_id": vid}

    def asset_update_coverage(self, endpoint_id: int, vuln_type: str,
                              status: str) -> Dict:
        self.store.update_coverage(endpoint_id, vuln_type, status)
        return {"ok": True}

    def asset_set_auth(self, target_id: int, auth_type: str, token: str,
                       login_url: str = "", username: str = "") -> Dict:
        """写入 per-host 认证凭据。

        auth_type: bearer / cookie / password / none
        关键：凭据按 target 隔离 —— A 子域的 cookie 绝不会发给 B 子域。
             取不到凭据的 host 一律以 unauthenticated 跑（防"假认证"吞掉未授权漏洞）。
        """
        cid = self.store.set_auth(target_id, auth_type, token,
                                  login_url=login_url, username=username)
        return {"ok": True, "credential_id": cid}

    # 探针：已改回 bash（probes/*.sh + run_probes_tier1/2），不再经 MCP 执行。
    # 探针命中后回写覆盖矩阵用 asset_update_coverage。

    # 路由
    def router_match(self, tech_stack: Optional[List[str]] = None,
                     attack_text: str = "", infra_text: str = "",
                     feedback_hits: Optional[List[str]] = None) -> Dict:
        skills = route_signals(
            set(tech_stack or []), attack_text=attack_text, infra_text=infra_text,
            feedback_hits=set(feedback_hits or []))
        return {"skills": skills, "count": len(skills)}

    def gate_override_check(self, decision: Dict) -> Dict:
        actions = check_gate_override(decision)
        return {"actions": actions, "count": len(actions)}

    # 续轮
    def session_checkpoint(self, state: Dict, checkpoint_path: str) -> Dict:
        st = RoundState(round_no=state.get("round_no", 1),
                        context_usage=state.get("context_usage", 0.0),
                        turns_used=state.get("turns_used", 0),
                        last_endpoint_id=state.get("last_endpoint_id", 0))
        self.runner.save_checkpoint(checkpoint_path, st)
        return {"ok": True, "path": checkpoint_path}

    def session_resume(self, target_id: int, checkpoint_path: str = "") -> Dict:
        pending = self.store.next_pending_endpoints(target_id, limit=10)
        return {"pending": pending, "count": len(pending)}


# ── MCP 绑定层 (mcp>=2.0, lowlevel API) ───────────────────────────────────
# 兼容 mcp 2.x (pip install "mcp[cli]" 装的是新版, FastMCP 已移除, 改用 lowlevel Server)

def run_mcp(db_path: str) -> None:
    if not _HAVE_MCP:
        print("mcp 库未安装. 安装: pip install \"mcp[cli]\"\n"
              "降级可用: 通过 HackXPlusCore 直接调用核心逻辑.", file=sys.stderr)
        sys.exit(1)

    import asyncio
    from mcp.server.lowlevel import Server
    from mcp.server.models import InitializationOptions
    from mcp.server.stdio import stdio_server
    from mcp.types import Tool, TextContent

    core = HackXPlusCore(db_path)

    TOOLS = [
        Tool(name="asset_create_target", description="创建目标 (返回 target_id)",
             inputSchema={"type": "object",
                          "properties": {"url": {"type": "string"}, "scope": {"type": "string"},
                                         "auth_mode": {"type": "string"}},
                          "required": ["url"]}),
        Tool(name="asset_get_asset_tree", description="恢复/查看完整渗透状态 (续轮第一指令)",
             inputSchema={"type": "object", "properties": {"target_id": {"type": "integer"}},
                          "required": ["target_id"]}),
        Tool(name="asset_inject_endpoint", description="注入新发现的接口",
             inputSchema={"type": "object",
                          "properties": {"target_id": {"type": "integer"}, "path": {"type": "string"},
                                         "method": {"type": "string"}, "params": {"type": "string"},
                                         "func_desc": {"type": "string"}, "risk_tags": {"type": "string"}},
                          "required": ["target_id", "path"]}),
        Tool(name="asset_annotate_endpoint", description="接口风险标注",
             inputSchema={"type": "object",
                          "properties": {"endpoint_id": {"type": "integer"},
                                         "risk_tags": {"type": "string"}, "priority": {"type": "integer"}},
                          "required": ["endpoint_id", "risk_tags"]}),
        Tool(name="asset_record_vuln", description="漏洞入库 (触发五层门禁, 拒绝则不入库)",
             inputSchema={"type": "object",
                          "properties": {"endpoint_id": {"type": "integer"}, "vtype": {"type": "string"},
                                         "severity": {"type": "string"}, "title": {"type": "string"},
                                         "description": {"type": "string"}, "evidence": {"type": "string"}},
                          "required": ["endpoint_id", "vtype", "severity", "title"]}),
        Tool(name="asset_update_coverage", description="更新覆盖矩阵",
             inputSchema={"type": "object",
                          "properties": {"endpoint_id": {"type": "integer"},
                                         "vuln_type": {"type": "string"}, "status": {"type": "string"}},
                          "required": ["endpoint_id", "vuln_type", "status"]}),
        Tool(name="asset_set_auth", description="写入 per-host 认证凭据 (bearer/cookie/password/none)",
             inputSchema={"type": "object",
                          "properties": {"target_id": {"type": "integer"},
                                         "auth_type": {"type": "string"}, "token": {"type": "string"},
                                         "login_url": {"type": "string"}, "username": {"type": "string"}},
                          "required": ["target_id", "auth_type", "token"]}),
        Tool(name="router_match", description="信号→技能映射",
             inputSchema={
                 "type": "object",
                 "properties": {
                     "tech_stack": {"type": "string"},
                     "attack_text": {"type": "string"},
                     "infra_text": {"type": "string"},
                     "feedback_hits": {"type": "string"},
                 },
             }),
        Tool(name="gate_override_check", description="决策门覆写检测 (单向放宽)",
             inputSchema={"type": "object",
                          "properties": {"decision": {"type": "string"}},
                          "required": ["decision"]}),
        Tool(name="session_checkpoint", description="写续轮点",
             inputSchema={"type": "object",
                          "properties": {"state": {"type": "string"}, "checkpoint_path": {"type": "string"}},
                          "required": ["state", "checkpoint_path"]}),
        Tool(name="session_resume", description="恢复 pending 端点",
             inputSchema={"type": "object",
                          "properties": {"target_id": {"type": "integer"},
                                         "checkpoint_path": {"type": "string"}},
                          "required": ["target_id"]}),
    ]

    HANDLERS = {
        "asset_create_target": lambda a: json.dumps({"target_id": core.store.create_target(
            a["url"], a.get("scope", "in-scope"), a.get("auth_mode", "unauthenticated"))}, ensure_ascii=False),
        "asset_get_asset_tree": lambda a: json.dumps(core.asset_get_asset_tree(int(a["target_id"])), ensure_ascii=False),
        "asset_inject_endpoint": lambda a: json.dumps(core.asset_inject_endpoint(
            int(a["target_id"]), a["path"], a.get("method", "GET"),
            json.loads(a.get("params") or "[]"), a.get("func_desc", ""),
            json.loads(a.get("risk_tags") or "[]")), ensure_ascii=False),
        "asset_annotate_endpoint": lambda a: json.dumps(core.asset_annotate_endpoint(
            int(a["endpoint_id"]), json.loads(a.get("risk_tags") or "[]"),
            int(a.get("priority", 1))), ensure_ascii=False),
        "asset_record_vuln": lambda a: json.dumps(core.asset_record_vuln(
            int(a["endpoint_id"]), a["vtype"], a["severity"], a["title"],
            a.get("description", ""), json.loads(a.get("evidence") or "{}")), ensure_ascii=False),
        "asset_update_coverage": lambda a: json.dumps(core.asset_update_coverage(
            int(a["endpoint_id"]), a["vuln_type"], a["status"]), ensure_ascii=False),
        "asset_set_auth": lambda a: json.dumps(core.asset_set_auth(
            int(a["target_id"]), a["auth_type"], a["token"],
            a.get("login_url", ""), a.get("username", "")), ensure_ascii=False),
        "router_match": lambda a: json.dumps(core.router_match(
            json.loads(a.get("tech_stack") or "[]"), a.get("attack_text", ""),
            a.get("infra_text", ""), json.loads(a.get("feedback_hits") or "[]")), ensure_ascii=False),
        "gate_override_check": lambda a: json.dumps(core.gate_override_check(
            json.loads(a.get("decision") or "{}")), ensure_ascii=False),
        "session_checkpoint": lambda a: json.dumps(core.session_checkpoint(
            json.loads(a.get("state") or "{}"), a["checkpoint_path"]), ensure_ascii=False),
        "session_resume": lambda a: json.dumps(core.session_resume(
            int(a["target_id"]), a.get("checkpoint_path", "")), ensure_ascii=False),
    }

    from mcp import types

    async def on_list_tools(ctx, params):
        return types.ListToolsResult(tools=TOOLS)

    async def on_call_tool(ctx, params):
        name = params.name
        args = params.arguments or {}
        try:
            result = HANDLERS[name](args)
        except Exception as e:
            return types.CallToolResult(
                content=[types.TextContent(type="text", text=f"error: {e}")],
                isError=True)
        return types.CallToolResult(
            content=[types.TextContent(type="text", text=result)])

    server = Server(
        "hackxplus", version="0.1.0",
        on_list_tools=on_list_tools, on_call_tool=on_call_tool)

    async def main():
        async with stdio_server() as (read_stream, write_stream):
            await server.run(
                read_stream, write_stream,
                InitializationOptions(
                    server_name="hackxplus",
                    server_version="0.1.0",
                    capabilities={},
                ),
                raise_exceptions=False,
            )

    asyncio.run(main())


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="hackxplus MCP server")
    parser.add_argument("--db", default=DB_PATH, help="SQLite 资产库路径")
    parser.add_argument("--self-test", action="store_true", help="跑核心逻辑自测")
    args = parser.parse_args()

    if args.self_test:
        c = HackXPlusCore(":memory:")
        tid = c.store.create_target("http://demo", auth_mode="register")
        eid = c.asset_inject_endpoint(tid, "/api/x", "GET", ["id"], "test", ["sqli"])["endpoint_id"]
        print("inject:", eid)
        print("record vuln:", c.asset_record_vuln(
            eid, "cors", "info", "CORS on /api/x"))
        print("record vuln:", c.asset_record_vuln(
            eid, "sqli", "high", "SQLi /api/x?id=1", evidence={"params": ["id"]}))
        print("tree stats:", c.asset_get_asset_tree(tid)["stats"])
        print("router:", c.router_match(tech_stack=["php"], attack_text="/upload"))
        sys.exit(0)

    if not _HAVE_MCP:
        print("mcp 库未安装. 核心逻辑可用 (见 --self-test).\n"
              "完整 MCP 模式需: pip install mcp", file=sys.stderr)
        sys.exit(1)
    run_mcp(args.db)
