#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
gate_chain.py — hackxplus 五层漏洞质量门禁 (代码层硬控制)

参考文章作者核心结论: "SYSTEM PROMPT 的效果非常一般, 关键规则必须在代码层做硬性控制."
本模块把 anti_patterns.md 里的"垃圾洞纪律"从 prompt 约束落成代码强制.
漏洞只有通过全部 Gate 才允许入库 (asset_store.record_vuln).

五层:
    Gate1 垃圾洞标题拦截   — CORS / 安全头缺失 / Cookie 属性 / 点击劫持等
    Gate2 描述否定检测     — "not a vulnerability" / "expected behavior" 等自否
    Gate3 低价值类型黑名单  — SRC 不收的低危类型
    Gate4 IDOR 危害校验    — 越权必须证明访问了非授权数据
    Gate5 相同漏洞去重     — 同端点+同类型+同参数模式只入第一条
"""

import json
import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional

# ── Gate 1: 垃圾洞标题关键词 (命中即拒) ────────────────────────────────────
GATE1_JUNK_TITLE = [
    "cors", "cross-origin", "security header", "x-frame-options",
    "cookie flag", "httponly", "same-site", "samesite", "clickjacking",
    "content-security-policy", "csp", "hsts", "strict-transport-security",
    "server version", "x-powered-by", "technology disclosure",
]

# ── Gate 2: 描述/标题中的自否定表述 (命中即拒) ─────────────────────────────
GATE2_SELF_DENY = [
    "not a vulnerability", "not a bug", "not an issue",
    "expected behavior", "expected behaviour", "by design",
    "no impact", "no security impact", "won't fix", "wont fix",
    "false positive", "intended functionality",
]

# ── Gate 3: 低价值类型黑名单 (SRC 不收, 直接拒) ─────────────────────────────
GATE3_BLACKLIST_TYPES = {
    "self-xss", "sourcemap", "version-disclosure", "tls-version",
    "directory-listing", "host-header", "referrer-leak", "favicon-hash",
    "http-methods-options", "server-header",
}

# ── Gate 4: 需要额外危害证明的漏洞类型 ─────────────────────────────────────
GATE4_IMPACT_PROOF_REQUIRED = {
    "idor", "authbypass", "info_disclosure", "misconfig",
}


@dataclass
class Vuln:
    endpoint_id: int
    type: str
    severity: str            # critical / high / medium / low / info
    title: str
    description: str = ""
    evidence: Dict = field(default_factory=dict)
    # 可选去重键; 为空则由 Gate5 自动生成
    dedup_key: Optional[str] = None

    @property
    def canonical_key(self) -> str:
        """Gate5 去重键: 端点 + 类型 + 规范化参数模式."""
        params = sorted(self.evidence.get("params", []))
        return f"{self.endpoint_id}:{self.type}:{json.dumps(params, ensure_ascii=False)}"


@dataclass
class GateResult:
    passed: bool
    gate: int                # 1-5, 在哪一层被拦
    reason: str
    dedup_key: str

    def to_dict(self) -> Dict:
        return {"passed": self.passed, "gate": self.gate,
                "reason": self.reason, "dedup_key": self.dedup_key}


class GateChain:
    """五层门禁. 用法:
        gc = GateChain(seen_keys=set())
        res = gc.validate(vuln)
        if res.passed: store.record_vuln(..., dedup_key=res.dedup_key)
        else: log(res.reason)
    """

    def __init__(self, seen_keys: Optional[set] = None):
        # seen_keys 由调用方跨会话持久化, 防止重启后重复入库
        self.seen = seen_keys if seen_keys is not None else set()

    def validate(self, v: Vuln) -> GateResult:
        # Gate 1 — 垃圾洞标题拦截
        t = (v.title + " " + v.description).lower()
        for kw in GATE1_JUNK_TITLE:
            if kw in t:
                return self._reject(1, f"junk-title: contains '{kw}'")
            # 描述里明确否定危害
        for kw in GATE2_SELF_DENY:
            if kw in t:
                return self._reject(2, f"self-denied: '{kw}'")
        # Gate 3 — 低价值类型黑名单
        if v.type in GATE3_BLACKLIST_TYPES:
            return self._reject(3, f"blacklist-type: {v.type}")
        # Gate 4 — IDOR 等必须证明危害
        if v.type in GATE4_IMPACT_PROOF_REQUIRED:
            proof = self._impact_proof(v)
            if not proof:
                return self._reject(
                    4, f"{v.type} without unauthorized-data-access proof "
                       "(evidence must show access to data NOT belonging to the tester)")
        # Gate 5 — 去重
        key = v.dedup_key or v.canonical_key
        if key in self.seen:
            return self._reject(5, f"duplicate: {key}")
        self.seen.add(key)
        return GateResult(passed=True, gate=0, reason="accepted", dedup_key=key)

    # ── Gate 4 危害证明判定 ─────────────────────────────────────────────────
    def _impact_proof(self, v: Vuln) -> bool:
        ev = v.evidence or {}
        # 显式标记
        if ev.get("unauthorized_data_access"):
            return True
        # 越权访问到了 用户A→用户B 的数据 (evidence.response 里含他人数据特征)
        resp = ev.get("response", "")
        resp_body = ev.get("response_body", "")
        other_user = ev.get("other_user", "")
        if other_user and (other_user in resp or other_user in resp_body):
            return True
        # 状态码/响应体差异足以证明绕过 (401/403 → 200 拿到数据)
        if ev.get("auth_bypassed") is True:
            return True
        if v.severity in ("critical", "high") and ev.get("confirmed_by_llm"):
            # 高危且已由 LLM 判定危害的, 放行 (防止门禁误杀)
            return True
        return False

    def _reject(self, gate: int, reason: str) -> GateResult:
        return GateResult(passed=False, gate=gate, reason=reason, dedup_key="")


# ── 便捷工具: 从文本快速判"是不是垃圾洞" (供 probe_engine 预过滤) ────────────
def is_junk_title(title: str) -> bool:
    t = title.lower()
    return any(k in t for k in GATE1_JUNK_TITLE) or any(k in t for k in GATE2_SELF_DENY)


if __name__ == "__main__":
    # 冒烟自测
    gc = GateChain()
    cases = [
        Vuln(1, "cors", "info", "CORS misconfiguration on /api"),
        Vuln(1, "sqli", "high", "SQLi in /api/user?id=1", evidence={"params": ["id"]}),
        Vuln(1, "sqli", "high", "SQLi in /api/user?id=1", evidence={"params": ["id"]}),
        Vuln(1, "idor", "high", "IDOR /api/order", evidence={"params": ["id"]}),
        Vuln(1, "idor", "high", "IDOR /api/order", evidence={"params": ["id"], "auth_bypassed": True}),
    ]
    for c in cases:
        r = gc.validate(c)
        print(f"GATE{r.gate} {r.reason:<40} pass={r.passed}")
    print("smoke OK")
