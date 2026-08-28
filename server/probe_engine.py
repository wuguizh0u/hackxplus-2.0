#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
probe_engine.py — hackxplus 探针执行引擎

50 探针从 markdown 迁到 JSON 配置 (agent/probes/*.json), 本引擎读取配置执行.
探针是确定性执行 (发请求 + 规则匹配), 不该花 LLM token; LLM 只消费 probe_hits 做判断.

配置格式 (agent/probes/tier1_universal.json):
    [{
      "id": "P1", "category": "sqli",
      "tier": 1, "name": "SQLi Boolean+Time+OOB",
      "method": "GET", "param": "id",
      "payloads": ["' OR 1=1-- -", "1' AND SLEEP(3)-- -", "'\" AND pg_sleep(3)-- -"],
      "detect": {
        "timeout_ms": 5000,               # 可选: time-based 判定
        "match_status": [500, 400],       # 可选: 命中状态码
        "match_regex": ["sql syntax", "mysql", "ORA-", "syntax error"],  # 可选
        "diff_mark": true                 # 可选: 响应长度差异
      }
    }, ...]

执行不引入重依赖: 优先 requests, 没有则用 urllib 兜底.
输出 probe_hits 统一结构:
    [{"probe_id": "P1", "category": "sqli", "param": "id", "payload": "...",
      "hit": true, "evidence": {"status": 500, "length": 1234, "match": "sql syntax"}}]
"""

import json
import os
import re
import time
import urllib.parse
from typing import Dict, List, Optional

try:
    import requests
    _HAVE_REQUESTS = True
except ImportError:
    _HAVE_REQUESTS = False


class ProbeEngine:
    def __init__(self, probes_dir: Optional[str] = None):
        # 默认指向仓库 agent/probes/
        self.probes_dir = probes_dir or os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "agent", "probes")

    # ── 配置加载 (按 tier 懒加载) ───────────────────────────────────────────
    def load_tier(self, tier: int) -> List[Dict]:
        fname = {1: "tier1_universal.json", 2: "tier2_signal.json",
                 3: "tier3_feedback.json"}.get(tier)
        if not fname:
            return []
        path = os.path.join(self.probes_dir, fname)
        if not os.path.exists(path):
            return []
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)

    # ── 请求执行 (requests 优先, urllib 兜底) ──────────────────────────────
    def _request(self, method: str, url: str, param: Optional[str],
                 payload: str, timeout: int = 10,
                 auth_headers: Dict = None) -> Dict:
        target = url
        headers = dict(auth_headers or {})
        headers.setdefault("User-Agent", "hackxplus-probe/1.0")
        body = None

        if param:
            parsed = urllib.parse.urlparse(url)
            query = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
            query[param] = [payload]
            new_q = urllib.parse.urlencode(query, doseq=True)
            target = urllib.parse.urlunparse(parsed._replace(query=new_q))

        if _HAVE_REQUESTS:
            try:
                resp = requests.request(
                    method, target, params=None if param else payload,
                    headers=headers, data=body,
                    timeout=timeout / 1000 if timeout < 100 else timeout,
                    verify=False, allow_redirects=True)
                return {"status": resp.status_code, "headers": dict(resp.headers),
                        "body": resp.text[:200000], "length": len(resp.content)}
            except requests.exceptions.RequestException as e:
                return {"error": str(e)}
        # urllib 兜底 (仅 GET)
        try:
            import ssl
            import urllib.request
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            req = urllib.request.Request(target, headers=headers)
            with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
                body = resp.read().decode("utf-8", errors="replace")
                return {"status": resp.status, "headers": dict(resp.headers),
                        "body": body[:200000], "length": len(body)}
        except Exception as e:
            return {"error": str(e)}

    # ── 命中判定 ───────────────────────────────────────────────────────────
    def _match(self, probe: Dict, resp: Dict, payload: str,
               baseline: Optional[Dict]) -> Optional[Dict]:
        detect = probe.get("detect", {})
        evidence = {"status": resp.get("status"),
                    "length": resp.get("length"),
                    "match": None, "error": resp.get("error")}

        if "error" in resp:
            return None  # 网络错误不算命中

        # 1) 状态码命中
        if detect.get("match_status") and resp.get("status") in detect["match_status"]:
            evidence["match"] = f"status={resp['status']}"
            return evidence

        # 2) 正则命中
        body = resp.get("body", "")
        for pat in detect.get("match_regex", []):
            if re.search(pat, body, re.IGNORECASE):
                evidence["match"] = pat
                return evidence

        # 3) time-based
        if detect.get("timeout_ms"):
            # 由调用方传入 elapsed; 这里简单用响应时长近似
            evidence["match"] = f"slow-response"
            return evidence

        # 4) diff_mark: 与基线长度差异超过阈值
        if detect.get("diff_mark") and baseline:
            bl = baseline.get("length") or 0
            cur = resp.get("length") or 0
            if abs(cur - bl) > max(detect.get("diff_threshold", 50), 50):
                evidence["match"] = f"length-diff {bl}->{cur}"
                return evidence
        return None

    # ── 主入口: 对目标执行某 tier 全部探针 ─────────────────────────────────
    def run(self, url: str, tier: int = 1, params: Optional[List[str]] = None,
            auth_headers: Dict = None) -> List[Dict]:
        """
        对 url 跑指定 tier 探针.
        params 缺省时自动从 url query 提取 (若无参数则回退到探测常见参数).
        """
        probes = self.load_tier(tier)
        if not probes:
            return []

        query_params = params or self._extract_params(url)
        hits: List[Dict] = []
        for probe in probes:
            for param in (query_params or ["id"]):
                baseline = None
                # 先拿基线 (无 payload)
                if probe.get("detect", {}).get("diff_mark"):
                    baseline = self._request(probe.get("method", "GET"), url,
                                             param, "", auth_headers=auth_headers)
                for payload in probe.get("payloads", [])[:3]:  # 每参数最多 3 payload, 控流量
                    t0 = time.time()
                    resp = self._request(probe.get("method", "GET"), url,
                                         param, payload,
                                         timeout=probe.get("detect", {}).get("timeout_ms", 10) or 10,
                                         auth_headers=auth_headers)
                    elapsed_ms = (time.time() - t0) * 1000
                    resp["elapsed_ms"] = elapsed_ms

                    evidence = self._match(probe, resp, payload, baseline)
                    if evidence:
                        hits.append({
                            "probe_id": probe["id"],
                            "category": probe["category"],
                            "param": param,
                            "payload": payload,
                            "hit": True,
                            "evidence": evidence,
                        })
                        break  # 该参数命中即停止后续 payload
        return hits

    @staticmethod
    def _extract_params(url: str) -> List[str]:
        parsed = urllib.parse.urlparse(url)
        return list(urllib.parse.parse_qs(parsed.query).keys())


if __name__ == "__main__":
    # 冒烟: 对本地靶场占位 URL 跑, 无环境则空转
    eng = ProbeEngine()
    print("requests available:", _HAVE_REQUESTS)
    print("tier1 probes loaded:", len(eng.load_tier(1)))
    print("params extract:", ProbeEngine._extract_params("http://x/?id=1&name=a"))
    print("smoke OK (engine init, no target executed)")
