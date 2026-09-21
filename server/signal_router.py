#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
signal_router.py — hackxplus 信号路由 (技术栈/攻击面/反馈 → 技能加载清单)

把 markdown 里的"信号→技能映射表"(signal_router.md) 代码化.
输入多路信号, 输出按 RCE>Auth>Info 排序的技能加载清单.
探针只做"发请求+规则匹配", 技能该不该加载由这里决定 (探针贱, 技能贵).

信号来源:
    tech      技术栈 (HTTP 头/Cookie/错误页/HTML)   ← 隐式框架检测
    attack    攻击面 (登录/JWT/GraphQL/上传/支付...)
    infra     基础设施 (CDN/SCM/actuator/邮件...)
    feedback  探针反馈 (P3命中→ssti, LFI读到environ→cmdi...)
"""

import re
from typing import Dict, List, Set


# ── 技术栈 → 技能 (隐式框架检测逻辑内嵌) ────────────────────────────────────
TECH_RULES = [
    # (信号正则, 匹配串, 推断技术栈, 加载技能)
    (r"jsessionid", "cookie", "java-tomcat", ["deserialization", "ghost-bits", "jndi", "el-injection"]),
    (r"phpsessid", "cookie", "php", ["type-juggling", "deserialization", "lfi"]),
    (r"laravel_session", "cookie", "laravel", ["lfi", "upload"]),
    (r"org\.springframework", "error", "spring-boot", ["deserialization", "jndi", "403-bypass"]),
    (r"pdoexception|fatal error", "error", "php", ["type-juggling", "deserialization", "lfi"]),
    (r"traceback.*most recent call last", "error", "python", ["ssti", "deserialization"]),
    (r"wordpress", "meta", "wordpress", ["upload", "authbypass"]),
    (r"__next_data__|/_next/static", "html", "next-js", ["ssrf", "idor"]),
    (r"__nuxt|/_nuxt/static", "html", "nuxt", ["ssrf", "idor"]),
    (r"asp\.net|viewstate|__VIEWSTATE", "cookie", "dotnet-iis", ["deserialization", "xslt-injection"]),
    (r"express|node|koa", "header", "node-express", ["prototype-pollution", "nosql"]),
    (r"graphql", "header", "graphql", ["graphql"]),
    (r"django|csrftoken", "cookie", "django", ["csrf", "idor"]),
]

# ── 攻击面信号 → 技能 ─────────────────────────────────────────────────────
ATTACK_RULES = [
    (r"/login|/signin|/auth", "login", ["authbypass", "csrf", "race-condition", "weak-password"]),
    (r"jwt|bearer", "token", ["jwt-oauth"]),
    (r"graphql", "endpoint", ["graphql"]),
    (r"pay|charge|order|checkout|refund|wallet", "biz", ["business-logic", "race-condition"]),
    (r"upload|file|attach|avatar", "endpoint", ["upload"]),
    (r"tenant|org_id|account_id|user_id=\d", "multi-tenant", ["idor", "business-logic"]),
    (r"id=\d|page=\d|user=\d|profile=\d", "numeric-id", ["idor"]),
]

# ── 基础设施信号 → 技能 ───────────────────────────────────────────────────
INFRA_RULES = [
    (r"cloudfront|cloudflare|akamai|s3\.amazonaws|aliyuncs\.com", "cname-cdn", ["subdomain-takeover"]),
    (r"\.git/|\.svn/|source code|scm", "scm", ["source-code-leak"]),
    (r"actuator|heapdump|jolokia", "endpoint", ["deserialization", "403-bypass"]),
    (r"cdn|waf", "header", ["waf-bypass", "http2"]),
]

# ── 探针反馈 → 技能 (单轮, 不递归) ────────────────────────────────────────
FEEDBACK_RULES = [
    ("ssti", "ssti"),
    ("lfi-environ", "cmdi"),
    ("ssrf-metadata", "dns-rebinding"),
    ("sqli-error", "sqli-deep"),
    ("deserial-java", "ghost-bits"),
]

# 优先级: P0 RCE > P1 Auth > P2 Info
PRIORITY = {"P0": 0, "P1": 1, "P2": 2}


def _tech_stack(cookie: str = "", error_page: str = "", html: str = "",
                headers: Dict = None) -> Set[str]:
    headers = headers or {}
    haystacks = {
        "cookie": cookie,
        "error": error_page,
        "html": html,
        "header": " ".join(headers.values()),
    }
    stacks = set()
    for regex, source, stack, _ in TECH_RULES:
        if re.search(regex, haystacks.get(source, ""), re.IGNORECASE):
            stacks.add(stack)
    return stacks


def _match(rules, text: str) -> Set[str]:
    out = set()
    for regex, _kind, skills in rules:
        if re.search(regex, text, re.IGNORECASE):
            out.update(skills)
    return out


def route_signals(tech_stack: Set[str], attack_text: str = "",
                  infra_text: str = "", feedback_hits: Set[str] = None,
                  cookie: str = "", error_page: str = "", html: str = "",
                  headers: Dict = None) -> List[Dict]:
    """
    汇总所有信号 → 技能清单.
    返回: [{"skill": ..., "priority": "P0"/"P1"/"P2", "source": [...]}]
    """
    stacks = tech_stack or _tech_stack(cookie, error_page, html, headers)

    skill_source: Dict[str, List[str]] = {}
    for stack in stacks:
        for regex, _src, _st, skills in TECH_RULES:
            # 该 stack 对应的技能都挂上 (简化: 按 stack 名倒查)
            if stack == _st:
                for s in skills:
                    skill_source.setdefault(s, []).append(f"tech:{stack}")

    for s in _match(ATTACK_RULES, attack_text):
        skill_source.setdefault(s, []).append("attack")
    for s in _match(INFRA_RULES, infra_text):
        skill_source.setdefault(s, []).append("infra")
    for hit in (feedback_hits or set()):
        for fb_hit, skill in FEEDBACK_RULES:
            if hit == fb_hit:
                skill_source.setdefault(skill, []).append(f"feedback:{hit}")

    # 按优先级排序
    def prio(skill: str) -> int:
        # 显式映射, 未列出的默认 P1
        p0 = {"deserialization", "cmdi", "ssti", "sqli-deep", "ghost-bits", "jndi",
              "el-injection", "xxe", "upload", "ssrf", "dns-rebinding", "prototype-pollution"}
        p2 = {"xss", "open-redirect", "crlf", "graphql", "source-code-leak",
              "subdomain-takeover", "waf-bypass", "http2"}
        if skill in p0:
            return 0
        if skill in p2:
            return 2
        return 1

    ordered = sorted(skill_source.items(),
                     key=lambda kv: (prio(kv[0]), kv[0]))
    return [{"skill": k, "priority": f"P{prio(k)}", "source": v}
            for k, v in ordered]


# ── Gate Override 判定 (单向放宽) ──────────────────────────────────────────
OVERRIDE_SIGNALS = {
    "static-skip": {
        "cond": lambda r: r.get("static") and r.get("dynamic_endpoint_found"),
        "action": "append-wave2-reduced", "desc": "静态站判定被 /api 动态端点推翻",
    },
    "headers-only": {
        "cond": lambda r: r.get("headers_only") and r.get("login_form_found"),
        "action": "expand-tier2", "desc": "仅 headers 策略被登录表单推翻",
    },
    "waf-skip-sqlmap": {
        "cond": lambda r: r.get("strong_waf") and r.get("probe_bypassed_waf"),
        "action": "allow-sqlmap-level1", "desc": "探针绕过 WAF → 放宽 sqlmap",
    },
    "unknown-cms": {
        "cond": lambda r: r.get("cms_features_found") and r.get("classified_unknown"),
        "action": "append-cms-probes", "desc": "CMS 特征被覆盖 → 追加 CMS 专杀",
    },
}


def check_gate_override(decision: Dict) -> List[Dict]:
    """Gate Override: 只允许 '跳过→启用' 单向放宽, 不可反向收紧. 返回追加动作列表."""
    actions = []
    for name, rule in OVERRIDE_SIGNALS.items():
        try:
            if rule["cond"](decision):
                actions.append({"signal": name, "action": rule["action"], "desc": rule["desc"]})
        except (KeyError, TypeError):
            continue
    return actions


if __name__ == "__main__":
    # 冒烟
    s = _tech_stack(cookie="laravel_session=abc", html="")
    print("tech:", s)
    out = route_signals(s, attack_text="/api/user?id=1&pay=1",
                        infra_text="actuator exposed")
    for o in out:
        print(f"  P: {o}")
    print("override:", check_gate_override({"static": True, "dynamic_endpoint_found": True}))
    print("smoke OK")
