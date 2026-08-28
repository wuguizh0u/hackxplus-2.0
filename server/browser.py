#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
browser.py — hackxplus Playwright 封装 (浏览器 = 眼睛和手)

参考文章定位: 浏览器是 agent 的眼睛和手, 用于与目标交互并捕获流量.
本模块提供三个核心能力 (均通过 MCP 暴露给 agent):
    open()          打开目标, 返回截图 + 快照
    deep_explore()  遍历导航链接, 触发页面加载, 捕获后端 API 调用
    traffic()       提取捕获到的请求/响应

Playwright 是可选依赖: 未安装时工具返回不可用, agent 降级纯 HTTP 探测 (不阻塞).
"""

import json
import time
from typing import Dict, List, Optional

_HAVE_PLAYWRIGHT = False
try:
    from playwright.sync_api import sync_playwright  # type: ignore
    _HAVE_PLAYWRIGHT = True
except ImportError:
    pass


class BrowserSession:
    """封装一次 Playwright 浏览器会话. 未安装 Playwright 时降级为占位. """

    def __init__(self):
        self._pw = None
        self._browser = None
        self._page = None
        self._traffic: List[Dict] = []
        self._available = _HAVE_PLAYWRIGHT

    def start(self, headless: bool = True) -> bool:
        if not self._available:
            return False
        self._pw = sync_playwright().start()
        self._browser = self._pw.chromium.launch(headless=headless)
        self._page = self._browser.new_page()
        # 捕获所有 XHR/fetch 网络流量 (即"后端 API 调用")
        self._page.on("request", self._on_request)
        self._page.on("response", self._on_response)
        return True

    def _on_request(self, req) -> None:
        if req.resource_type in ("xhr", "fetch"):
            self._traffic.append({
                "ts": int(time.time()), "method": req.method, "url": req.url,
                "post_data": req.post_data or "", "kind": "request"})

    def _on_response(self, resp) -> None:
        try:
            body = resp.text()[:200000]
        except Exception:
            body = ""
        for item in self._traffic:
            if item.get("kind") == "request" and item["url"] == resp.url:
                item.update({
                    "status": resp.status,
                    "content_type": resp.headers.get("content-type", ""),
                    "body_preview": body[:2000],
                    "kind": "response",
                })
                break

    def open(self, url: str) -> Dict:
        if not self._page:
            return {"available": False, "error": "playwright not available or not started"}
        self._page.goto(url, timeout=30000)
        time.sleep(1.5)
        snapshot = self._page.locator("body").inner_text()[:3000]
        return {"title": self._page.title(), "url": self._page.url,
                "text_snapshot": snapshot, "traffic_count": len(self._traffic)}

    def deep_explore(self, max_links: int = 30) -> Dict:
        """遍历当前页可见链接, 逐个点击, 捕获后端 API. 返回发现接口数. """
        if not self._page:
            return {"available": False}
        links = []
        try:
            anchors = self._page.locator("a").all()
            for a in anchors[:max_links]:
                href = a.get_attribute("href")
                if href and not href.startswith(("javascript:", "#")):
                    links.append(href)
        except Exception:
            pass
        visited = 0
        for href in links[:max_links]:
            try:
                self._page.goto(href, timeout=15000)
                time.sleep(0.6)
                visited += 1
            except Exception:
                continue
        return {"links_discovered": len(links), "links_visited": visited,
                "api_traffic": len([t for t in self._traffic if t.get("kind") == "response"])}

    def traffic(self, detail: bool = False) -> List[Dict]:
        return self._traffic[-200:] if detail else [
            {k: t[k] for k in ("method", "url", "status") if k in t} for t in self._traffic]

    def close(self) -> None:
        try:
            if self._browser:
                self._browser.close()
            if self._pw:
                self._pw.stop()
        except Exception:
            pass


if __name__ == "__main__":
    b = BrowserSession()
    ok = b.start(headless=True)
    print("playwright available:", ok)
    if ok:
        print(b.open("https://example.com")["title"])
        b.close()
    else:
        print("degraded mode: pure-HTTP probes only (no browser)")
    print("smoke OK")
