#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
runner.py — hackxplus 自动续轮 + 恢复

解决"长任务中断/上下文爆"问题 (参考文章难点二):
    1. 上下文达到阈值 (约 50%) 或 max_turns 耗尽 → 写 checkpoint
    2. 新 Session 首指令 asset_get_asset_tree → 从 pending 端点继续
    3. 终止条件: 连续 2 轮无新端点 → 充分探索; 最大轮次上限 MAX_ROUNDS

本模块是"纯状态 + 决策规则", 不依赖 LLM 运行时, 可独立测试.
"""

import json
import os
from dataclasses import dataclass, field
from typing import Dict, List

MAX_ROUNDS = 70                 # 安全上限 (参考文章)
CONTEXT_THRESHOLD = 0.50        # 上下文使用达 50% 触发续轮
MIN_NEW_ENDPOINTS_TO_CONTINUE = 0  # 一轮无新端点即计数空轮


@dataclass
class RoundState:
    round_no: int = 1
    last_endpoint_id: int = 0
    endpoints_discovered_this_round: List[int] = field(default_factory=list)
    consecutive_empty_rounds: int = 0
    context_usage: float = 0.0     # 0.0-1.0, 由外部传入估算
    turns_used: int = 0
    max_turns: int = 200
    reason: str = "natural_end"
    done: bool = False

    def to_dict(self) -> Dict:
        return {"round_no": self.round_no, "last_endpoint_id": self.last_endpoint_id,
                "endpoints_discovered_this_round": self.endpoints_discovered_this_round,
                "consecutive_empty_rounds": self.consecutive_empty_rounds,
                "context_usage": self.context_usage, "turns_used": self.turns_used,
                "reason": self.reason, "done": self.done}


class Runner:
    """续轮决策器. 与 AssetStore 解耦: 传入状态即可决策, 便于单测. """

    def __init__(self, max_rounds: int = MAX_ROUNDS):
        self.max_rounds = max_rounds

    def should_continue(self, state: RoundState, new_endpoints_found: int) -> Dict:
        """每轮结束时调用. 返回是否续轮 + 原因. """
        state.endpoints_discovered_this_round = [new_endpoints_found]
        if new_endpoints_found <= MIN_NEW_ENDPOINTS_TO_CONTINUE:
            state.consecutive_empty_rounds += 1
        else:
            state.consecutive_empty_rounds = 0

        # 终止条件判定
        if state.round_no >= self.max_rounds:
            state.reason = "max_rounds_reached"
            state.done = True
            return {"continue": False, "reason": state.reason}
        if state.consecutive_empty_rounds >= 2:
            state.reason = "exhausted_no_new_endpoints"
            state.done = True
            return {"continue": False, "reason": state.reason}
        if state.context_usage >= CONTEXT_THRESHOLD:
            state.reason = "context_threshold"
            state.done = True  # 本会话结束, 但开新会话续轮
            return {"continue": True, "new_session": True, "reason": state.reason}
        if state.turns_used >= state.max_turns:
            state.reason = "max_turns"
            state.done = True
            return {"continue": True, "new_session": True, "reason": state.reason}

        return {"continue": True, "new_session": False, "reason": "proceed"}

    def save_checkpoint(self, path: str, state: RoundState, extra: Dict = None) -> None:
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        payload = {"state": state.to_dict(), "extra": extra or {}}
        with open(path, "w", encoding="utf-8") as f:
            json.dump(payload, f, ensure_ascii=False, indent=2)

    def load_checkpoint(self, path: str) -> Optional[RoundState]:
        if not os.path.exists(path):
            return None
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        s = data.get("state", {})
        st = RoundState(round_no=s.get("round_no", 1),
                        last_endpoint_id=s.get("last_endpoint_id", 0),
                        consecutive_empty_rounds=s.get("consecutive_empty_rounds", 0),
                        context_usage=s.get("context_usage", 0.0),
                        turns_used=s.get("turns_used", 0))
        st.done = s.get("done", False)
        st.reason = s.get("reason", "natural_end")
        return st


if __name__ == "__main__":
    r = Runner()
    st = RoundState(round_no=1, context_usage=0.3)
    for _ in range(3):
        # 模拟每轮发现 2 个新端点
        res = r.should_continue(st, new_endpoints_found=2)
        st.round_no += 1
        print(res)
    # 模拟连续空轮
    st2 = RoundState(round_no=5)
    print(r.should_continue(st2, 0))
    print(r.should_continue(st2, 0))
    print("smoke OK")
