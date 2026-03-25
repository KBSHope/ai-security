from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable, Dict, Any, List, Optional
import re

Event = Dict[str, Any]


@dataclass(frozen=True)
class Rule:
    name: str
    description: str
    score_delta: int
    # 回傳 True 就觸發
    condition: Callable[[Event], bool]
    # 可選：觸發時加上 tags
    tags: List[str] = field(default_factory=list)


def _s(val: Any) -> str:
    return (val or "").__str__().lower()


def _get_ip(ev: Event) -> str:
    # 兼容 local/cloud 不同欄位
    return ev.get("ip") or ev.get("source_ip") or ev.get("sourceIPAddress") or ""


def _get_user(ev: Event) -> str:
    return ev.get("username") or ev.get("user") or ev.get("userName") or ""


def _get_status(ev: Event) -> str:
    return ev.get("status") or ""  # local 常見：fail/success


def _get_event_name(ev: Event) -> str:
    # cloud 常見 eventName
    return ev.get("event_name") or ev.get("eventName") or ""


# 你可以在這裡一直加規則（越加越強）
RULES: List[Rule] = [
    # ===== Local auth.log 類 =====
    Rule(
        name="AUTH_FAILED_LOGIN",
        description="Failed login attempt detected",
        score_delta=15,
        condition=lambda e: _get_status(e) == "fail" or ("failed login" in _s(e.get("raw"))),
        tags=["local", "auth"],
    ),
    Rule(
        name="AUTH_ACCEPTED_PASSWORD",
        description="Successful login detected",
        score_delta=5,
        condition=lambda e: _get_status(e) == "success" or ("accepted password" in _s(e.get("raw"))),
        tags=["local", "auth"],
    ),

    # ===== CloudTrail 類 =====
    Rule(
        name="ROOT_USAGE",
        description="Root account usage detected (ConsoleLogin as Root)",
        score_delta=80,
        condition=lambda e: _get_event_name(e) == "ConsoleLogin" and _get_user(e).lower() == "root",
        tags=["cloud", "iam", "critical"],
    ),
    Rule(
        name="IAM_PRIV_ESCALATION_ATTACH_POLICY",
        description="Possible privilege escalation via AttachUserPolicy",
        score_delta=60,
        condition=lambda e: _get_event_name(e) in {"AttachUserPolicy", "AttachRolePolicy", "PutUserPolicy", "PutRolePolicy"},
        tags=["cloud", "iam", "priv-esc"],
    ),
]


def apply_rules(event: Event, base_score: int = 0) -> Dict[str, Any]:
    """
    套用所有規則到單一 event
    回傳：
      final_score, matched_rules(list), tags(set)
    """
    score = int(base_score)
    matched: List[Dict[str, Any]] = []
    tags = set(event.get("tags", []) or [])

    for rule in RULES:
        try:
            if rule.condition(event):
                score += rule.score_delta
                matched.append(
                    {
                        "rule": rule.name,
                        "delta": rule.score_delta,
                        "desc": rule.description,
                    }
                )
                for t in rule.tags:
                    tags.add(t)
        except Exception as ex:
            # 規則爆掉不要整個程式死
            matched.append({"rule": rule.name, "error": str(ex)})

    # clamp：0~100
    score = max(0, min(score, 100))
    return {
        "final_score": score,
        "matched_rules": matched,
        "tags": sorted(tags),
    }