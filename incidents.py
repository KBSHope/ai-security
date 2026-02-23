# incidents.py

from collections import defaultdict
from datetime import timedelta   

def build_correlated_incidents(
    auth_events: list[dict],
    window: timedelta = timedelta(minutes=5),
    fail_threshold: int = 5
) -> list[dict]:
    """
    Time-window based brute force detection.

    Expected auth_event fields:
    - timestamp: datetime
    - ip: str
    - username: str
    - status: "fail" | "success"
    - raw: str
    """
    incidents = []

    # 1️⃣ 依 IP 分組
    events_by_ip = defaultdict(list)
    for ev in auth_events:
        ip = ev.get("ip")
        if not ip:
            continue
        events_by_ip[ip].append(ev)

    # 2️⃣ 對每個 IP 做 sliding window（只看 fail）
    for ip, events in events_by_ip.items():
        fail_events = [
            e for e in events
            if e.get("status") == "fail" and e.get("timestamp")
        ]
        fail_events.sort(key=lambda e: e["timestamp"])

        start = 0
        for end in range(len(fail_events)):
            while (
                fail_events[end]["timestamp"]
                - fail_events[start]["timestamp"]
                > window
            ):
                start += 1

            window_events = fail_events[start:end + 1]

            if len(window_events) >= fail_threshold:
                incidents.append({
                    "type": "BRUTE_FORCE",
                    "severity": "CRITICAL",
                    "ip": ip,
                    "count": len(window_events),
                    "window": str(window),
                    "start_time": window_events[0]["timestamp"],
                    "end_time": window_events[-1]["timestamp"],
                    "evidence": [
                        e.get("raw") for e in window_events[:5]
                    ],
                })
                break  # 同一 IP 只報一次
    return incidents

def build_account_based_incidents(
    auth_events: list[dict],
    window,
    fail_threshold: int = 5,
    ip_threshold: int = 3,
) -> list[dict]:
    """
    Account-based attack detection:
    Same username, many failed logins, from multiple IPs within time window.
    """

    incidents = []

    # 依 username 分組
    by_user = defaultdict(list)
    for ev in auth_events:
        user = ev.get("username")
        if not user:
            continue
        by_user[user].append(ev)

    for user, events in by_user.items():
        # 只看 fail
        fail_events = [
            e for e in events
            if e.get("status") == "fail" and e.get("timestamp")
        ]
        fail_events.sort(key=lambda e: e["timestamp"])

        start = 0
        for end in range(len(fail_events)):
            while (
                fail_events[end]["timestamp"]
                - fail_events[start]["timestamp"]
                > window
            ):
                start += 1

            window_events = fail_events[start:end + 1]
            ips = {e.get("ip") for e in window_events if e.get("ip")}

            if len(window_events) >= fail_threshold and len(ips) >= ip_threshold:
                incidents.append({
                    "type": "ACCOUNT_BRUTE_FORCE",
                    "severity": "CRITICAL",
                    "username": user,
                    "count": len(window_events),
                    "ip_count": len(ips),
                    "ips": list(ips),
                    "window": str(window),
                    "start_time": window_events[0]["timestamp"],
                    "end_time": window_events[-1]["timestamp"],
                    "evidence": [e.get("raw") for e in window_events[:5]],
                })
                break  # 同一帳號只報一次

    return incidents

# -----------------------------
# B2: Cross-signal correlation
# -----------------------------

def detect_fail_then_success(
    auth_events: list[dict],
    window: timedelta,
) -> list[dict]:
    incidents = []

    # 1) 依 username 分組
    events_by_user = defaultdict(list)
    for ev in auth_events:
        username = ev.get("username") or "unknown"
        ts = ev.get("timestamp")
        if not ts:
            continue
        events_by_user[username].append(ev)

    # 2) 每個 user 依時間排序，找「success 前 window 內的 fail」
    for username, events in events_by_user.items():
        events.sort(key=lambda e: e["timestamp"])

        for i, ev in enumerate(events):
            if ev.get("status") != "success":
                continue

            success_time = ev["timestamp"]

            recent_fails = []
            for e in events[:i]:  # success 之前的事件
                if e.get("status") != "fail":
                    continue
                if not e.get("timestamp"):
                    continue

                dt = success_time - e["timestamp"]
                if timedelta(0) <= dt <= window:
                    recent_fails.append(e)

            if recent_fails:
                incidents.append({
                    "type": "FAIL_THEN_SUCCESS",
                    "severity": "HIGH",
                    "username": username,
                    "fail_count": len(recent_fails),
                    "window": str(window),
                    "success_time": success_time,
                    "ips": sorted({e.get("ip") for e in recent_fails if e.get("ip")}),
                    "evidence": [e.get("raw") for e in recent_fails[:5]] + [ev.get("raw")],
                })
                break  # 同一個 user 只報一次

    return incidents

def build_risk_enriched_incidents(
    auth_events: list[dict],
    ip_incidents: list[dict],
    account_incidents: list[dict],
    b2_incidents: list[dict],
) -> list[dict]:
    """
    將多種偵測結果（IP brute force / account-based / fail-then-success）
    合併成一份 enriched incidents，並附上 risk_score。
    """

    enriched = []

    # 1) 先把所有 incidents 串起來
    all_incs = []
    all_incs.extend(ip_incidents or [])
    all_incs.extend(account_incidents or [])
    all_incs.extend(b2_incidents or [])

    # 2) risk score 簡單規則（你之後可以再調）
    severity_score = {
        "LOW": 10,
        "MEDIUM": 30,
        "HIGH": 60,
        "CRITICAL": 90,
    }

    type_bonus = {
        "BRUTE_FORCE": 10,
        "ACCOUNT_BRUTE_FORCE": 15,
        "FAIL_THEN_SUCCESS": 25,
    }

    for inc in all_incs:
        sev = inc.get("severity", "MEDIUM")
        base = severity_score.get(sev, 30)
        bonus = type_bonus.get(inc.get("type"), 0)

        # count 越大分數越高（上限 +30）
        count = inc.get("count") or inc.get("fail_count") or 0
        count_boost = min(30, int(count) * 3) if isinstance(count, int) else 0

        risk_score = min(100, base + bonus + count_boost)

        enriched.append({
            **inc,
            "risk_score": risk_score,
        })

    # 3) 依 risk_score 由高到低排序
    enriched.sort(key=lambda x: x.get("risk_score", 0), reverse=True)

    return enriched
    
def detect_ip_multi_account_attack(
    auth_events: list[dict],
    window: timedelta,
    user_threshold: int = 3,
    fail_only: bool = True,
) -> list[dict]:
    """
    Detect: same IP triggers failed logins across many usernames within a time window.
    Expected auth_event fields: timestamp(datetime), ip(str), username(str), status("fail"/"success"), raw(str)
    """
    # 依 IP 分組
    events_by_ip = defaultdict(list)
    for ev in auth_events:
        ip = ev.get("ip")
        ts = ev.get("timestamp")
        if not ip or not ts:
            continue
        if fail_only and ev.get("status") != "fail":
            continue
        events_by_ip[ip].append(ev)

    incidents = []

    for ip, events in events_by_ip.items():
        events.sort(key=lambda e: e["timestamp"])

        start = 0
        for end in range(len(events)):
            # 縮小 window
            while events[end]["timestamp"] - events[start]["timestamp"] > window:
                start += 1

            window_events = events[start:end+1]
            users = { (e.get("username") or "unknown") for e in window_events }

            if len(users) >= user_threshold:
                incidents.append({
                    "type": "IP_MULTI_ACCOUNT",
                    "severity": "HIGH",
                    "ip": ip,
                    "user_count": len(users),
                    "users": sorted(users),
                    "window": str(window),
                    "start_time": window_events[0]["timestamp"],
                    "end_time": window_events[-1]["timestamp"],
                    "evidence": [e.get("raw") for e in window_events[:8]],
                })
                break  # 同一 IP 報一次就好

    return incidents