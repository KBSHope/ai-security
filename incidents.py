# incidents.py
from collections import defaultdict

def build_incidents(high_events: list[dict], fail_threshold: int = 5) -> list[dict]:
    """
    把 high_events 依 IP 聚合成 incident
    """
    by_ip = defaultdict(list)
    for e in high_events:
        ip = e.get("ip")
        if not ip:
            continue
        by_ip[ip].append(e)

    incidents = []
    for ip, events in by_ip.items():
        # 取這個 IP 在事件中出現過的最大累積失敗次數（你 event 裡已有 ip_fail_count）
        max_fail = max((ev.get("ip_fail_count", 0) for ev in events), default=0)

        if max_fail >= fail_threshold:
            incidents.append({
                "type": "BRUTE_FORCE",
                "severity": "CRITICAL",
                "ip": ip,
                "count": len(events),
                "max_ip_fail_count": max_fail,
                "evidence": [ev.get("raw") for ev in events[:5]],  # 只保留前 5 條當證據
            })
        else:
            incidents.append({
                "type": "SUSPICIOUS_ACTIVITY",
                "severity": "HIGH",
                "ip": ip,
                "count": len(events),
                "max_ip_fail_count": max_fail,
                "evidence": [ev.get("raw") for ev in events[:5]],
            })

    # 嚴重度/次數排序：先看 max_fail 再看 count
    incidents.sort(key=lambda x: (x["max_ip_fail_count"], x["count"]), reverse=True)
    return incidents

