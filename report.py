# report.py
import json
import re
from pathlib import Path
from collections import Counter, defaultdict
from datetime import datetime, timedelta

# --------------------
# Regex
# --------------------
IP_RE = re.compile(r"\b(\d{1,3}\.){3}\d{1,3}\b")

# --------------------
# Parse auth.log
# --------------------
def parse_auth_log(path: str):
    events = []
    for line in Path(path).read_text(encoding="utf-8", errors="replace").splitlines():
        if not line.strip():
            continue

        status = "fail" if "failed login" in line.lower() else "success" if "accepted" in line.lower() else "other"
        ip_match = IP_RE.search(line)

        events.append({
            "timestamp": datetime.now(),   # demo 用，真實專案可解析時間
            "status": status,
            "ip": ip_match.group(0) if ip_match else None,
            "raw": line.strip()
        })
    return events

# --------------------
# B1: IP brute force
# --------------------
def build_ip_incidents(events, window=timedelta(minutes=5), threshold=5):
    incidents = []
    by_ip = defaultdict(list)

    for e in events:
        if e["status"] == "fail" and e["ip"]:
            by_ip[e["ip"]].append(e)

    for ip, evs in by_ip.items():
        if len(evs) >= threshold:
            incidents.append({
                "type": "BRUTE_FORCE",
                "severity": "CRITICAL",
                "ip": ip,
                "count": len(evs),
                "evidence": [e["raw"] for e in evs[:5]]
            })
    return incidents

# --------------------
# B2: fail -> success
# --------------------
def detect_fail_then_success(events, window=timedelta(minutes=5)):
    incidents = []
    fails = []

    for e in events:
        if e["status"] == "fail":
            fails.append(e)
        if e["status"] == "success" and fails:
            incidents.append({
                "type": "FAIL_THEN_SUCCESS",
                "severity": "HIGH",
                "fail_count": len(fails),
                "ip": e["ip"],
                "evidence": [f["raw"] for f in fails[:5]] + [e["raw"]],
            })
            fails = []

    return incidents

# --------------------
# Build report
# --------------------
def build_report(log_path="logs/auth.log"):
    events = parse_auth_log(log_path)

    ip_incidents = build_ip_incidents(events)
    b2_incidents = detect_fail_then_success(events)

    ip_counter = Counter(e["ip"] for e in events if e["ip"])

    return {
        "summary": {
            "total_events": len(events),
        },
        "top_ips": ip_counter.most_common(3),
        "incidents": ip_incidents + b2_incidents
    }

# --------------------
# Main
# --------------------
if __name__ == "__main__":
    report = build_report()
    print(json.dumps(report, ensure_ascii=False, indent=2))