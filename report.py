import json
import re
from collections import Counter
from pathlib import Path
from rules import apply_rules
from incidents import build_incidents

IP_RE = re.compile(r"\b(\d{1,3}\.){3}\d{1,3}\b")

def risk(sc: int) -> str:
    if sc >= 70: return "HIGH"
    if sc >= 40: return "MEDIUM"
    return "LOW"

def score_line(line: str) -> int:
    s = line.lower()
    sc = 0
    suspicious_keywords = ["failed", "error", "attack", "unauthorized", "invalid"]
    for kw in suspicious_keywords:
        if kw in s:
            sc += 40
    if "failed login" in s:
        sc += 40
    if IP_RE.search(line):
        sc += 10
    return min(sc, 100)

def build_report(log_path: str = "logs/auth.log") -> dict:
    log_path = Path(log_path)
    if not log_path.exists():
        raise FileNotFoundError(f"Log file not found: {log_path.resolve()}")

    counts = Counter()
    ip_counts = Counter()
    high_events = []
    events = []  # ✅ 放這裡（在函式內）

    for raw in log_path.read_text(encoding="utf-8", errors="replace").splitlines():
        if not raw.strip():
            continue

        base_score = score_line(raw)
        base_risk = risk(base_score)

        ip_match = IP_RE.search(raw)
        ip_addr = ip_match.group(0) if ip_match else None

        # ip_fail_count：同一個 IP 失敗次數（只在 failed login 時累加）
        ip_fail_count = 0
        if ip_addr and "failed login" in raw.lower():
            ip_counts[ip_addr] += 1
            ip_fail_count = ip_counts[ip_addr]

        event = {
            "score": base_score,
            "risk": base_risk,
            "raw": raw.strip(),
            "ip": ip_addr,
            "ip_fail_count": ip_fail_count,
        }

        # ✅ 套用規則引擎（rules.py）
        final_score = apply_rules(event, ip_fail_count)
        event["score"] = final_score
        event["risk"] = risk(final_score)

        events.append(event)  # ✅ 這行一定要有

        counts[event["risk"]] += 1
        if event["risk"] == "HIGH":
            high_events.append(event)

    incidents = build_incidents(high_events, fail_threshold=5)

    report = {
    "summary": {
        "total": sum(counts.values()),
        "by_risk": dict(counts),
    },
    "top_ips": ip_counts.most_common(3),
    "high_events": high_events,
    "incidents": incidents,
}
    return report


def main():
    report = build_report("logs/auth.log")
    print(json.dumps(report, ensure_ascii=False, indent=2))

if __name__ == "__main__":
    main()
