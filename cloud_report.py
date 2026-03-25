# cloud_report.py
import json
from collections import Counter, defaultdict
from datetime import timedelta
from pathlib import Path

from cloud_analyze import parse_cloudtrail_jsonl


def detect_root_usage(events: list[dict]) -> list[dict]:
    """
    Detect usage of root account (very suspicious).
    """
    incidents = []
    for ev in events:
        uname = (ev.get("username") or "").lower()
        # root signals: contains "root" or arn ends with ":root"
        if "root" in uname or uname.endswith(":root"):
            incidents.append(
                {
                    "type": "ROOT_USAGE",
                    "severity": "CRITICAL",
                    "username": ev.get("username", "unknown"),
                    "ip": ev.get("ip", ""),
                    "time": ev.get("timestamp"),
                    "evidence": [ev.get("raw", "")],
                }
            )
    return incidents


def detect_privilege_escalation(events: list[dict]) -> list[dict]:
    """
    Detect IAM privilege escalation related API calls.
    """
    suspicious_apis = {
        "AttachUserPolicy",
        "AttachRolePolicy",
        "PutUserPolicy",
        "PutRolePolicy",
        "CreateAccessKey",
        "AddUserToGroup",
        "UpdateAssumeRolePolicy",
    }

    incidents = []

    for ev in events:
        event_name = ev.get("event_name")
        if event_name in suspicious_apis:
            incidents.append(
                {
                    "type": "IAM_PRIV_ESCALATION",
                    "severity": "CRITICAL",
                    "username": ev.get("username", "unknown"),
                    "ip": ev.get("ip", ""),
                    "event_name": event_name,
                    "time": ev.get("timestamp"),
                    "evidence": [ev.get("raw", "")],
                }
            )

    return incidents


def detect_api_spike(
    events: list[dict],
    window: timedelta = timedelta(minutes=5),
    threshold: int = 20,
) -> list[dict]:
    """
    Detect API call spike per IP in a sliding window.
    (Simple heuristic version)
    """
    # group by ip
    by_ip = defaultdict(list)
    for ev in events:
        ip = ev.get("ip") or ""
        ts = ev.get("timestamp")
        if not ip or not ts:
            continue
        by_ip[ip].append(ev)

    incidents = []
    for ip, evs in by_ip.items():
        evs.sort(key=lambda e: e["timestamp"])
        start = 0
        for end in range(len(evs)):
            while evs[end]["timestamp"] - evs[start]["timestamp"] > window:
                start += 1
            count = end - start + 1
            if count >= threshold:
                window_events = evs[start : end + 1]
                incidents.append(
                    {
                        "type": "API_SPIKE",
                        "severity": "HIGH",
                        "ip": ip,
                        "count": count,
                        "window": str(window),
                        "start_time": window_events[0]["timestamp"],
                        "end_time": window_events[-1]["timestamp"],
                        "top_event_names": Counter(
                            (e.get("event_name") or "unknown") for e in window_events
                        ).most_common(5),
                        "evidence": [e.get("raw", "") for e in window_events[:8]],
                    }
                )
                break  # one incident per ip is enough
    return incidents


def build_cloud_report(log_path: str = "cloud_logs/cloudtrail.jsonl") -> dict:
    events = parse_cloudtrail_jsonl(log_path)

    # detectors
    root_incidents = detect_root_usage(events)
    spike_incidents = detect_api_spike(events)
    priv_incidents = detect_privilege_escalation(events)

    # merge incidents
    incidents = []
    incidents.extend(root_incidents)
    incidents.extend(spike_incidents)
    incidents.extend(priv_incidents)

    # summary
    total = len(events)
    by_risk = Counter()

    for inc in incidents:
        by_risk[inc.get("severity", "LOW")] += 1

    top_ips = Counter(
        e.get("ip") for e in events if e.get("ip")
    ).most_common(5)

    report = {
        "summary": {
            "total_events": total,
            "by_risk": dict(by_risk),
        },
        "top_ips": top_ips,
        "incidents": incidents,
    }

    return report


def main():
    out = Path("cloud_report.json")
    report = build_cloud_report("cloud_logs/cloudtrail.jsonl")
    print("DEBUG total events:", report["summary"]["total_events"])
    out.write_text(
        json.dumps(report, ensure_ascii=False, indent=2, default=str),
        encoding="utf-8"
    )
    print("[cloud_report] generated:", out.resolve())


if __name__ == "__main__":
    main()