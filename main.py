from datetime import timedelta
from collections import Counter

from analyze import parse_auth_log
from incidents import (
    build_account_based_incidents,
    build_correlated_incidents,
    detect_fail_then_success,
    detect_ip_multi_account_attack,
    build_risk_enriched_incidents,
)


def _normalize_risk(value) -> str:
    if not value:
        return "UNKNOWN"
    return str(value).upper()


def _count_risks(incidents: list[dict]) -> dict:
    counter = Counter()
    for inc in incidents or []:
        risk = _normalize_risk(inc.get("risk") or inc.get("severity"))
        counter[risk] += 1
    return dict(counter)


def _count_top_ips_from_incidents(incidents: list[dict], limit: int = 5) -> list[list]:
    counter = Counter()
    for inc in incidents or []:
        ip = inc.get("ip")
        if ip:
            counter[str(ip)] += 1
    return [[ip, count] for ip, count in counter.most_common(limit)]


def analyze_auth_log(auth_log_path: str):
    auth_events = parse_auth_log(auth_log_path)

    account_incidents = build_account_based_incidents(
        auth_events,
        window=timedelta(minutes=5),
        fail_threshold=5,
        ip_threshold=3,
    )

    correlated = build_correlated_incidents(
        auth_events,
        window=timedelta(minutes=5),
        fail_threshold=5,
    )

    b2_incidents = detect_fail_then_success(
        auth_events=auth_events,
        window=timedelta(minutes=5),
    )

    b3_incidents = detect_ip_multi_account_attack(
        auth_events=auth_events,
        window=timedelta(minutes=5),
        user_threshold=3,
    )

    enriched = build_risk_enriched_incidents(
        auth_events=auth_events,
        ip_incidents=correlated,
        account_incidents=account_incidents,
        b2_incidents=b2_incidents,
    )

    by_risk = _count_risks(enriched)
    top_ips = _count_top_ips_from_incidents(enriched, limit=5)

    return {
        "event_count": len(auth_events),
        "incident_count": len(enriched),
        "top_incident": enriched[0] if enriched else None,
        "incidents": enriched,
        "by_risk": by_risk,
        "top_ips": top_ips,
    }


if __name__ == "__main__":
    result = analyze_auth_log("logs/auth.log")
    print(result)