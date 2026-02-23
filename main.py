from datetime import timedelta
from analyze import parse_auth_log
from incidents import (
    build_account_based_incidents,
    build_correlated_incidents,
    detect_fail_then_success,
    detect_ip_multi_account_attack,
    build_risk_enriched_incidents,
)

auth_log_path = "logs/auth.log"
auth_events = parse_auth_log(auth_log_path)
print(f"[main] parsed auth events: {len(auth_events)}")

account_incidents = build_account_based_incidents(
    auth_events,
    window=timedelta(minutes=5),
    fail_threshold=5,
    ip_threshold=3,
)
print(f"[account] incidents found: {len(account_incidents)}")

correlated = build_correlated_incidents(
    auth_events,
    window=timedelta(minutes=5),
    fail_threshold=5,
)
print(f"[correlation] incidents found: {len(correlated)}")

b2_incidents = detect_fail_then_success(
    auth_events=auth_events,
    window=timedelta(minutes=5),
)
print(f"[B2] incidents found: {len(b2_incidents)}")

# ✅ B3 要在 enriched 之前
b3_incidents = detect_ip_multi_account_attack(
    auth_events=auth_events,
    window=timedelta(minutes=5),
    user_threshold=3,
)
print(f"[B3] incidents found: {len(b3_incidents)}")

# ✅ enriched 最後做
enriched = build_risk_enriched_incidents(
    auth_events=auth_events,
    ip_incidents=correlated,
    account_incidents=account_incidents,
    b2_incidents=b2_incidents,
)

print(f"[enriched] incidents found: {len(enriched)}")
if enriched:
    print("[enriched] top incident:")
    print(enriched[0])