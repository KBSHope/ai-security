def apply_rules(event: dict, ip_fail_count: int) -> int:
    score = int(event.get("score", 0))

    if ip_fail_count >= 5:
        score += 30
    elif ip_fail_count >= 3:
        score += 15

    if event.get("risk") == "HIGH":
        score += 10

    return min(score, 100)
