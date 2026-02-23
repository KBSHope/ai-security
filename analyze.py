import re
from datetime import datetime
from typing import Optional


def parse_line(line: str) -> Optional[dict]:
    ip_match = re.search(r"(\d+\.\d+\.\d+\.\d+)", line)
    if not ip_match:
        return None

    status = "fail" if ("Failed" in line or "failed" in line) else "success"

    return {
        "timestamp": datetime.now(),     # MVP：先用 now（下一步再解析真實時間）
        "ip": ip_match.group(1),
        "username": "unknown",
        "status": status,
        "raw": line.strip(),
    }


def parse_auth_log(path: str) -> list[dict]:
    events: list[dict] = []
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            ev = parse_line(line)
            if ev:
                events.append(ev)
    return events