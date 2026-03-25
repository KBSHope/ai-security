# cloud_analyze.py
import json
from datetime import datetime, timezone
from pathlib import Path


def _parse_ts(s: str) -> datetime | None:
    """
    CloudTrail eventTime example: "2026-02-23T08:12:34Z"
    """
    if not s:
        return None
    try:
        if s.endswith("Z"):
            # UTC
            return datetime.fromisoformat(s.replace("Z", "+00:00"))
        return datetime.fromisoformat(s)
    except Exception:
        return None


def parse_cloudtrail_jsonl(path: str) -> list[dict]:
    """
    Read CloudTrail logs in JSONL format (one JSON object per line).
    Return normalized events list.

    Normalized event fields:
      - timestamp: datetime
      - source: "cloudtrail"
      - event_name: str
      - event_source: str
      - username: str
      - ip: str
      - status: "success" | "fail"
      - raw: str (original line)
      - extra: dict (optional)
    """
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"cloudtrail log not found: {p.resolve()}")

    events: list[dict] = []
    for line in p.read_text(encoding="utf-8", errors="replace").splitlines():
        raw = line.strip()
        if not raw:
            continue

        try:
            obj = json.loads(raw)
        except Exception as e:
            print("PARSE ERROR:", e)
            print("BAD LINE:", line)

        ts = _parse_ts(obj.get("eventTime")) or datetime.now(timezone.utc)

        # identity
        ui = obj.get("userIdentity") or {}
        username = (
            ui.get("userName")
            or ui.get("principalId")
            or ui.get("arn")
            or "unknown"
        )

        ip = obj.get("sourceIPAddress") or obj.get("additionalEventData", {}).get("sourceIPAddress") or ""

        event_name = obj.get("eventName") or ""
        event_source = obj.get("eventSource") or ""

        # determine success/fail
        # CloudTrail usually: presence of "errorCode"/"errorMessage" => fail
        status = "fail" if (obj.get("errorCode") or obj.get("errorMessage")) else "success"

        events.append(
            {
                "timestamp": ts,
                "source": "cloudtrail",
                "event_name": event_name,
                "event_source": event_source,
                "username": username,
                "ip": ip,
                "status": status,
                "raw": raw,
                "extra": {
                    "awsRegion": obj.get("awsRegion"),
                    "eventType": obj.get("eventType"),
                },
            }
        )

    return events