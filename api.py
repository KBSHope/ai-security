from __future__ import annotations

import json
import os
import time
from collections import Counter
from pathlib import Path
from typing import Any, Dict

from fastapi import FastAPI, File, UploadFile, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from cloud_analyze import parse_cloudtrail_jsonl
from unify_report import build_unified

app = FastAPI(title="AI-Security SaaS API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://127.0.0.1:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

BASE_DIR = Path(__file__).resolve().parent
UPLOAD_DIR = BASE_DIR / "uploads"
UPLOAD_DIR.mkdir(exist_ok=True)


def _safe_name(name: str) -> str:
    name = os.path.basename(name).replace("..", "")
    return name or "upload.log"


def _json_safe(obj):
    import datetime as dt

    if isinstance(obj, dict):
        return {k: _json_safe(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_json_safe(v) for v in obj]
    if isinstance(obj, (dt.datetime, dt.date, dt.time, dt.timedelta)):
        return obj.isoformat() if hasattr(obj, "isoformat") else str(obj)
    return obj


def _try_run_analyzer(saved_path: Path) -> Dict[str, Any]:
    try:
        from main import analyze_auth_log

        result = analyze_auth_log(str(saved_path))
        if isinstance(result, dict):
            return _json_safe(result)
        return {"result": _json_safe(result)}

    except Exception as e:
        return {"status": "analyzer_crashed", "error": f"{type(e).__name__}: {e}"}


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


def _count_top_ips_from_events(events: list[dict], limit: int = 5) -> list[list]:
    counter = Counter()
    for ev in events or []:
        ip = ev.get("ip")
        if ip:
            counter[str(ip)] += 1
    return [[ip, count] for ip, count in counter.most_common(limit)]


def _build_cloud_incidents(cloud_events: list[dict]) -> list[dict]:
    """
    Build simple cloud incidents from failed CloudTrail events.
    This is a lightweight MVP version.
    """
    grouped = {}

    for ev in cloud_events:
        if ev.get("status") != "fail":
            continue

        key = (
            ev.get("ip") or "",
            ev.get("username") or "unknown",
            ev.get("event_name") or "unknown_event",
        )

        if key not in grouped:
            grouped[key] = {
                "type": "CLOUD_FAIL_EVENT",
                "title": f"Cloud failure: {ev.get('event_name') or 'unknown_event'}",
                "ip": ev.get("ip") or "",
                "username": ev.get("username") or "unknown",
                "event_name": ev.get("event_name") or "unknown_event",
                "event_source": ev.get("event_source") or "",
                "count": 0,
                "risk": "MEDIUM",
                "severity": "MEDIUM",
                "source": "cloud",
                "first_seen": ev.get("timestamp"),
                "last_seen": ev.get("timestamp"),
            }

        grouped[key]["count"] += 1

        ts = ev.get("timestamp")
        if ts:
            if not grouped[key]["first_seen"] or ts < grouped[key]["first_seen"]:
                grouped[key]["first_seen"] = ts
            if not grouped[key]["last_seen"] or ts > grouped[key]["last_seen"]:
                grouped[key]["last_seen"] = ts

    incidents = list(grouped.values())

    for inc in incidents:
        cnt = int(inc.get("count", 0))
        if cnt >= 5:
            inc["risk"] = "HIGH"
            inc["severity"] = "HIGH"
        elif cnt >= 2:
            inc["risk"] = "MEDIUM"
            inc["severity"] = "MEDIUM"
        else:
            inc["risk"] = "LOW"
            inc["severity"] = "LOW"

    incidents.sort(key=lambda x: (-int(x.get("count", 0)), x.get("title", "")))
    return _json_safe(incidents)


@app.get("/")
def root():
    return {"status": "SaaS API running 🚀", "upload_dir": str(UPLOAD_DIR)}


@app.post("/analyze/upload")
async def analyze_upload(file: UploadFile = File(...)):
    if not file.filename:
        raise HTTPException(status_code=400, detail="Missing filename")

    content = await file.read()
    if not content:
        raise HTTPException(status_code=400, detail="Empty file")

    safe = _safe_name(file.filename)
    saved_path = UPLOAD_DIR / f"{int(time.time())}_{safe}"
    saved_path.write_bytes(content)

    analysis = _try_run_analyzer(saved_path)

    return JSONResponse(
        {
            "ok": True,
            "filename": file.filename,
            "saved_as": saved_path.name,
            "bytes": len(content),
            "analysis": analysis,
        }
    )


@app.post("/analyze/unified")
async def analyze_unified(
    auth_file: UploadFile = File(...),
    cloud_file: UploadFile = File(...),
):
    from main import analyze_auth_log

    auth_path = UPLOAD_DIR / f"auth_{int(time.time())}.log"
    cloud_path = UPLOAD_DIR / f"cloud_{int(time.time())}.jsonl"

    auth_content = await auth_file.read()
    cloud_content = await cloud_file.read()

    if not auth_content:
        raise HTTPException(status_code=400, detail="auth_file is empty")
    if not cloud_content:
        raise HTTPException(status_code=400, detail="cloud_file is empty")

    auth_path.write_bytes(auth_content)
    cloud_path.write_bytes(cloud_content)

    auth_result = analyze_auth_log(str(auth_path))
    cloud_events = parse_cloudtrail_jsonl(str(cloud_path))
    cloud_incidents = _build_cloud_incidents(cloud_events)

    auth_report = {
        "summary": {
            "total_events": auth_result.get("event_count", 0),
            "by_risk": auth_result.get("by_risk", _count_risks(auth_result.get("incidents", []))),
        },
        "incidents": auth_result.get("incidents", []),
        "top_ips": auth_result.get("top_ips", _count_top_ips_from_incidents(auth_result.get("incidents", []))),
    }

    cloud_report = {
        "summary": {
            "total_events": len(cloud_events),
            "by_risk": _count_risks(cloud_incidents),
        },
        "incidents": cloud_incidents,
        "top_ips": _count_top_ips_from_events(cloud_events),
    }

    auth_report_path = UPLOAD_DIR / f"auth_report_{int(time.time())}.json"
    cloud_report_path = UPLOAD_DIR / f"cloud_report_{int(time.time())}.json"

    auth_report_path.write_text(
        json.dumps(_json_safe(auth_report), ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    cloud_report_path.write_text(
        json.dumps(_json_safe(cloud_report), ensure_ascii=False, indent=2),
        encoding="utf-8",
    )

    unified_path = build_unified(
        local_path=str(auth_report_path),
        cloud_path=str(cloud_report_path),
    )

    unified = json.loads(Path(unified_path).read_text(encoding="utf-8"))
    return JSONResponse(unified)