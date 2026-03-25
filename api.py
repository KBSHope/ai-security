from __future__ import annotations

import os
import time
from pathlib import Path
from typing import Any, Dict

from fastapi import FastAPI, File, UploadFile, HTTPException
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware

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


from cloud_analyze import parse_cloudtrail_jsonl
from unify_report import build_unified


@app.post("/analyze/unified")
async def analyze_unified(
    auth_file: UploadFile = File(...),
    cloud_file: UploadFile = File(...)
):
    from main import analyze_auth_log
    import json

    auth_path = UPLOAD_DIR / f"auth_{int(time.time())}.log"
    cloud_path = UPLOAD_DIR / f"cloud_{int(time.time())}.jsonl"

    auth_content = await auth_file.read()
    cloud_content = await cloud_file.read()

    auth_path.write_bytes(auth_content)
    cloud_path.write_bytes(cloud_content)

    auth_result = analyze_auth_log(str(auth_path))
    cloud_events = parse_cloudtrail_jsonl(str(cloud_path))

    auth_report = {
        "summary": {
            "total_events": auth_result.get("event_count", 0)
        },
        "incidents": [auth_result.get("top_incident")] if auth_result.get("top_incident") else []
    }

    cloud_report = {
        "summary": {
            "total_events": len(cloud_events)
        },
        "incidents": []
    }

    auth_report_path = UPLOAD_DIR / f"auth_report_{int(time.time())}.json"
    cloud_report_path = UPLOAD_DIR / f"cloud_report_{int(time.time())}.json"

    auth_report_path.write_text(json.dumps(auth_report, default=str), encoding="utf-8")
    cloud_report_path.write_text(json.dumps(cloud_report, default=str), encoding="utf-8")

    unified_path = build_unified(
        local_path=str(auth_report_path),
        cloud_path=str(cloud_report_path),
    )

    unified = json.loads(Path(unified_path).read_text(encoding="utf-8"))

    return JSONResponse(unified)