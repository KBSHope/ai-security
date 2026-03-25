import json
from pathlib import Path
from collections import Counter

DEFAULT_LOCAL = "report.json"
DEFAULT_CLOUD = "cloud_report.json"
OUT_FILE = "unified_report.json"


def _load_json(path: str) -> dict:
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"Missing file: {p.resolve()}")
    return json.loads(p.read_text(encoding="utf-8"))


def _norm_top_ips(top_ips):
    """
    Accept formats:
    - [["10.0.0.5", 6], ["1.2.3.4", 3]]
    - ["10.0.0.5", "1.2.3.4"]  (rare)
    Return list[tuple[str,int]]
    """
    if not top_ips:
        return []
    out = []
    for item in top_ips:
        if isinstance(item, (list, tuple)) and len(item) == 2:
            ip, cnt = item
            try:
                out.append((str(ip), int(cnt)))
            except Exception:
                continue
        elif isinstance(item, str):
            out.append((item, 1))
    return out


def _extract_total(summary: dict) -> int:
    # support both:
    # { "total_events": 9 } or { "total": 9 } or { "total": 9 } inside summary
    for k in ("total_events", "total"):
        if k in summary and isinstance(summary[k], int):
            return summary[k]
    return 0


def _extract_by_risk(summary: dict) -> dict:
    by_risk = summary.get("by_risk", {})
    return by_risk if isinstance(by_risk, dict) else {}


def _infer_risk_from_incident(inc: dict) -> str:
    # unify possible fields: severity / risk
    for k in ("severity", "risk"):
        v = inc.get(k)
        if isinstance(v, str) and v:
            return v.upper()
    return "UNKNOWN"


def _annotate_source(incidents: list, source: str) -> list:
    out = []
    for inc in incidents or []:
        if not isinstance(inc, dict):
            continue
        x = dict(inc)
        x["source"] = source
        # unify risk field (optional)
        x.setdefault("risk", _infer_risk_from_incident(x))
        out.append(x)
    return out


def build_unified(local_path=DEFAULT_LOCAL, cloud_path=DEFAULT_CLOUD, out_path=OUT_FILE):
    local = _load_json(local_path)
    cloud = _load_json(cloud_path)

    # totals
    local_total = _extract_total(local.get("summary", {}))
    cloud_total = _extract_total(cloud.get("summary", {}))
    total_events = local_total + cloud_total

    # by_risk
    risk_counter = Counter()
    risk_counter.update({k.upper(): int(v) for k, v in _extract_by_risk(local.get("summary", {})).items()})
    risk_counter.update({k.upper(): int(v) for k, v in _extract_by_risk(cloud.get("summary", {})).items()})

    # top_ips
    ip_counter = Counter()
    ip_counter.update(dict(_norm_top_ips(local.get("top_ips"))))
    ip_counter.update(dict(_norm_top_ips(cloud.get("top_ips"))))
    top_ips = ip_counter.most_common(5)

    # incidents
    local_incs = _annotate_source(local.get("incidents", []), "local")
    cloud_incs = _annotate_source(cloud.get("incidents", []), "cloud")
    incidents = local_incs + cloud_incs

    # simple ordering: CRITICAL/HIGH/MEDIUM/LOW/UNKNOWN then by count if present
    severity_rank = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "UNKNOWN": 9}
    def _sort_key(inc: dict):
        r = (inc.get("severity") or inc.get("risk") or "UNKNOWN").upper()
        rank = severity_rank.get(r, 9)
        cnt = inc.get("count") or inc.get("fail_count") or inc.get("user_count") or 0
        try:
            cnt = int(cnt)
        except Exception:
            cnt = 0
        return (rank, -cnt)

    incidents.sort(key=_sort_key)

    unified = {
        "summary": {
            "total_events": total_events,
            "by_risk": dict(risk_counter),
        },
        "top_ips": top_ips,
        "incidents": incidents,
        "sources": {
            "local_report": str(Path(local_path).resolve()),
            "cloud_report": str(Path(cloud_path).resolve()),
        },
    }

    Path(out_path).write_text(json.dumps(unified, ensure_ascii=False, indent=2), encoding="utf-8")
    return out_path


if __name__ == "__main__":
    out = build_unified()
    print(f"[unify] generated: {Path(out).resolve()}")