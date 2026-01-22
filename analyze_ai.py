import json
import re
from pathlib import Path

SUSPICIOUS_KEYWORDS = [
    "failed",
    "error",
    "attack",
    "unauthorized",
    "invalid password",
    "denied",
]

IP_RE = re.compile(r"\b(\d{1,3}\.){3}\d{1,3}\b")

def risk_score(line: str) -> int:
    s = line.lower()
    score = 0
    for kw in SUSPICIOUS_KEYWORDS:
        if kw in s:
            score += 40
    if "failed login" in s:
        score += 40
    if IP_RE.search(line):
        score += 10
    return min(score, 100)

def classify(score: int) -> str:
    if score >= 70:
        return "HIGH"
    if score >= 40:
        return "MEDIUM"
    return "LOW"

def analyze_log_local(line: str) -> dict:
    score = risk_score(line)
    risk = classify(score)
    reason = "Matched local heuristics/keywords." if score > 0 else "No suspicious signals detected."
    return {
        "risk": risk,
        "score": score,
        "reason": reason,
        "raw": line.strip(),
    }

def main():
    log_path = Path("logs/auth.log")
    if not log_path.exists():
        raise FileNotFoundError(f"Log file not found: {log_path.resolve()}")

    for line in log_path.read_text(encoding="utf-8", errors="replace").splitlines():
        if not line.strip():
            continue
        result = analyze_log_local(line)
        print(json.dumps(result, ensure_ascii=False))

if __name__ == "__main__":
    main()
