import json
from report import build_report

def main():
    report = build_report("logs/auth.log")
    with open("report.json", "w", encoding="utf-8") as f:
        json.dump(report, f, ensure_ascii=False, indent=2)
print("report.json generated")

if __name__ == "__main__":
    main()
