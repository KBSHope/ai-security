# AI Security – Suspicious Login Detection

This project analyzes authentication logs and detects suspicious login behavior,
aggregating high-risk events into security incidents.

## Features

- Parse auth logs
- Score events based on risk rules
- Track failed login attempts per IP
- Aggregate high-risk events into incidents
- Export structured JSON report

## Project Structure

```text
ai-security/
├── analyze.py
├── analyze_ai.py
├── export_report.py
├── report.py
├── incidents.py
├── rules.py
├── logs/
│   └── auth.log (ignored)

## Sample Output

```md
## Incident Detection Logic

High-risk login events are aggregated into security incidents based on source IP.

- Failed login attempts are tracked per IP address
- If the maximum failure count for an IP reaches a threshold (default: `5`)
  - The incident is classified as `BRUTE_FORCE`
  - Severity is marked as `CRITICAL`
- Otherwise, it is labeled as `SUSPICIOUS_ACTIVITY`

This approach simulates real-world SOC workflows by correlating raw events into actionable security incidents.
After running `python report.py`, the system generates a structured JSON report:

```json
{
  "summary": {
    "total": 9,
    "by_risk": {
      "HIGH": 8,
      "LOW": 1
    }
  },
  "top_ips": [
    ["10.0.0.5", 6],
    ["192.168.1.10", 1],
    ["8.8.8.8", 1]
  ],
  "incidents": [
    {
      "type": "BRUTE_FORCE",
      "severity": "CRITICAL",
      "ip": "10.0.0.5",
      "count": 6,
      "max_ip_fail_count": 6,
      "evidence": [
        "failed login from 10.0.0.5"
      ]
    }
  ]
}
## Demo

You can modify `logs/auth.log` to simulate different attack scenarios
(e.g. brute force, single failed login, mixed IP sources)
and observe how incidents are generated.

## How to Run

```bash
python report.py

