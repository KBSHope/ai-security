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


## How to Run

```bash
python report.py

