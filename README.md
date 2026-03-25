# AI Security SaaS MVP

AI Security SaaS MVP is a security log analysis project built with **Python, FastAPI, React, and Vite**.

It is designed as an early-stage SaaS prototype that can analyze local authentication logs and CloudTrail-style logs, then generate structured security findings, incidents, and downloadable reports.

This project is positioned as a **founder-style MVP** for an AI-driven cybersecurity product.

---

## Product Vision

Small and mid-sized teams often do not have a full SOC, SIEM, or dedicated security analyst.

This project explores how an AI-assisted SaaS product can help users:

- upload security logs
- detect suspicious behaviors
- unify multi-source events
- generate readable incident summaries
- export security reports quickly

The long-term vision is to turn this into a lightweight **AI Security Analysis Platform** for teams that want faster visibility without enterprise-grade complexity.

---

## Problem It Solves

Security data is often scattered across different sources such as:

- Linux auth logs
- cloud activity logs
- incident notes
- exported JSON results

This MVP brings those signals into one unified workflow.

---

## Core Features

### 1. Local Auth Log Analysis

Analyze authentication-related logs and detect suspicious login activity.

Examples:

- failed login attempts
- repeated login failures
- invalid access patterns
- suspicious IP-related behavior

### 2. CloudTrail-style Log Analysis

Support cloud event analysis through CloudTrail-like log structures.

Examples:

- suspicious API activity
- abnormal cloud events
- identity-based activity review

### 3. Unified Threat Analysis

Combine multiple sources into one analysis flow.

Examples:

- auth log + cloud log review
- incident aggregation
- single report output for multiple event streams

### 4. Risk Scoring

Assign a risk level to security findings.

Typical levels:

- LOW
- MEDIUM
- HIGH
- CRITICAL

### 5. Report Generation

Generate structured output for downstream usage.

Supported directions:

- JSON report output
- incident-style summaries
- downloadable report workflow

### 6. Frontend Dashboard

A React-based dashboard is included for future SaaS usage.

Dashboard includes:

- analysis result display
- incident visibility
- timeline view
- report download entry
- reset flow
- smooth scroll to result area

---

## Demo Workflow

A typical usage flow looks like this:

1. Prepare security log files
2. Run backend analysis
3. Parse and score suspicious events
4. Generate structured security report
5. Display results in frontend dashboard
6. Export report for review or sharing

---

## Demo Files

This project includes sample files for local demo testing:

- `samples/auth.log`
- `samples/cloudtrail.jsonl`

You can use these files to test the unified analysis flow in the dashboard.

---

## Quick Demo

### 1. Start backend

```bash
py -m uvicorn api:app --reload