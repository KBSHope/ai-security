# AI Security SaaS MVP

一個可上傳 **Linux auth log** 與 **CloudTrail log**，並進行 **Unified Threat Analysis** 的 AI Security SaaS MVP。

目前已完成：

- FastAPI 後端 API
- React + Vite 前端 Dashboard
- Unified Analysis 串接
- Incident 顯示
- Timeline 顯示
- JSON 報告下載
- HTML 報告下載

---

## Features

### 1. Unified Threat Analysis
可同時上傳：

- `auth.log`
- `cloudtrail.jsonl`

系統會將兩種來源的資料做整合分析，輸出：

- incidents
- risk score
- critical incidents
- top IP
- timeline

### 2. Web Dashboard
前端 Dashboard 可顯示：

- Executive Summary
- Highest Risk Score
- Critical Incidents
- Top IP
- Incidents 卡片
- Timeline 表格

### 3. Report Export
支援下載：

- `unified_report.json`
- `unified_report.html`

---

## Project Structure

```bash
ai-security/
├─ api.py
├─ main.py
├─ analyze.py
├─ analyze_ai.py
├─ cloud_analyze.py
├─ unify_report.py
├─ incidents.py
├─ rules.py
├─ logs/
│  └─ auth.log
├─ cloud_logs/
│  └─ cloudtrail.jsonl
├─ uploads/
├─ dashboard/
│  ├─ src/
│  │  └─ App.jsx
│  ├─ package.json
│  └─ vite.config.js
└─ README.md



## Tech Stack

### Backend
- FastAPI
- Python

### Frontend
- React
- Vite

### Analysis
- Auth log analysis
- CloudTrail analysis
- Unified incident reporting

---

## How to Run

### 1. Start Backend

在專案根目錄執行：

```bash
py -m uvicorn api:app --reload
