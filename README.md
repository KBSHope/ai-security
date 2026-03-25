# AI Security SaaS

AI Security SaaS 是一個以 **Python + FastAPI + React** 建立的安全日誌分析專案。  
它可以分析本機 auth log、CloudTrail 類型事件，並產出風險結果與報告，作為未來 SaaS 化資安產品的 MVP 基礎。

---

## Features

- Analyze local auth logs
- Detect suspicious login behavior
- Score security events by risk level
- Generate JSON security reports
- Support CloudTrail-style log analysis
- Unified analysis structure for multi-source logs
- Frontend dashboard built with React + Vite
- FastAPI backend for future SaaS expansion

---

## Tech Stack

### Backend
- Python
- FastAPI

### Frontend
- React
- Vite
- JavaScript
- CSS

### Other
- Git
- GitHub
- JSON-based report output

---

## Project Structure

```bash
ai-security/
├─ api.py
├─ main.py
├─ analyze.py
├─ incidents.py
├─ rules.py
├─ report.py
├─ export_report.py
├─ cloud_analyze.py
├─ cloud_report.py
├─ unify_report.py
├─ README.md
├─ .gitignore
├─ dashboard/
│  ├─ package.json
│  ├─ package-lock.json
│  ├─ vite.config.js
│  ├─ index.html
│  ├─ src/
│  │  ├─ App.jsx
│  │  ├─ App.css
│  │  ├─ main.jsx
│  │  └─ index.css
│  └─ public/
├─ logs/
├─ cloud_logs/
└─ uploads/