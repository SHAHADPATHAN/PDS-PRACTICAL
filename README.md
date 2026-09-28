# SENTINEL AI // AI-Powered Log Intelligence & Cybersecurity Platform

> **An enterprise-grade, end-to-end log analytics, machine learning, and AI cybersecurity platform built on Python for Data Science (PDS Practicals 1–10).**

![Platform Visual Style: Black + Orange](https://img.shields.io/badge/Theme-Black%20%2B%20Orange-FF6A00?style=for-the-badge)
![FastAPI Backend](https://img.shields.io/badge/Backend-FastAPI-009688?style=for-the-badge&logo=fastapi)
![ML Accuracy](https://img.shields.io/badge/ML%20Accuracy-97.89%25-10B981?style=for-the-badge)
![Zero-Mocking](https://img.shields.io/badge/Data%20Integrity-100%25%20Verified-blue?style=for-the-badge)

---

## 🌟 Executive Summary

SENTINEL AI transforms raw web server access logs into an interactive cybersecurity analytics environment. It connects the complete data science and ML engineering pipeline:

```
RAW LOGS (cj.log, 2.06M rows)
       ↓
PARSING & CANONICAL SCHEMA (8 fields)
       ↓
CLEANING & PREPROCESSING
       ↓
THREAT VECTOR LABELING (SQLi, Path Traversal, Brute Force, Benign)
       ↓
BEHAVIORAL FEATURE ENGINEERING (15 features: frequency, velocity, bot heuristics)
       ↓
DATA BALANCING (Undersampling to 2,604 samples)
       ↓
DATA WRANGLING & TIME-SERIES AGGREGATIONS
       ↓
EXPLORATORY DATA ANALYSIS & INTERACTIVE VISUALIZATIONS
       ↓
MACHINE LEARNING (Random Forest: 97.89% Accuracy, 0.98 F1)
       ↓
EXPLAINABLE AI (Feature attribution & local evidence)
       ↓
AI SECURITY ANALYST (Contextually grounded threat intelligence)
       ↓
FASTAPI REST BACKEND
       ↓
BLACK + ORANGE CYBER-ANALYTICS WEB APPLICATION
```

---

## 🚀 Quick Start Guide

### 1. Launch Platform
From the project root:

```powershell
cd "d:\PDS PRACTICAL\platform\backend"
python -m uvicorn app.main:app --host 127.0.0.1 --port 8000
```

### 2. Open Platform in Browser
* **Web Application UI:** [http://127.0.0.1:8000/](http://127.0.0.1:8000/)
* **Interactive API Documentation:** [http://127.0.0.1:8000/api/docs](http://127.0.0.1:8000/api/docs)

---

## 🛡️ Core Capabilities

| Module | Features |
| :--- | :--- |
| **Executive Dashboard** | Real KPI cards (2.06M total logs, 16.68K unique IPs, 2,545 attacks), interactive canvas traffic chart, threat vector distribution, and top threat actors table. |
| **Pipeline Control Center** | Multi-stage orchestration stepper covering 9 validated steps with live duration tracking, record counts, and streaming log console. |
| **Log Explorer** | Server-side paginated log search engine with multi-criteria filtering by IP, attack category, bot flag, and client tool type. Includes deep modal inspector. |
| **Machine Learning Hub** | Real Random Forest evaluation: 97.89% Accuracy, 0.99 attack recall, confusion matrix, and an **interactive live predictor** with instant explainability evidence. |
| **AI Security Analyst** | Interactive SOC analyst grounded directly in actual dataset telemetry. Answers complex queries and provides zero-hallucination analysis. |
| **Incident Workspace** | Automated incident triage generator providing copyable Linux `iptables` rules and ModSecurity WAF directives for malicious IPs. |
| **System Diagnostics** | Real-time service health check and direct CSV exports for balanced datasets, model predictions, and summary reports. |

---

## 📁 Repository Structure

```
D:\PDS PRACTICAL\
├── Logs\                               [Raw cj.log (226 MB, 2.06M records)]
├── Practical-1 to Practical-10         [100% Preserved Academic Practicals]
├── platform\                           [Enterprise Platform Implementation]
│   ├── backend\                        [FastAPI Application, Services, Artifacts]
│   │   ├── app\                        [Routers, Orchestrator, Services, Models]
│   │   ├── artifacts\                  [Saved model.joblib, metadata]
│   │   └── tests\                      [Automated integration test suite]
│   └── frontend\                       [Black + Orange Cyber-Analytics Web SPA]
│       ├── css\style.css               [Custom design tokens & responsive styles]
│       ├── js\api.js                   [FastAPI client interface]
│       ├── js\app.js                   [Reactive SPA state & chart renderer]
│       └── index.html                  [Semantic single-page application markup]
├── PROJECT_AUDIT.md                    [Phase A Complete Project Audit]
├── PIPELINE_VALIDATION_REPORT.md       [Phase B Stage-by-Stage Verification]
├── DATA_LINEAGE.md                     [Metric-to-Source Traceability Spec]
├── ARCHITECTURE.md                     [System Architecture & Data Flow]
├── API_DOCUMENTATION.md                [REST API Reference & Schemas]
├── AI_ARCHITECTURE.md                  [ML & Explainable AI Specifications]
├── MODEL_DOCUMENTATION.md              [Model Card & Evaluation Metrics]
├── TESTING.md                          [Automated Regression Test Suite Guide]
└── DEPLOYMENT.md                       [Installation & Running Instructions]
```

---

## 🧪 Testing & Validation

Run the automated integration test suite:

```powershell
python "d:\PDS PRACTICAL\platform\backend\tests\test_platform.py"
```

All 8 automated test suites pass with 100% success.
