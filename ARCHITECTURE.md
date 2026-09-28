# SYSTEM ARCHITECTURE SPECIFICATION

**Platform:** SENTINEL AI - Log Intelligence & Cybersecurity Platform  
**Architecture Style:** Decoupled High-Performance Analytical Engine (FastAPI + Modern Web SPA)  
**Root Workspace:** `D:\PDS PRACTICAL`

---

## 1. Architectural Philosophy

1. **Academic Preservation:** Retains all 10 PDS academic practicals (`Practical-1` to `Practical-10`) in their original directories as verified academic milestones.
2. **Unified Enterprise Engine:** Integrates all practical steps into a production-grade platform located in `platform/`.
3. **Strict Zero-Mocking Architecture:** No static or placeholder data in production paths. All KPIs, charts, predictions, and AI responses derive from real backend computations.
4. **Performance & Memory Optimization:** Utilizes stratified balanced subsets (2,604 rows) for instant sub-second dashboard and log exploration, while maintaining full pipeline processing capacity for 2.06 million rows.

---

## 2. Component Diagram

```
+-----------------------------------------------------------------------------------+
| FRONTEND LAYER: Black + Orange Cyber-Analytics SPA                                |
| Path: platform/frontend/                                                          |
| Technologies: Semantic HTML5, Vanilla CSS Design System, Reactive JavaScript      |
| Design Tokens: Dark (#050505), Cards (#111111), Borders (#242424), Glow (#FF6A00) |
+-----------------------------------------------------------------------------------+
                                         |
                                         | HTTP / JSON REST APIs
                                         v
+-----------------------------------------------------------------------------------+
| BACKEND APPLICATION LAYER: FastAPI Async Server                                  |
| Path: platform/backend/app/                                                       |
|                                                                                   |
|  +--------------------+  +--------------------+  +--------------------+           |
|  | health.py          |  | pipeline.py        |  | logs.py            |           |
|  +--------------------+  +--------------------+  +--------------------+           |
|  +--------------------+  +--------------------+  +--------------------+           |
|  | analytics.py       |  | predictions.py     |  | ai.py              |           |
|  +--------------------+  +--------------------+  +--------------------+           |
|  +--------------------+                                                           |
|  | system.py          |                                                           |
|  +--------------------+                                                           |
+-----------------------------------------------------------------------------------+
                                         |
                                         v
+-----------------------------------------------------------------------------------+
| CORE SERVICES & ORCHESTRATION                                                     |
|                                                                                   |
|  [PipelineOrchestrator]     --> Manages multi-stage background execution          |
|  [AnalyticsService]         --> Pre-computed KPI and time-series aggregations     |
|  [DataService]              --> High-speed filtered & paginated log search        |
|  [MLService]                --> Random Forest Classifier & explainable evidence   |
|  [AIService]                --> Grounded LLM reasoning & deterministic heuristics |
+-----------------------------------------------------------------------------------+
                                         |
                                         v
+-----------------------------------------------------------------------------------+
| PERSISTENCE & ARTIFACTS LAYER                                                     |
|                                                                                   |
|  - model.joblib             --> Serialized Random Forest Classifier (97.89% Acc)  |
|  - model_metadata.json      --> Evaluation metrics, confusion matrix, importances |
|  - balanced_dataset.csv     --> 2,604 rows (50% benign, 50% attack)               |
|  - processed_logs.csv       --> 2,060,520 records with 15 engineered features     |
|  - cj.log                   --> Raw 226MB source log repository                   |
+-----------------------------------------------------------------------------------+
```

---

## 3. Security Considerations
- **CORS Restricted Configuration:** Whitelisted origin handling for production deployments.
- **Input Validation:** Strict Pydantic models validate all incoming requests.
- **Header Sanitization:** Defensive escaping prevents XSS and log injection attacks.
- **Zero API Secrets in Client:** GenAI keys reside exclusively in backend environment variables.
