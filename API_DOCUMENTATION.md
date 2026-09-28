# REST API SPECIFICATION & REFERENCE

**Platform:** SENTINEL AI - Log Intelligence Platform  
**Base URL:** `http://127.0.0.1:8000/api`  
**Interactive Docs (Swagger UI):** `http://127.0.0.1:8000/api/docs`  
**Alternative Docs (ReDoc):** `http://127.0.0.1:8000/api/redoc`

---

## 1. System & Health

### `GET /api/health`
Returns system status, active version, dataset existence, and loaded model status.
- **Response:**
  ```json
  {
    "status": "healthy",
    "version": "1.0.0",
    "raw_log_found": true,
    "model_loaded": true,
    "total_records": 2060520,
    "environment": "Production (Local)"
  }
  ```

---

## 2. Telemetry & Analytics

### `GET /api/analytics/overview`
Retrieves aggregated executive dashboard data including KPIs, time-series, attack categories, and top offending IPs.

### `GET /api/analytics/kpis`
Returns high-level KPI cards: total logs, unique IPs, attacks, benign count, attack percentage, and bot ratio.

### `GET /api/analytics/traffic`
Returns hourly network traffic and attack points.

### `GET /api/analytics/attacks`
Returns the distribution of attack categories (`brute_force`, `path_traversal`, `sqli`) with counts and percentages.

### `GET /api/analytics/ip-analysis`
Returns top high-density attacking IP records with attack counts, ratios, and risk levels.

---

## 3. Log Explorer

### `GET /api/logs/records`
Search and filter structured log records.
- **Query Parameters:**
  - `page` (int, default: 1)
  - `page_size` (int, default: 25, min: 1, max: 200)
  - `search` (string, optional: search query against IP, UA, Route)
  - `ip` (string, optional)
  - `label` (string, optional: `all`, `benign`, `attack`, `sqli`, `path_traversal`, `brute_force`)
  - `is_bot` (bool, optional)
  - `client_type` (string, optional: `chrome`, `firefox`, `gobuster`, etc.)
- **Response:**
  ```json
  {
    "total_matches": 2604,
    "page": 1,
    "page_size": 25,
    "total_pages": 105,
    "records": [...]
  }
  ```

---

## 4. Machine Learning & Inference

### `GET /api/model/metrics`
Returns evaluation metrics from the trained Random Forest model.
- **Response Attributes:** `accuracy`, `precision_attack`, `recall_attack`, `f1_attack`, `confusion_matrix`, `feature_importances`.

### `POST /api/model/predict`
Runs live model inference against incoming behavioral features.
- **Request Body:**
  ```json
  {
    "requests_per_ip": 120,
    "time_between_requests": 0.05,
    "user_agent_length": 18,
    "unique_user_agents_per_ip": 1,
    "client_type": "gobuster",
    "is_bot": true
  }
  ```
- **Response Body:**
  ```json
  {
    "prediction": "Attack",
    "predicted_class": 1,
    "confidence": 0.985,
    "probabilities": { "Benign": 0.015, "Attack": 0.985 },
    "risk_score": 98,
    "evidence": [...],
    "timestamp": "2026-09-28T18:55:00Z"
  }
  ```

---

## 5. AI Security Analyst

### `POST /api/ai/analyze`
Generates natural language threat intelligence strictly grounded in actual system statistics.
- **Request Body:**
  ```json
  {
    "query": "How many attacks were detected?",
    "context_type": "general"
  }
  ```
- **Response:** Grounded answer, threat assessment, recommended investigation steps, mitigation guidance.

### `POST /api/ai/mitigation`
Generates tailored Linux `iptables` and ModSecurity WAF rules for offending IPs and attack types.

---

## 6. Pipeline & Maintenance

### `GET /api/pipeline/status`
Returns real-time execution state of all 9 pipeline stages and logs.

### `POST /api/pipeline/run`
Triggers pipeline execution in background thread.

### `GET /api/system/export/{dataset_name}`
Downloads verified CSV/TXT output files (`balanced`, `predictions`, `ip_frequency`, `pipeline_summary`).
