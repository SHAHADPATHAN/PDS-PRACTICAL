# TESTING & QUALITY ASSURANCE SPECIFICATION

**Platform:** SENTINEL AI - Log Intelligence Platform  
**Test Suite:** `platform/backend/tests/test_platform.py`  
**Framework:** Python `unittest` + `starlette.testclient`

---

## 1. Test Execution Commands

To execute the complete regression test suite:

```powershell
python "d:/PDS PRACTICAL/platform/backend/tests/test_platform.py"
```

### Expected Output
```
Ran 8 tests in 0.256s
OK
```

---

## 2. Test Coverage Matrix

| Test Identifier | Tested Component | Verification Goal | Status |
| :--- | :--- | :--- | :--- |
| `test_01_raw_log_and_artifacts` | Storage & Artifacts | Verifies existence of `cj.log`, `balanced_dataset.csv`, and `model.joblib`. | **PASS** |
| `test_02_health_endpoint` | System Health API | Validates `/api/health` response schema and loaded model status. | **PASS** |
| `test_03_analytics_kpis` | Analytics Engine | Validates 2,060,520 total logs, 16,680 unique IPs, and attack counts. | **PASS** |
| `test_04_logs_query_pagination_and_filters` | Log Explorer API | Tests server-side pagination, search queries, `label=sqli`, and `is_bot=true`. | **PASS** |
| `test_05_model_metrics_and_prediction` | ML Inference | Verifies model metrics and tests both attack (scanner) and benign inference. | **PASS** |
| `test_06_ai_analyst_grounded_response` | AI Security Analyst | Verifies AI query response contains real dataset counts (2,545 attacks). | **PASS** |
| `test_07_pipeline_orchestrator` | Orchestrator Engine | Verifies status reporting for all 9 pipeline execution stages. | **PASS** |
| `test_08_data_quality_and_exports` | Data Quality & Files | Verifies data quality statistics and real binary/CSV file downloads. | **PASS** |
