# DATA LINEAGE & TRACEABILITY SPECIFICATION

**Document Version:** 1.0.0  
**Project:** AI-Powered Log Intelligence & Security Analytics Platform  
**System Root:** `D:\PDS PRACTICAL`

---

## 1. High-Level Pipeline Flow

```
+-------------------------------------------------------+
| 1. RAW LOG REPOSITORY                                 |
| Source: D:\PDS PRACTICAL\Logs\logs\cj.log             |
| Records: 2,062,365 raw lines (~215.4 MB)              |
+-------------------------------------------------------+
                           |
                           v
+-------------------------------------------------------+
| 2. PARSING & CANONICAL STRUCTURING                    |
| Practical-2: output/cj_cleaned.csv                    |
| Fields: category_type, sub_key, timestamp, Client-IP, |
|         port, Browser-OS, language, meta-data         |
| Records: 2,060,520 valid records (911 malformed)      |
+-------------------------------------------------------+
                           |
                           v
+-------------------------------------------------------+
| 3. PREPROCESSING & CLEANING                           |
| Practical-3: output/cj_preprocessed.csv               |
| Transformations: ISO-8601 datetime parsing, lower-   |
|                  casing, whitespace stripping         |
+-------------------------------------------------------+
                           |
                           v
+-------------------------------------------------------+
| 4. THREAT VECTOR LABELING                             |
| Practical-4: output/labeled_logs.csv                  |
| Heuristic Classifications:                            |
|  - benign: 2,057,975                                  |
|  - brute_force: 1,484                                 |
|  - path_traversal: 885                                |
|  - sqli: 176                                          |
+-------------------------------------------------------+
                           |
                           v
+-------------------------------------------------------+
| 5. BEHAVIORAL FEATURE ENGINEERING                     |
| Practical-5: output/feature_engineered_logs.csv       |
| New Features: requests_per_ip, time_between_requests,  |
|               user_agent_length, is_bot, client_type, |
|               unique_user_agents_per_ip               |
+-------------------------------------------------------+
                           |
                           v
+-------------------------------------------------------+
| 6. DATASET BALANCING (UNDERSAMPLING)                  |
| Practical-6: output/balanced_dataset.csv              |
| Retains all 1,302 attack records; randomly samples    |
| 1,302 benign records. Total: 2,604 samples (50/50).   |
+-------------------------------------------------------+
          |                        |                 |
          v                        v                 v
+--------------------+   +-------------------+  +-------------------------+
| 7. DATA WRANGLING  |   | 8. VISUAL EDA     |  | 9. CLASSIFIER TRAINING  |
| Practical-7 output |   | Practical-8 output|  | Practical-9 & Platform  |
| Hourly/Daily pivots|   | Interactive HTML  |  | Random Forest (100 est) |
| Top IP frequencies |   | Correlation heat- |  | Accuracy: 97.89%        |
| Bot/IP filtering   |   | map, timelines    |  | F1-Score: 0.98          |
+--------------------+   +-------------------+  +-------------------------+
          |                        |                 |
          +------------------------+-----------------+
                                   |
                                   v
             +---------------------------------------------+
             | 10. ENTERPRISE PLATFORM (FASTAPI + WEB SPA) |
             | D:\PDS PRACTICAL\platform                   |
             | Zero-mocking, real-time live inference,     |
             | Grounded AI Security Analyst chat.          |
             +---------------------------------------------+
```

---

## 2. Metric-by-Metric Lineage Matrix

| Metric in UI | Value | Upstream Transformation & Source File |
| :--- | :--- | :--- |
| **Total Ingested Logs** | 2,060,520 | `Practical-10/output/pipeline_summary.txt` (Parsed from `Logs/logs/cj.log`). |
| **Unique Client IPs** | 16,680 | Calculated across unique `Client-IP-address` values in structured logs. |
| **Total Attack Count** | 2,545 | Sum of `sqli` (176) + `path_traversal` (885) + `brute_force` (1,484) in `Practical-10/output/processed_logs.csv`. |
| **Benign Traffic** | 2,057,975 | Records flagged as `benign` in `Practical-10/output/pipeline_summary.txt`. |
| **Attack Ratio** | 0.124% | Mathematically derived: $(2,545 / 2,060,520) \times 100\%$. |
| **Primary Threat Actor** | `14.139.122.76` | `Practical-7/output/ip_attack_frequency.csv` (101 requests, 100 attacks, 99.01% attack density). |
| **Model Test Accuracy** | 97.89% | `platform/backend/artifacts/model_metadata.json` (Evaluated on 521 held-out test samples from `balanced_dataset.csv`). |
| **Attack Precision / Recall**| 0.97 / 0.99 | Derived from confusion matrix `[[253, 8], [3, 257]]` in `model_metadata.json`. |
| **Bot Ratio** | 4.95% | Frequency of `is_bot == True` based on user-agent scanner regexes in `Practical-5`. |
| **AI Analyst Grounding** | Exact Context | Retrieved live via `analytics_service.get_kpis()` and injected directly into LLM prompts. |

---

## 3. Zero-Mock Policy Verification

All data visualized in the dashboard, queried in the Log Explorer, processed by the Machine Learning Hub, and synthesized by the AI Security Analyst originates exclusively from the source log dataset or serialized model artifacts. No synthetic or hardcoded numbers exist in the production runtime.
