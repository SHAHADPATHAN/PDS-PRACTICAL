# PROJECT AUDIT: AI-POWERED LOG INTELLIGENCE & CYBERSECURITY ANALYTICS PLATFORM

**Audit Date:** 2026-09-28  
**Auditor:** Senior Engineering Architecture Team  
**Workspace Root:** `D:\PDS PRACTICAL`  
**Raw Source Dataset:** `D:\PDS PRACTICAL\Logs\logs\cj.log` (225,867,389 bytes / ~215.40 MB)

---

## 1. Project Structure

```
D:\PDS PRACTICAL\
├── Logs\
│   ├── logs\
│   │   ├── cj.log                      [225.87 MB - 2,062,365 raw lines, 2,060,520 valid records]
│   │   └── cj_final_vscode_safe.csv    [234.05 MB - Intermediate safe export]
│   ├── Task\                           [Notebooks, training sheets, intermediate research files]
│   ├── cj_cleaned.csv                  [169.02 MB]
│   └── FINAL_UPDATED_LABELED.csv       [449.06 MB]
├── Practical-1\
│   ├── pr-1.py                         [Raw log loader, initial JSON extractor & EDA]
│   └── output\                         [extracted_fields.csv, sample_logs.csv, report.txt, PNGs]
├── Practical-2\
│   ├── pr-2.py                         [Structuring raw logs to standard 8-column schema]
│   └── output\                         [cj_cleaned.csv, field_description.csv, report]
├── Practical-3\
│   ├── pr-3.py                         [Timestamp parsing, lowercase cleaning, deduplication]
│   └── output\                         [cj_preprocessed.csv, practical_3_report.txt]
├── Practical-4\
│   ├── pr-4.py                         [Attack rule labeling: benign, sqli, path_traversal, brute_force]
│   └── output\                         [labeled_logs.csv, label_summary.csv, practical_4_report.txt]
├── Practical-5\
│   ├── pr_5.py                         [Behavioral feature engineering: frequency, time delta, UA length, bot detection]
│   └── output\                         [feature_engineered_logs.csv, ip_features.csv, report]
├── Practical-6\
│   ├── Pr-6.py                         [Dataset balancing: undersampling majority benign to match attack count]
│   └── output\                         [balanced_dataset.csv (2,604 rows), distributions, report]
├── Practical-7\
│   ├── Pr-7.py                         [Wrangling & time-series aggregation: hourly/daily traffic, IP pivots]
│   └── output\                         [hourly_traffic.csv, ip_attack_frequency.csv, bot filtering, charts]
├── Practical-8\
│   ├── Pr-8.py                         [Exploratory Data Analysis: Seaborn charts, Matplotlib, Plotly interactive HTML]
│   └── output\                         [interactive_hourly_traffic.html, heatmaps, top_10_attacking_ips.png]
├── Practical-9\
│   ├── Pr-9.py                         [ML Classifier: Random Forest attack detector on balanced dataset]
│   └── output\                         [confusion_matrix.png, classification_report.txt, feature_importance.csv]
├── Practical-10\
│   ├── Pr-10.py                        [Monolithic reusable pipeline class (LogDataPipeline)]
│   └── output\                         [processed_logs.csv (287.50 MB), pipeline_summary.txt]
└── Practical List for the Python for Data Science.pdf  [Curriculum specification]
```

---

## 2. Existing Architecture Analysis

The existing codebase was built incrementally as 10 discrete academic practical exercises:
1. **Pipeline Execution Model:** Currently, each practical is an isolated script (`pr-1.py` through `Pr-10.py`).
2. **Intermediate Storage:** Massive disk I/O occurs because each practical reads a massive uncompressed CSV (~160 MB - ~287 MB) and writes another massive CSV.
3. **Coupling:** Practical 10 introduced a class `LogDataPipeline` that bundled steps 1–5 (load -> parse -> label -> preprocess -> feature engineer) into one file, but bypassed balancing (Pr-6), analytics aggregation (Pr-7), visualization (Pr-8), and ML training (Pr-9).
4. **Backend / API:** No REST or HTTP API existed prior to this audit.
5. **Frontend / UI:** No web application existed (only static PNG images and an interactive Plotly HTML export).

---

## 3. Practical-by-Practical Deep Dive

### Practical-1: Load and Explore Unstructured Log Data
* **Script:** `Practical-1/pr-1.py`
* **Input:** `Logs/logs/cj.log` (225.87 MB)
* **Output:** `Practical-1/output/extracted_fields.csv` (161.02 MB), `sample_logs.csv`, `report.txt`, charts.
* **Status:** PASS (Verified).
* **Column Schema:** `Event_Type`, `Sub_Type`, `Timestamp`, `IP_Address`, `Port`, `User_Agent`, `Language`, `Forwarded_IP`.
* **Note:** Used capitalized snake_case.

### Practical-2: Convert Unstructured Data to Structured Dataset
* **Script:** `Practical-2/pr-2.py`
* **Input:** `Logs/logs/cj.log`
* **Output:** `Practical-2/output/cj_cleaned.csv` (161.02 MB, 2,060,520 rows), `field_description.csv`.
* **Status:** PASS (Verified).
* **Column Schema:** Standardized to `['category_type', 'sub_key', 'timestamp', 'Client-IP-address', 'port', 'Browser-OS', 'language', 'meta-data']`.

### Practical-3: Data Cleaning and Preprocessing
* **Script:** `Practical-3/pr-3.py`
* **Input:** `Practical-2/output/cj_cleaned.csv`
* **Output:** `Practical-3/output/cj_preprocessed.csv` (162.90 MB)
* **Status:** PASS (Verified).
* **Transformations:** `pd.to_datetime` coercion, lowercasing, stripping extra whitespace, duplicate checking.

### Practical-4: Attack Labeling
* **Script:** `Practical-4/pr-4.py`
* **Input:** `Practical-3/output/cj_preprocessed.csv`
* **Output:** `Practical-4/output/labeled_logs.csv` (172.86 MB), `label_summary.csv`.
* **Status:** PASS (Verified).
* **Rule Engine:**
  - SQL Injection (`sqli`): Regex for `' or 1=1`, `union select`, `drop table`, `insert into`, `--`.
  - Path Traversal (`path_traversal`): Regex for `../`, `..\`, `%2e%2e`.
  - Brute Force (`brute_force`): High-frequency access to auth endpoints (`login`, `password`, `auth`) >= 5 attempts.
  - Normal Traffic: `benign`.

### Practical-5: Feature Engineering
* **Script:** `Practical-5/pr_5.py`
* **Input:** `Practical-4/output/labeled_logs.csv`
* **Output:** `Practical-5/output/feature_engineered_logs.csv` (215.12 MB, 15 columns), `ip_features.csv`.
* **Status:** PASS (Verified).
* **Features Generated:** `requests_per_ip`, `time_between_requests`, `user_agent_length`, `unique_user_agents_per_ip`, `is_bot`, `client_type`.

### Practical-6: Dataset Balancing
* **Script:** `Practical-6/Pr-6.py`
* **Input:** `Practical-5/output/feature_engineered_logs.csv`
* **Output:** `Practical-6/output/balanced_dataset.csv` (0.46 MB, 2,604 rows), `balanced_class_distribution.csv`.
* **Status:** PASS (Verified).
* **Balancing Strategy:** Grouped attacks into binary classification (`attack` vs `benign`), kept all 1,302 attack records, randomly undersampled benign records to exactly 1,302. Result: 2,604 rows, 50% benign, 50% attack.

### Practical-7: Data Wrangling for Aggregated Analysis
* **Script:** `Practical-7/Pr-7.py`
* **Input:** `Practical-6/output/balanced_dataset.csv`
* **Output:** `ip_attack_frequency.csv`, `hourly_traffic.csv`, `daily_traffic.csv`, `hourly_attack_traffic.csv`, `request_type_label_pivot.csv`, `data_without_bots.csv`, `filtered_external_traffic.csv`, `top_attack_ips.png`.
* **Status:** PASS (Verified).
* **Filters:** Bot filtering via regex, internal RFC1918 private IP filtering (10.x, 172.16-31.x, 192.168.x).

### Practical-8: Data Visualization and Exploratory Data Analysis (EDA)
* **Script:** `Practical-8/Pr-8.py`
* **Input:** `Practical-6/output/balanced_dataset.csv`
* **Output:** 11 files including `interactive_hourly_traffic.html` (5.14 MB Plotly interactive chart), `top_10_attacking_ips.png`, `ip_request_type_heatmap.png`, `attack_categories_over_time.png`.
* **Status:** PASS (Verified).

### Practical-9: Attack Classification Model
* **Script:** `Practical-9/Pr-9.py`
* **Input:** `Practical-6/output/balanced_dataset.csv` (2,604 records)
* **Output:** `confusion_matrix.png`, `confusion_matrix.csv`, `classification_report.txt`, `feature_importance.csv`, `feature_importance.png`, `model_results.csv`, `test_predictions.csv`.
* **Status:** PASS (Verified).
* **Metrics:** 
  - Accuracy: **97.89%**
  - Benign Precision: 0.99, Recall: 0.97, F1: 0.98
  - Attack Precision: 0.97, Recall: 0.99, F1: 0.98
  - Top Features: `client_type`, `is_bot`, `unique_user_agents_per_ip`, `requests_per_ip`, `user_agent_length`.

### Practical-10: Reusable Data Pipeline
* **Script:** `Practical-10/Pr-10.py`
* **Input:** `Logs/logs/cj.log`
* **Output:** `Practical-10/output/processed_logs.csv` (287.50 MB, 2,060,520 records, 15 columns), `pipeline_summary.txt`.
* **Status:** PASS (Verified).
* **Execution Time:** ~160 seconds on raw log file.

---

## 4. Existing Datasets Inventory

| Dataset Location | File Name | Size (MB) | Rows | Purpose |
| :--- | :--- | :--- | :--- | :--- |
| `Logs\logs\` | `cj.log` | 215.40 MB | 2,062,365 | Raw JSON-array log source |
| `Practical-1\output\` | `extracted_fields.csv` | 161.02 MB | ~1.49M | Initial parsed table |
| `Practical-2\output\` | `cj_cleaned.csv` | 161.02 MB | 2,060,520 | Structured 8-column log |
| `Practical-3\output\` | `cj_preprocessed.csv` | 162.90 MB | ~1.49M | Cleaned & normalized logs |
| `Practical-4\output\` | `labeled_logs.csv` | 172.86 MB | ~1.49M | Labeled with attack types |
| `Practical-5\output\` | `feature_engineered_logs.csv` | 215.12 MB | ~1.49M | 15 engineered features |
| `Practical-6\output\` | `balanced_dataset.csv` | 0.46 MB | 2,604 | Balanced 50/50 dataset |
| `Practical-7\output\` | `filtered_external_traffic.csv` | 0.02 MB | Filtered | Bot & internal IP filtered |
| `Practical-10\output\`| `processed_logs.csv` | 287.50 MB | 2,060,520 | Full pipeline output |

---

## 5. Existing ML & AI Status

* **Machine Learning:** Random Forest model in `Practical-9/Pr-9.py` trains dynamically in-memory on each run.
  * **Gap:** The trained model was never serialized to disk with `joblib.dump()` or `pickle`.
* **Explainable AI:** Feature importances are calculated via tree impurity and exported to CSV/PNG, but local sample-level explanations (evidence breakdown) are not exposed via an API.
* **Generative AI:** None existed in the repo. Needs ground-truth-grounded contextual AI security analyst.

---

## 6. Identified Problems & Architectural Gaps

1. **Massive CSV Redundancy:** Multiple ~200MB CSV files stored on disk.
2. **Missing Model Persistence:** Practical 9 trains the model but does not save `model.joblib`. Real-time inference requires loading a saved model artifact.
3. **No Parquet Utilization:** Parquet was skipped in Practical 10 due to missing `pyarrow` (now installed).
4. **No Unified Orchestrator:** The pipeline exists as disconnected sequential scripts.
5. **No Backend API:** Frontend cannot query real-time analytics, trigger pipeline runs, or inspect logs.
6. **No Web Frontend:** No user-facing application exists yet.

---

## 7. Recommended Enterprise Architecture

To meet all requirements of the master prompt without breaking existing practicals:

```
D:\PDS PRACTICAL\
├── platform\                           [NEW UNIFIED ENTERPRISE ENGINE]
│   ├── backend\
│   │   ├── app\
│   │   │   ├── main.py                 [FastAPI application entrypoint]
│   │   │   ├── config.py               [Paths, environment, settings]
│   │   │   ├── api\                    [REST endpoints: logs, analytics, pipeline, ml, ai, health]
│   │   │   ├── services\               [Data access, ingestion, analytics, ml, ai services]
│   │   │   ├── pipeline\
│   │   │   │   └── orchestrator.py     [Unified PipelineOrchestrator]
│   │   │   └── models\                 [Pydantic schemas & state models]
│   │   └── artifacts\                  [Saved model.joblib, metadata, parquet cache]
│   └── frontend\                       [PREMIUM BLACK + ORANGE SPA]
│       ├── index.html                  [Semantic HTML5, Google Fonts Inter/Outfit]
│       ├── css\
│       │   └── style.css               [Tailored Black & Orange design system tokens]
│       └── js\
│           ├── api.js                  [Real backend client]
│           ├── state.js                [Reactive UI state management]
│           └── app.js                  [Dashboard, Explorer, Pipeline, ML, AI components]
├── Practical-1 ... Practical-10        [100% PRESERVED ACADEMIC WORK]
└── Logs\                               [RAW DATA SOURCE]
```

### Key Technical Decisions:
1. **Model Persistence:** Train and save `model.joblib` using scikit-learn on the balanced dataset so inference endpoints respond in milliseconds.
2. **Fast In-Memory Analytics & Parquet:** Cache aggregates for dashboard KPIs so queries respond instantly without scanning 200MB repeatedly.
3. **Strict Zero-Mocking Rule:** All statistics, charts, predictions, and AI prompts read directly from the actual output files or live model inference.
4. **AI Grounding:** AI Security Analyst queries live pipeline summary stats, top IPs, and model predictions before formulating responses.
5. **Black + Orange Design System:** Background `#050505`, Cards `#111111`, Borders `#242424`, Accents `#FF6A00` / `#FF7A00`, Text `#F5F5F5`.
