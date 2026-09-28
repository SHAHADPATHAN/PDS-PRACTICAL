# PIPELINE VALIDATION REPORT

**Validation Date:** 2026-09-28  
**Dataset Root:** `D:\PDS PRACTICAL`  
**Execution Environment:** Windows / Python 3.14.6 & Python 3.12 (dual verified)  
**Status:** ALL 10 STAGES AUDITED & VALIDATED

---

## Stage-by-Stage Verification Matrix

| Practical | Name | Input | Output | Rows / Size | Validation Checks | Status | Problems & Fixes |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **Practical-1** | Load & Explore | `Logs\logs\cj.log` (215.4 MB) | `Practical-1\output\extracted_fields.csv` | 161.02 MB / 8 cols | Schema, JSON array parsing, field extraction | **PASS** | None. Capitalized column names (`IP_Address`). Handled in P2. |
| **Practical-2** | Convert to Structured | `Logs\logs\cj.log` | `Practical-2\output\cj_cleaned.csv` | 161.02 MB / 2,060,520 rows | 8 standard columns: `category_type`, `sub_key`, `timestamp`, `Client-IP-address`, `port`, `Browser-OS`, `language`, `meta-data` | **PASS** | Standardized schema adopted by all subsequent stages. |
| **Practical-3** | Clean & Preprocess | `Practical-2\output\cj_cleaned.csv` | `Practical-3\output\cj_preprocessed.csv` | 162.90 MB | Datetime conversion, lowercase normalization, whitespace stripping | **PASS** | Date parsing with `errors='coerce'` handles corrupted timestamps. |
| **Practical-4** | Attack Labeling | `Practical-3\output\cj_preprocessed.csv` | `Practical-4\output\labeled_logs.csv` | 172.86 MB / 9 cols | Labels: `benign`, `sqli`, `path_traversal`, `brute_force` | **PASS** | Severe class imbalance (99.91% benign). Solved in Practical 6. |
| **Practical-5** | Feature Engineering | `Practical-4\output\labeled_logs.csv` | `Practical-5\output\feature_engineered_logs.csv` | 215.12 MB / 15 cols | Features: `requests_per_ip`, `time_between_requests`, `user_agent_length`, `unique_user_agents_per_ip`, `is_bot`, `client_type` | **PASS** | High memory usage on 2M rows; vectorized pandas operations used. |
| **Practical-6** | Dataset Balancing | `Practical-5\output\feature_engineered_logs.csv` | `Practical-6\output\balanced_dataset.csv` | 0.46 MB / 2,604 rows | 1,302 benign vs 1,302 attack (exact 50/50 ratio) | **PASS** | Successfully downsamples majority class to eliminate accuracy paradox. |
| **Practical-7** | Data Wrangling | `Practical-6\output\balanced_dataset.csv` | `Practical-7\output\hourly_traffic.csv` + 12 files | 13 output files | Time-series resampling (1h, 1D), IP frequency grouping, bot filtering, RFC1918 private IP filtering | **PASS** | No HTTP GET/POST column present; wrangling gracefully pivoted on `category_type`. |
| **Practical-8** | Visualizations & EDA | `Practical-6\output\balanced_dataset.csv` | `Practical-8\output\interactive_hourly_traffic.html` + 10 files | 11 output files (Plotly HTML + PNGs) | Hourly trends, top 10 attacking IPs barplot, attack category timeline, IP vs request type heatmap | **PASS** | Interactive Plotly HTML generated (5.14 MB) for web embedding. |
| **Practical-9** | Attack Classifier ML | `Practical-6\output\balanced_dataset.csv` | `Practical-9\output\model_results.csv`, `classification_report.txt`, `confusion_matrix.png`, `feature_importance.csv` | 2,604 samples (80/20 train/test split) | Random Forest Classifier, balanced class evaluation, metrics, feature importances | **PASS** | Previously trained on imbalanced data; now verified on balanced dataset (97.89% Accuracy, 0.98 F1). |
| **Practical-10**| Reusable Pipeline | `Logs\logs\cj.log` | `Practical-10\output\processed_logs.csv`, `pipeline_summary.txt` | 287.50 MB / 2,060,520 records | End-to-end load -> parse -> label -> preprocess -> feature engineering | **PASS** | PyArrow missing previously; now installed. Unified orchestrator designed in Phase D. |

---

## Data Lineage & Stage Connectivity

```
[Logs/logs/cj.log] (Raw: 2,062,365 lines)
       │
       ▼ (Pr-1 & Pr-2)
[cj_cleaned.csv] (2,060,520 rows, 8 columns)
       │
       ▼ (Pr-3)
[cj_preprocessed.csv] (Cleaned text, ISO datetimes)
       │
       ▼ (Pr-4)
[labeled_logs.csv] (Adds 'label': benign, sqli, path_traversal, brute_force)
       │
       ▼ (Pr-5)
[feature_engineered_logs.csv] (Adds 6 behavioral ML features)
       │
       ▼ (Pr-6)
[balanced_dataset.csv] (2,604 rows: 1,302 attack + 1,302 benign)
       ├───► (Pr-7) [Time-series & IP aggregations]
       ├───► (Pr-8) [Interactive EDA & visual heatmaps]
       └───► (Pr-9) [Random Forest Classifier: 97.89% Accuracy, 0.98 F1]
```

All 10 practicals are verified operational, verified connected, and validated against actual disk artifacts.
