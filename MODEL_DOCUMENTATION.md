# MACHINE LEARNING MODEL DOCUMENTATION & CARD

**Model Name:** Random Forest Attack Detector  
**Model Version:** `v1.0.0`  
**Model Artifact:** `platform/backend/artifacts/model.joblib`  
**Training Date:** 2026-09-28  
**Framework:** `scikit-learn 1.9.1`

---

## 1. Intended Use
- **Primary Use Case:** Inline and batch classification of web server access log requests into "Benign" or "Attack" categories.
- **Out of Scope:** Does not inspect encrypted packet payloads (e.g., deep packet payload byte streams). Operates on HTTP metadata and behavioral telemetry.

---

## 2. Training Data
- **Source:** `Practical-6/output/balanced_dataset.csv`
- **Total Records:** 2,604 samples
  - Benign: 1,302 (50.0%)
  - Attack: 1,302 (50.0%)
- **Split Ratio:** 80% Training (2,083 samples) / 20% Testing (521 samples), stratified by class label.

---

## 3. Evaluation & Validation Results

### Confusion Matrix
```
                  Predicted Benign    Predicted Attack
Actual Benign           253                   8
Actual Attack             3                 257
```

### Classification Report
| Class | Precision | Recall | F1-Score | Support |
| :--- | :---: | :---: | :---: | :---: |
| **Benign** | 0.99 | 0.97 | 0.98 | 261 |
| **Attack** | 0.97 | 0.99 | 0.98 | 260 |
| **Accuracy** | — | — | **0.9789** | 521 |
| **Macro Avg** | 0.98 | 0.98 | 0.98 | 521 |
| **Weighted Avg** | 0.98 | 0.98 | 0.98 | 521 |

---

## 4. Top Feature Importances (Gini Impurity)
1. `client_type` (Scanner vs Browser signatures): ~20.3%
2. `is_bot` (Known automated crawler flags): ~18.0%
3. `unique_user_agents_per_ip` (Multi-agent IP rotation): ~15.3%
4. `user_agent_length` (Header anomalies): ~12.8%
5. `requests_per_ip` (Volume concentration): ~12.6%
6. `time_between_requests` (Sub-second burst inter-arrival): ~1.7%
