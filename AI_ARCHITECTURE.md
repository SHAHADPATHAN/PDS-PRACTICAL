# AI & MACHINE LEARNING ARCHITECTURE

**Platform:** SENTINEL AI - Log Intelligence Platform  
**Component:** Dual-Engine Threat Intelligence (Random Forest + Grounded LLM Analyst)

---

## 1. Machine Learning Engine (Classification)

### Architecture
- **Algorithm:** Random Forest Classifier (100 estimators, balanced class weights, parallel multi-threading `n_jobs=-1`).
- **Feature Vector (15 Dimensions):**
  - Continuous Numeric:
    1. `requests_per_ip`: Volume frequency indicating burst or scanner activity.
    2. `time_between_requests`: Sub-second inter-arrival times characteristic of scripts.
    3. `user_agent_length`: String length anomalies in header metadata.
    4. `unique_user_agents_per_ip`: Header rotation / IP spoofing indicator.
  - Categorical (One-Hot Encoded):
    5. `client_type_chrome`
    6. `client_type_firefox`
    7. `client_type_mozilla`
    8. `client_type_gobuster` (Security scanner)
    9. `client_type_dirbuster` (Directory brute forcer)
    10. `client_type_command_line_tool` (curl / wget / python-requests)
    11. `client_type_other`
    12. `is_bot_True`
    13. `is_bot_False`

### Performance Metrics on Balanced Held-Out Test Set (521 Samples)
- **Accuracy:** **97.89%**
- **Attack Recall (Sensitivity):** **0.99** (Catches 99% of all attacks)
- **Attack Precision:** **0.97**
- **Attack F1-Score:** **0.98**
- **Benign Precision / Recall:** **0.99 / 0.97**

---

## 2. Explainable AI (XAI) Subsystem

For every prediction made by the live inference engine, the system returns feature attribution evidence:
- **Feature Contribution:** Flags whether an attribute pushed the prediction toward "Attack" or "Benign".
- **Gini Importance Weight:** Cross-references tree-impurity weights to explain which variables had the largest impact.
- **Human-Readable Rationale:** Translates technical variables into actionable security observations (e.g., *"Sub-second request interval (0.05s) indicates automated scripted traffic"*).

---

## 3. Generative AI Security Analyst

### Grounded Intelligence Architecture
The AI Security Analyst is engineered to prevent hallucinations by injecting structured system telemetry directly into the context window:

```
[Live Database & Analytics Engine]
               │
               ▼ (Extract Verified Facts)
{
  "total_records": 2,060,520,
  "attack_records": 2,545,
  "top_attack_types": [...],
  "top_suspicious_ips": [...],
  "model_accuracy": "97.89%"
}
               │
               ▼ (Context Injection)
+-------------------------------------------------+
| LLM PROMPT (Google GenAI / Deterministic Fallback)|
| "Answer the analyst query strictly using the     |
| provided verified context. Never invent counts."|
+-------------------------------------------------+
               │
               ▼
[Structured Threat Assessment & Mitigation Output]
```

### Deterministic Expert Fallback Engine
If an external API key is not supplied or the network is disconnected, the platform activates its local deterministic cybersecurity expert system, ensuring uninterrupted operation without simulated or fabricated outputs.
