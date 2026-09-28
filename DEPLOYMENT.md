# DEPLOYMENT & OPERATION GUIDE

**Platform:** SENTINEL AI - Log Intelligence Platform  
**Target Environment:** Local Workstation / Windows / Linux Server  
**Default Host & Port:** `http://127.0.0.1:8000`

---

## 1. Prerequisites
- Python 3.12 or Python 3.14+
- Modern Web Browser (Chrome, Edge, Firefox, Brave)
- Git

---

## 2. Dependencies Installation

To install all required dependencies:

```powershell
pip install fastapi uvicorn pandas numpy scikit-learn matplotlib seaborn plotly pyarrow starlette httpx pydantic
```

---

## 3. Running the Platform Locally

To start the unified backend and frontend server:

```powershell
cd "d:\PDS PRACTICAL\platform\backend"
python -m uvicorn app.main:app --host 127.0.0.1 --port 8000
```

Once launched, access the platform in your browser at:
👉 **`http://127.0.0.1:8000/`**

Interactive Swagger API Documentation:
👉 **`http://127.0.0.1:8000/api/docs`**

---

## 4. Optional: Enabling Google Gemini GenAI

The AI Security Analyst includes an offline, deterministic expert system grounded in real dataset telemetry. To optionally enable Google Gemini 2.5 Flash:

1. Obtain a Gemini API key from [Google AI Studio](https://aistudio.google.com/).
2. Set the environment variable before launching the server:

```powershell
$env:GEMINI_API_KEY="YOUR_ACTUAL_GEMINI_API_KEY"
python -m uvicorn app.main:app --host 127.0.0.1 --port 8000
```

---

## 5. Running Standalone Academic Practicals

The original academic practicals are preserved in their respective directories:

```powershell
# Practical 6 (Dataset Balancing)
python "d:\PDS PRACTICAL\Practical-6\Pr-6.py"

# Practical 7 (Data Wrangling)
python "d:\PDS PRACTICAL\Practical-7\Pr-7.py"

# Practical 8 (Data Visualization & EDA)
python "d:\PDS PRACTICAL\Practical-8\Pr-8.py"

# Practical 9 (Machine Learning Classifier)
python "d:\PDS PRACTICAL\Practical-9\Pr-9.py"

# Practical 10 (Reusable Pipeline)
python "d:\PDS PRACTICAL\Practical-10\Pr-10.py"
```
