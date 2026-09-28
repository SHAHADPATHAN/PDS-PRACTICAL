import os
from pathlib import Path

# Base Paths
PROJECT_ROOT = Path(r"D:\PDS PRACTICAL").resolve()
PLATFORM_ROOT = PROJECT_ROOT / "platform"
BACKEND_ROOT = PLATFORM_ROOT / "backend"
FRONTEND_ROOT = PLATFORM_ROOT / "frontend"
ARTIFACTS_DIR = BACKEND_ROOT / "artifacts"

# Dataset Paths
RAW_LOG_FILE = PROJECT_ROOT / "Logs" / "logs" / "cj.log"
BALANCED_DATASET_FILE = PROJECT_ROOT / "Practical-6" / "output" / "balanced_dataset.csv"
PROCESSED_LOGS_FILE = PROJECT_ROOT / "Practical-10" / "output" / "processed_logs.csv"
PIPELINE_SUMMARY_FILE = PROJECT_ROOT / "Practical-10" / "output" / "pipeline_summary.txt"

# Model Artifacts
MODEL_FILE = ARTIFACTS_DIR / "model.joblib"
METADATA_FILE = ARTIFACTS_DIR / "model_metadata.json"

# Practical Outputs Directory Mapping
PRACTICAL_DIRS = {
    "P1": PROJECT_ROOT / "Practical-1" / "output",
    "P2": PROJECT_ROOT / "Practical-2" / "output",
    "P3": PROJECT_ROOT / "Practical-3" / "output",
    "P4": PROJECT_ROOT / "Practical-4" / "output",
    "P5": PROJECT_ROOT / "Practical-5" / "output",
    "P6": PROJECT_ROOT / "Practical-6" / "output",
    "P7": PROJECT_ROOT / "Practical-7" / "output",
    "P8": PROJECT_ROOT / "Practical-8" / "output",
    "P9": PROJECT_ROOT / "Practical-9" / "output",
    "P10": PROJECT_ROOT / "Practical-10" / "output",
}

# API Configuration
API_HOST = os.getenv("API_HOST", "127.0.0.1")
API_PORT = int(os.getenv("API_PORT", "8000"))
DEBUG = os.getenv("DEBUG", "False").lower() in ("true", "1", "yes")

# Optional GenAI Key
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY", "")
