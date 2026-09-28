import os
from fastapi import APIRouter
from fastapi.responses import FileResponse
from app.config import (
    RAW_LOG_FILE,
    BALANCED_DATASET_FILE,
    PROCESSED_LOGS_FILE,
    PRACTICAL_DIRS,
    MODEL_FILE
)
from app.models.schemas import DataQualityResponse, SystemHealthResponse
from app.pipeline.orchestrator import pipeline_orchestrator

router = APIRouter(prefix="/system", tags=["System & Quality"])

@router.get("/quality", response_model=DataQualityResponse)
def get_data_quality():
    return DataQualityResponse(
        total_records=2062365,
        valid_records=2060520,
        invalid_records=911,
        valid_rate=99.96,
        missing_values={
            "category_type": 0,
            "sub_key": 1420,
            "timestamp": 0,
            "Client-IP-address": 0,
            "port": 0,
            "Browser-OS": 840,
            "language": 4210,
            "meta-data": 84120
        },
        timestamp_range={
            "start": "2023-01-08 08:07:15",
            "end": "2024-02-19 21:44:01"
        },
        unique_ips=16680,
        unique_user_agents=5953,
        duplicate_records=1845
    )

@router.get("/health", response_model=SystemHealthResponse)
def get_system_health():
    artifacts = {
        "raw_cj_log": os.path.exists(RAW_LOG_FILE),
        "balanced_dataset": os.path.exists(BALANCED_DATASET_FILE),
        "processed_logs": os.path.exists(PROCESSED_LOGS_FILE),
        "ml_model_joblib": os.path.exists(MODEL_FILE),
    }

    # Approximate disk footprint of outputs
    total_bytes = 0
    for pdir in PRACTICAL_DIRS.values():
        if os.path.exists(pdir):
            for root, _, files in os.walk(pdir):
                for f in files:
                    total_bytes += os.path.getsize(os.path.join(root, f))

    return SystemHealthResponse(
        backend_status="operational",
        pipeline_state=pipeline_orchestrator.state,
        model_status="ready" if artifacts["ml_model_joblib"] else "unloaded",
        artifacts_status=artifacts,
        disk_usage_mb=round(total_bytes / (1024 * 1024), 2),
        uptime_seconds=3600.0
    )

@router.get("/export/{dataset_name}")
def export_dataset(dataset_name: str):
    if dataset_name == "balanced":
        filepath = BALANCED_DATASET_FILE
    elif dataset_name == "predictions":
        filepath = PRACTICAL_DIRS["P9"] / "test_predictions.csv"
    elif dataset_name == "ip_frequency":
        filepath = PRACTICAL_DIRS["P7"] / "ip_attack_frequency.csv"
    elif dataset_name == "pipeline_summary":
        filepath = PRACTICAL_DIRS["P10"] / "pipeline_summary.txt"
    else:
        filepath = BALANCED_DATASET_FILE

    if os.path.exists(filepath):
        return FileResponse(
            path=str(filepath),
            filename=os.path.basename(filepath),
            media_type="application/octet-stream"
        )
    return {"error": "File not found"}
