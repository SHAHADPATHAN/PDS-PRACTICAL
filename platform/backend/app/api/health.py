import os
from fastapi import APIRouter
from app.config import RAW_LOG_FILE, MODEL_FILE
from app.models.schemas import HealthResponse

router = APIRouter(tags=["Health"])

@router.get("/health", response_model=HealthResponse)
def get_health():
    raw_exists = os.path.exists(RAW_LOG_FILE)
    model_exists = os.path.exists(MODEL_FILE)
    
    return HealthResponse(
        status="healthy",
        version="1.0.0",
        raw_log_found=raw_exists,
        model_loaded=model_exists,
        total_records=2060520,
        environment="Production (Local)"
    )
