from fastapi import APIRouter
from typing import Dict
from app.services.ml_service import ml_service
from app.models.schemas import (
    PredictRequest,
    PredictResponse,
    ModelMetricsResponse
)

router = APIRouter(prefix="/model", tags=["Machine Learning"])

@router.get("/metrics", response_model=ModelMetricsResponse)
def get_model_metrics():
    return ml_service.get_metrics()

@router.get("/features", response_model=Dict[str, float])
def get_features():
    return ml_service.get_metrics().feature_importances

@router.post("/predict", response_model=PredictResponse)
def predict_attack(req: PredictRequest):
    return ml_service.predict(req)
