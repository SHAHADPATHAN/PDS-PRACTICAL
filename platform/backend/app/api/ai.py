from fastapi import APIRouter
from app.services.ai_service import ai_service
from app.models.schemas import (
    AIAnalysisRequest,
    AIAnalysisResponse,
    AIMitigationRequest,
    AIMitigationResponse
)

router = APIRouter(prefix="/ai", tags=["AI Security Analyst"])

@router.post("/analyze", response_model=AIAnalysisResponse)
def analyze_logs(req: AIAnalysisRequest):
    return ai_service.analyze(req)

@router.post("/mitigation", response_model=AIMitigationResponse)
def generate_mitigation(req: AIMitigationRequest):
    return ai_service.generate_mitigation(req)
