from fastapi import APIRouter
from typing import List, Dict
from app.services.analytics_service import analytics_service
from app.models.schemas import (
    AnalyticsOverviewResponse,
    KPICards,
    TrafficPoint,
    AttackCategoryStat,
    IPAnalysisRecord
)

router = APIRouter(prefix="/analytics", tags=["Analytics"])

@router.get("/overview", response_model=AnalyticsOverviewResponse)
def get_analytics_overview():
    return analytics_service.get_overview()

@router.get("/kpis", response_model=KPICards)
def get_kpis():
    return analytics_service.get_kpis()

@router.get("/traffic", response_model=List[TrafficPoint])
def get_traffic():
    return analytics_service.get_traffic_timeline()

@router.get("/attacks", response_model=List[AttackCategoryStat])
def get_attacks():
    return analytics_service.get_attack_distribution()

@router.get("/ip-analysis", response_model=List[IPAnalysisRecord])
def get_ip_analysis():
    return analytics_service.get_top_ips()

@router.get("/client-types", response_model=Dict[str, int])
def get_client_types():
    return analytics_service.get_client_type_distribution()
