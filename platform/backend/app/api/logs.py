from fastapi import APIRouter, Query
from typing import Optional
from app.services.data_service import data_service
from app.models.schemas import LogsQueryResponse

router = APIRouter(prefix="/logs", tags=["Logs"])

@router.get("/records", response_model=LogsQueryResponse)
def get_log_records(
    page: int = Query(1, ge=1),
    page_size: int = Query(25, ge=1, le=200),
    search: Optional[str] = Query(None),
    ip: Optional[str] = Query(None),
    label: Optional[str] = Query(None),
    is_bot: Optional[bool] = Query(None),
    client_type: Optional[str] = Query(None)
):
    return data_service.query_logs(
        page=page,
        page_size=page_size,
        search=search,
        ip=ip,
        label=label,
        is_bot=is_bot,
        client_type=client_type
    )
