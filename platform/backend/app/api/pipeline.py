from fastapi import APIRouter, HTTPException
from app.pipeline.orchestrator import pipeline_orchestrator
from app.models.schemas import PipelineStatusResponse, PipelineRunRequest

router = APIRouter(prefix="/pipeline", tags=["Pipeline"])

@router.get("/status", response_model=PipelineStatusResponse)
def get_pipeline_status():
    return pipeline_orchestrator.get_status()

@router.post("/run")
def trigger_pipeline(req: PipelineRunRequest = PipelineRunRequest()):
    success, msg = pipeline_orchestrator.trigger_run(mode=req.mode, include_training=req.include_training)
    if not success:
        raise HTTPException(status_code=400, detail=msg)
    return {"message": msg, "mode": req.mode}
