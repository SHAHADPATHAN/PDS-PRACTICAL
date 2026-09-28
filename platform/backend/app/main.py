import os
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from app.config import FRONTEND_ROOT, DEBUG
from app.api import (
    health,
    pipeline,
    logs,
    analytics,
    predictions,
    ai,
    system,
    upload
)

app = FastAPI(
    title="AI-Powered Log Intelligence & Security Analytics Platform",
    description="Unified Enterprise Backend integrating End-to-End Log Analytics, Machine Learning & Grounded AI",
    version="1.0.0",
    docs_url="/api/docs",
    redoc_url="/api/redoc"
)

# CORS Configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include API Routers under /api
app.include_router(health.router, prefix="/api")
app.include_router(pipeline.router, prefix="/api")
app.include_router(logs.router, prefix="/api")
app.include_router(analytics.router, prefix="/api")
app.include_router(predictions.router, prefix="/api")
app.include_router(ai.router, prefix="/api")
app.include_router(system.router, prefix="/api")
app.include_router(upload.router, prefix="/api")

# Mount Static Frontend
if os.path.exists(FRONTEND_ROOT):
    app.mount("/", StaticFiles(directory=str(FRONTEND_ROOT), html=True), name="frontend")

if __name__ == "__main__":
    import uvicorn
    from app.config import API_HOST, API_PORT
    uvicorn.run("app.main:app", host=API_HOST, port=API_PORT, reload=DEBUG)
