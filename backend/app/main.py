"""
AI-Based Network Attack Forecasting System - FastAPI Application
"""

import logging
from pathlib import Path
from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse

from app.config import settings
from app.database import init_db
from app.ml.predictor import predictor
from app.routes import prediction, forecast, alerts, history

logger = logging.getLogger("uvicorn.error")

@asynccontextmanager
async def lifespan(app: FastAPI):
    # 1. Initialize DB schema (SQLite or MySQL)
    init_db()
    
    # 2. Check if ML models are trained; if not, train automatically
    if not settings.MODEL_PATH.exists():
        logger.info("ML model artifacts not found. Initiating automated training pipeline...")
        try:
            from ml_pipeline.train_model import train
            train()
            predictor.ensure_loaded()
            logger.info("Automated model training completed.")
        except Exception as e:
            logger.error(f"Failed to auto-train model: {e}")
    else:
        predictor.ensure_loaded()
        
    yield
    logger.info("Shutting down AI Network Attack Forecasting API.")

app = FastAPI(
    title=settings.APP_NAME,
    version=settings.APP_VERSION,
    description="Proactive AI cybersecurity system forecasting network attacks from CIC-IDS2018 traffic data.",
    lifespan=lifespan
)

# Enable CORS for frontend dashboard
cors_origins_raw = settings.CORS_ORIGINS.strip()
if cors_origins_raw == "*":
    origins = ["*"]
    allow_creds = False
else:
    origins = [orig.strip() for orig in cors_origins_raw.split(",") if orig.strip()]
    allow_creds = True

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=allow_creds,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Register API routes
app.include_router(prediction.router)
app.include_router(forecast.router)
app.include_router(alerts.router)
app.include_router(history.router)

@app.get("/api/health")
async def health_check():
    return {
        "status": "HEALTHY",
        "model_loaded": predictor.is_loaded,
        "database": "CONNECTED",
        "database_url": settings.DATABASE_URL.split("@")[-1] if "@" in settings.DATABASE_URL else "local",
        "supported_attacks": [
            "Benign", "DDoS", "DoS", "Brute Force", 
            "Botnet", "Infiltration", "Web Attack"
        ]
    }

# Mount Compiled Frontend (Single-Port Unified Deployment)
FRONTEND_DIST = Path(__file__).resolve().parent.parent.parent / "frontend" / "dist"

if FRONTEND_DIST.exists():
    assets_dir = FRONTEND_DIST / "assets"
    if assets_dir.exists():
        app.mount("/assets", StaticFiles(directory=str(assets_dir)), name="assets")

    @app.get("/{full_path:path}")
    async def serve_spa(full_path: str):
        # Don't hijack API routes or docs
        if full_path.startswith("api") or full_path.startswith("docs") or full_path.startswith("openapi"):
            return None
        file_path = FRONTEND_DIST / full_path
        if file_path.is_file():
            return FileResponse(str(file_path))
        index_file = FRONTEND_DIST / "index.html"
        return FileResponse(str(index_file))
else:
    @app.get("/")
    async def root():
        return {
            "system": settings.APP_NAME,
            "version": settings.APP_VERSION,
            "status": "OPERATIONAL",
            "docs_url": "/docs",
            "message": "AI Network Attack Forecasting Backend is running."
        }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app.main:app", host="0.0.0.0", port=8000, reload=True)
