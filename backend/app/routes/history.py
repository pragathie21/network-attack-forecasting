"""
Historical Queries & Aggregate Traffic Statistics
"""

from datetime import datetime
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from sqlalchemy import func

from app.database import get_db
from app.models import PredictionRecord
from app.schemas import TrafficStatsOverview

router = APIRouter(prefix="/api", tags=["Traffic Analytics & History"])

@router.get("/traffic-stats", response_model=TrafficStatsOverview)
async def get_traffic_stats(db: Session = Depends(get_db)):
    """Retrieve global traffic metrics for dashboard overview cards."""
    total_records = db.query(func.count(PredictionRecord.id)).scalar() or 0
    normal_count = db.query(func.count(PredictionRecord.id)).filter(PredictionRecord.attack_type == "Benign").scalar() or 0
    attack_count = total_records - normal_count
    
    # Suspicious count: medium risk flows
    suspicious_count = db.query(func.count(PredictionRecord.id)).filter(
        PredictionRecord.risk_level == "MEDIUM"
    ).scalar() or 0

    # Latest record for current risk
    latest = db.query(PredictionRecord).order_by(PredictionRecord.timestamp.desc()).first()
    
    if latest:
        current_risk = latest.risk_score
        risk_level = latest.risk_level
        active_threat = latest.attack_type if latest.attack_type != "Benign" else "None"
        forecast = latest.forecast_status
    else:
        current_risk = 12.0
        risk_level = "LOW"
        active_threat = "None"
        forecast = "Normal traffic. System awaiting flow telemetry."

    network_status = "PROTECTED" if risk_level == "LOW" else ("ELEVATED" if risk_level == "MEDIUM" else "UNDER ATTACK")

    return TrafficStatsOverview(
        network_status=network_status,
        total_traffic_records=total_records,
        normal_traffic=normal_count,
        suspicious_traffic=suspicious_count,
        predicted_attacks=attack_count,
        current_risk_score=current_risk,
        risk_level=risk_level,
        active_threat=active_threat,
        forecast=forecast,
        last_updated=datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    )

@router.get("/history")
async def get_prediction_history(limit: int = 50, db: Session = Depends(get_db)):
    """Retrieve detailed tabular logs of analyzed traffic flows."""
    records = db.query(PredictionRecord).order_by(PredictionRecord.timestamp.desc()).limit(limit).all()
    
    return [
        {
            "id": r.id,
            "timestamp": r.timestamp.strftime("%Y-%m-%d %H:%M:%S"),
            "dst_port": r.dst_port,
            "attack_type": r.attack_type,
            "probability": r.probability,
            "risk_score": r.risk_score,
            "risk_level": r.risk_level,
            "forecast_status": r.forecast_status,
            "recommended_action": r.recommended_action
        }
        for r in records
    ]
