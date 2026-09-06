"""
Security Alerts & Early Warning Routes
"""

from typing import List
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import SecurityAlert
from app.schemas import AlertResponse
from app.ml.mitre_mapper import MITRE_ATTACK_MAPPING

router = APIRouter(prefix="/api/alerts", tags=["Security Alerts & Early Warnings"])

@router.get("", response_model=List[AlertResponse])
async def get_recent_alerts(limit: int = 20, db: Session = Depends(get_db)):
    """Retrieve security alerts and early warnings from database."""
    alerts = db.query(SecurityAlert).order_by(SecurityAlert.timestamp.desc()).limit(limit).all()
    
    return [
        AlertResponse(
            id=a.id,
            timestamp=a.timestamp.strftime("%Y-%m-%d %H:%M:%S"),
            attack_type=a.attack_type,
            severity=a.severity,
            mitre_id=a.mitre_id,
            mitre_name=a.mitre_name,
            alert_message=a.alert_message,
            recommended_action=a.recommended_action,
            status=a.status
        )
        for a in alerts
    ]

@router.get("/mitre-matrix")
async def get_mitre_matrix():
    """Returns the MITRE ATT&CK mapping database for all supported attack categories."""
    return MITRE_ATTACK_MAPPING
