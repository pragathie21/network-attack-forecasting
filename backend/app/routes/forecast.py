"""
Forecasting and Simulation Routes
"""

import random
from datetime import datetime, timedelta
import pandas as pd
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import PredictionRecord
from app.schemas import WindowForecastSummary
from app.ml.predictor import predictor
from app.ml.window_analyzer import analyze_traffic_windows
from ml_pipeline.generate_dataset import generate_flow_record

router = APIRouter(prefix="/api/forecast", tags=["Attack Forecasting"])

# In-memory buffer for real-time streaming simulation
SIMULATION_BUFFER: list[dict] = []
SIMULATION_STATE = {
    "step": 0,
    "phase": "Baseline", # Baseline -> Reconnaissance -> Attack -> Cooldown
    "attack_target": "DDoS"
}

@router.get("/current", response_model=WindowForecastSummary)
async def get_current_forecast(db: Session = Depends(get_db)):
    """Retrieve current time-window forecasting status and metrics."""
    global SIMULATION_BUFFER
    
    if not SIMULATION_BUFFER:
        # If simulation buffer is empty, query last 30 records from DB
        db_records = db.query(PredictionRecord).order_by(PredictionRecord.timestamp.desc()).limit(30).all()
        if db_records:
            flow_results = [
                {
                    "prediction": r.attack_type,
                    "probability": r.probability,
                    "risk_score": r.risk_score,
                    "risk_level": r.risk_level,
                    "forecast": r.forecast_status,
                    "recommended_action": r.recommended_action,
                    "timestamp": r.timestamp.strftime("%Y-%m-%d %H:%M:%S")
                }
                for r in reversed(db_records)
            ]
            summary = analyze_traffic_windows(flow_results)
            return WindowForecastSummary(**summary)
            
    summary = analyze_traffic_windows(SIMULATION_BUFFER)
    return WindowForecastSummary(**summary)

@router.post("/simulate-step", response_model=WindowForecastSummary)
async def simulate_live_traffic_step(db: Session = Depends(get_db)):
    """
    Advances real-time simulation by generating a small batch of flows,
    demonstrating the progression:
    Phase 1: Baseline (Low Risk ~10-25%)
    Phase 2: Early Reconnaissance / Probing (Medium Risk ~35-65%)
    Phase 3: High-Intensity Attack Wave (High Risk ~85-98%)
    Phase 4: Cooldown & Mitigation (Risk returning to Low)
    """
    global SIMULATION_BUFFER, SIMULATION_STATE
    
    SIMULATION_STATE["step"] += 1
    step = SIMULATION_STATE["step"]
    
    # Determine phase based on step
    if step <= 3:
        phase = "Baseline"
        labels = ["Benign"] * 6
    elif step <= 7:
        phase = "Reconnaissance"
        labels = ["Infiltration", "Botnet", "Benign", "Benign", "Infiltration", "Benign"]
    elif step <= 13:
        phase = "Active Attack Wave"
        attack = SIMULATION_STATE["attack_target"]
        labels = [attack, attack, attack, "DoS" if attack == "DDoS" else "DDoS", attack, "Benign"]
    else:
        phase = "Cooldown"
        labels = ["Benign"] * 6
        if step >= 16:
            # Cycle simulation with a different attack next time
            SIMULATION_STATE["step"] = 0
            SIMULATION_STATE["attack_target"] = random.choice(["DDoS", "Brute Force", "Web Attack", "Botnet"])

    SIMULATION_STATE["phase"] = phase
    
    # Generate records
    new_records = []
    base_time = datetime.now() - timedelta(seconds=len(labels) * 2)
    for lbl in labels:
        base_time += timedelta(seconds=random.uniform(0.2, 1.5))
        new_records.append(generate_flow_record(lbl, base_time))
        
    df_step = pd.DataFrame(new_records)
    step_results = predictor.predict_batch_df(df_step)
    
    # Append to rolling buffer (keep last 60 flows)
    SIMULATION_BUFFER.extend(step_results)
    if len(SIMULATION_BUFFER) > 70:
        SIMULATION_BUFFER = SIMULATION_BUFFER[-70:]
        
    summary = analyze_traffic_windows(SIMULATION_BUFFER)
    return WindowForecastSummary(**summary)

@router.post("/reset")
async def reset_simulation():
    """Reset the live simulation stream."""
    global SIMULATION_BUFFER, SIMULATION_STATE
    SIMULATION_BUFFER.clear()
    SIMULATION_STATE["step"] = 0
    SIMULATION_STATE["phase"] = "Baseline"
    return {"message": "Simulation stream reset to baseline state."}
