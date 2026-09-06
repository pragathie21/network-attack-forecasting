"""
Prediction & Traffic Upload Routes
"""

import io
from datetime import datetime
import pandas as pd
from fastapi import APIRouter, Depends, UploadFile, File, HTTPException
from sqlalchemy.orm import Session

from app.config import settings
from app.database import get_db
from app.models import PredictionRecord, SecurityAlert
from app.schemas import (
    FlowFeatures, 
    FlowPredictionResponse, 
    UploadResponse, 
    WindowForecastSummary
)
from app.ml.predictor import predictor
from app.ml.window_analyzer import analyze_traffic_windows

router = APIRouter(prefix="/api", tags=["Prediction & Traffic Analysis"])

@router.post("/predict-flow", response_model=FlowPredictionResponse)
async def predict_single_flow(flow: FlowFeatures, db: Session = Depends(get_db)):
    """Analyze a single network flow in real-time."""
    try:
        flow_dict = flow.model_dump(by_alias=True)
        result = predictor.predict_single(flow_dict)
        now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        # Persist record in database
        db_record = PredictionRecord(
            timestamp=datetime.now(),
            dst_port=flow.dst_port,
            flow_duration=flow.flow_duration,
            tot_fwd_pkts=flow.tot_fwd_pkts,
            tot_bwd_pkts=flow.tot_bwd_pkts,
            attack_type=result["prediction"],
            probability=result["probability"],
            risk_score=result["risk_score"],
            risk_level=result["risk_level"],
            forecast_status=result["forecast"],
            recommended_action=result["recommended_action"]
        )
        db.add(db_record)
        
        # If attack or high risk, persist security alert
        if result["prediction"] != "Benign" or result["risk_score"] >= settings.RISK_THRESHOLD_HIGH:
            mitre = result["mitre"]
            db_alert = SecurityAlert(
                timestamp=datetime.now(),
                attack_type=result["prediction"],
                severity=result["risk_level"],
                mitre_id=mitre["technique_id"] if mitre else "T1000",
                mitre_name=mitre["technique_name"] if mitre else "Suspicious Anomaly",
                alert_message=f"Individual flow signature matched {result['prediction']} ({result['risk_score']}% risk).",
                recommended_action=result["recommended_action"]
            )
            db.add(db_alert)
            
        db.commit()
        
        return FlowPredictionResponse(
            prediction=result["prediction"],
            probability=result["probability"],
            risk_score=result["risk_score"],
            risk_level=result["risk_level"],
            forecast=result["forecast"],
            recommended_action=result["recommended_action"],
            mitre=result["mitre"],
            timestamp=now_str
        )
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"Prediction error: {str(e)}")

@router.post("/upload-traffic", response_model=UploadResponse)
async def upload_traffic_csv(file: UploadFile = File(...), db: Session = Depends(get_db)):
    """Upload network traffic CSV, process flows, compute window forecasting & save to DB."""
    if not file.filename.lower().endswith(".csv"):
        raise HTTPException(status_code=400, detail="Only CSV files are supported.")

    try:
        content = await file.read()
        if not content or len(content.strip()) == 0:
            raise HTTPException(status_code=400, detail="Uploaded CSV file is empty.")

        try:
            df = pd.read_csv(io.BytesIO(content))
        except (pd.errors.EmptyDataError, pd.errors.ParserError) as pe:
            raise HTTPException(status_code=400, detail=f"Invalid CSV structure: {str(pe)}")
        
        if df.empty or len(df) == 0:
            raise HTTPException(status_code=400, detail="Uploaded CSV file contains no records.")

        # Batch prediction
        results = predictor.predict_batch_df(df)
        summary_dict = analyze_traffic_windows(results)
        
        # Persist a batch sample into DB (up to 100 flows to keep DB light and responsive)
        for item in results[:100]:
            rec = PredictionRecord(
                timestamp=datetime.now(),
                dst_port=item["dst_port"],
                attack_type=item["prediction"],
                probability=item["probability"],
                risk_score=item["risk_score"],
                risk_level=item["risk_level"],
                forecast_status=item["forecast"],
                recommended_action=item["recommended_action"]
            )
            db.add(rec)
            
        # Persist generated alerts
        for alert in summary_dict.get("recent_alerts", []):
            db_alert = SecurityAlert(
                timestamp=datetime.now(),
                attack_type=alert["attack_type"],
                severity=alert["severity"],
                mitre_id=alert["mitre_id"],
                mitre_name=alert["mitre_name"],
                alert_message=alert["alert_message"],
                recommended_action=alert["recommended_action"]
            )
            db.add(db_alert)
            
        db.commit()
        
        return UploadResponse(
            message="Traffic dataset processed successfully.",
            filename=file.filename,
            records_processed=len(df),
            summary=WindowForecastSummary(**summary_dict)
        )
    except HTTPException:
        db.rollback()
        raise
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"Failed to process traffic CSV: {str(e)}")

@router.get("/load-sample", response_model=UploadResponse)
async def load_sample_dataset(db: Session = Depends(get_db)):
    """Instant 1-click demo loader for pre-packaged CIC-IDS2018 sample dataset."""
    sample_path = settings.SAMPLE_TEST_CSV
    if not sample_path.exists():
        from ml_pipeline.generate_dataset import generate_sample_test_traffic
        generate_sample_test_traffic(str(sample_path))

    try:
        df = pd.read_csv(sample_path)
        results = predictor.predict_batch_df(df)
        summary_dict = analyze_traffic_windows(results)
        
        # Persist to DB
        for item in results[:85]:
            rec = PredictionRecord(
                timestamp=datetime.now(),
                dst_port=item["dst_port"],
                attack_type=item["prediction"],
                probability=item["probability"],
                risk_score=item["risk_score"],
                risk_level=item["risk_level"],
                forecast_status=item["forecast"],
                recommended_action=item["recommended_action"]
            )
            db.add(rec)
            
        for alert in summary_dict.get("recent_alerts", []):
            db_alert = SecurityAlert(
                timestamp=datetime.now(),
                attack_type=alert["attack_type"],
                severity=alert["severity"],
                mitre_id=alert["mitre_id"],
                mitre_name=alert["mitre_name"],
                alert_message=alert["alert_message"],
                recommended_action=alert["recommended_action"]
            )
            db.add(db_alert)
            
        db.commit()
        
        return UploadResponse(
            message="Pre-packaged CIC-IDS2018 demonstration dataset loaded.",
            filename="sample_cicids2018_test.csv",
            records_processed=len(df),
            summary=WindowForecastSummary(**summary_dict)
        )
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"Failed to load sample dataset: {str(e)}")
