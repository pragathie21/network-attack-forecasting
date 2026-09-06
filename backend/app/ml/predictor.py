"""
AI/ML Predictor & Risk Scoring Engine
Executes model inference, computes probabilities, calculates risk score,
and evaluates proactive attack forecast status.
"""

import os
import joblib
import logging
import numpy as np
import pandas as pd
from app.config import settings
from app.ml.preprocessor import load_feature_columns, preprocess_dataframe
from app.ml.mitre_mapper import get_mitre_mapping

logger = logging.getLogger("uvicorn.error")

class AttackPredictor:
    def __init__(self):
        self.model = None
        self.scaler = None
        self.label_encoder = None
        self.feature_columns = None
        self.is_loaded = False
        self._load_artifacts()

    def _load_artifacts(self):
        try:
            if settings.MODEL_PATH.exists() and settings.SCALER_PATH.exists() and settings.LABEL_ENCODER_PATH.exists():
                self.model = joblib.load(settings.MODEL_PATH)
                self.scaler = joblib.load(settings.SCALER_PATH)
                self.label_encoder = joblib.load(settings.LABEL_ENCODER_PATH)
                self.feature_columns = load_feature_columns()
                self.is_loaded = True
                logger.info("ML artifacts loaded successfully.")
            else:
                logger.warning("ML artifacts not found. Will load on demand once trained.")
        except Exception as e:
            logger.error(f"Error loading ML artifacts: {e}")

    def ensure_loaded(self):
        if not self.is_loaded:
            self._load_artifacts()
            if not self.is_loaded:
                raise RuntimeError("ML Model is not trained yet. Please run training pipeline.")

    def compute_risk_score(self, prediction: str, prob_dict: dict) -> tuple[float, str, str, str]:
        """
        Calculate calibrated risk score (0-100), risk level (LOW/MEDIUM/HIGH),
        forecast status, and recommended defensive action.
        """
        benign_prob = prob_dict.get("Benign", 0.0)
        attack_prob = 1.0 - benign_prob
        
        if prediction == "Benign":
            # Normal baseline risk: 5% - 28%
            risk_score = round(max(5.0, (1.0 - benign_prob) * 60.0), 1)
            risk_level = "LOW"
            forecast = "Normal baseline operations"
            action = "Routine passive monitoring; maintain standard telemetry retention."
        else:
            # Active or developing attack
            pred_prob = prob_dict.get(prediction, attack_prob)
            
            # Severity weighting
            severity_weights = {
                "DDoS": 1.0,
                "DoS": 0.92,
                "Brute Force": 0.88,
                "Botnet": 0.95,
                "Infiltration": 0.93,
                "Web Attack": 0.90,
            }
            weight = severity_weights.get(prediction, 0.85)
            
            # Calibrated score 45% - 99%
            raw_score = (45.0 + (pred_prob * 50.0)) * weight
            risk_score = round(min(99.0, max(30.0, raw_score)), 1)
            
            if risk_score >= settings.RISK_THRESHOLD_HIGH:
                risk_level = "HIGH"
                forecast = "Cyber attack likely or underway. Immediate preventive action recommended."
            elif risk_score >= settings.RISK_THRESHOLD_MEDIUM:
                risk_level = "MEDIUM"
                forecast = "Suspicious traffic detected. Possible attack reconnaissance or early ramp-up."
            else:
                risk_level = "LOW"
                forecast = "Minor anomaly detected, but confidence remains low."
                
            mitre = get_mitre_mapping(prediction)
            action = mitre.get("recommended_action", "Investigate origin IP and restrict traffic.")

        return risk_score, risk_level, forecast, action

    def predict_single(self, flow_data: dict) -> dict:
        """Run prediction on a single network flow record."""
        self.ensure_loaded()
        df = pd.DataFrame([flow_data])
        df_proc = preprocess_dataframe(df, self.feature_columns)
        X_scaled = self.scaler.transform(df_proc)
        
        # Predict class & probabilities
        pred_idx = self.model.predict(X_scaled)[0]
        prediction = str(self.label_encoder.inverse_transform([pred_idx])[0])
        probabilities = self.model.predict_proba(X_scaled)[0]
        
        prob_dict = {
            str(cls_name): round(float(prob), 4)
            for cls_name, prob in zip(self.label_encoder.classes_, probabilities)
        }
        
        highest_prob = prob_dict[prediction]
        risk_score, risk_level, forecast, action = self.compute_risk_score(prediction, prob_dict)
        mitre = get_mitre_mapping(prediction)
        
        return {
            "prediction": prediction,
            "probability": highest_prob,
            "probabilities": prob_dict,
            "risk_score": risk_score,
            "risk_level": risk_level,
            "forecast": forecast,
            "recommended_action": action,
            "mitre": mitre
        }

    def predict_batch_df(self, df: pd.DataFrame) -> list[dict]:
        """Run batch prediction on a DataFrame of flow records."""
        self.ensure_loaded()
        df_proc = preprocess_dataframe(df, self.feature_columns)
        X_scaled = self.scaler.transform(df_proc)
        
        pred_indices = self.model.predict(X_scaled)
        predictions = self.label_encoder.inverse_transform(pred_indices)
        all_probs = self.model.predict_proba(X_scaled)
        classes = [str(c) for c in self.label_encoder.classes_]
        
        results = []
        for i, (pred, probs) in enumerate(zip(predictions, all_probs)):
            prob_dict = {cls_name: round(float(p), 4) for cls_name, p in zip(classes, probs)}
            risk_score, risk_level, forecast, action = self.compute_risk_score(pred, prob_dict)
            mitre = get_mitre_mapping(pred)
            
            # Flow metadata
            dst_port = int(df.iloc[i].get("Dst Port", 80)) if "Dst Port" in df.columns else 80
            timestamp = str(df.iloc[i].get("Timestamp", f"2026-09-06 20:{i:02d}:00"))
            
            results.append({
                "index": i,
                "timestamp": timestamp,
                "dst_port": dst_port,
                "prediction": str(pred),
                "probability": prob_dict[str(pred)],
                "probabilities": prob_dict,
                "risk_score": risk_score,
                "risk_level": risk_level,
                "forecast": forecast,
                "recommended_action": action,
                "mitre": mitre
            })
            
        return results

predictor = AttackPredictor()
