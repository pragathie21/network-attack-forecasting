"""
Time-Window Trend Analysis & Attack Forecasting Engine
Computes sliding-window anomaly metrics, risk acceleration, early-warning triggers,
and forecasts attack trajectories before full escalation.
"""

from collections import Counter
from datetime import datetime
from app.config import settings
from app.ml.mitre_mapper import get_mitre_mapping

def analyze_traffic_windows(flow_results: list[dict], window_size: int = None) -> dict:
    """
    Analyzes a sequence of flow prediction results using sliding time-windows
    to generate attack forecasting trends, trajectory, and early-warning alerts.
    """
    if not flow_results:
        return _empty_window_summary()

    if window_size is None:
        window_size = settings.WINDOW_SIZE_FLOWS

    total_records = len(flow_results)
    
    # Classify each flow into Normal / Suspicious / Attack
    normal_count = 0
    suspicious_count = 0
    attack_count = 0
    attack_distribution = Counter()
    
    for item in flow_results:
        pred = item["prediction"]
        risk = item["risk_score"]
        
        if pred == "Benign":
            if risk > 25.0:
                suspicious_count += 1
            else:
                normal_count += 1
        else:
            attack_count += 1
            attack_distribution[pred] += 1
            if risk < settings.RISK_THRESHOLD_HIGH:
                suspicious_count += 1

    # Segment into chronological time-series points for dashboard charting
    chunk_size = max(1, total_records // 12) if total_records > 12 else 1
    time_series = []
    
    for i in range(0, total_records, chunk_size):
        chunk = flow_results[i : i + chunk_size]
        chunk_normal = sum(1 for c in chunk if c["prediction"] == "Benign")
        chunk_attack = len(chunk) - chunk_normal
        avg_risk = round(sum(c["risk_score"] for c in chunk) / len(chunk), 1)
        
        # Most frequent attack in this window chunk
        threat_counter = Counter(c["prediction"] for c in chunk if c["prediction"] != "Benign")
        top_chunk_threat = threat_counter.most_common(1)[0][0] if threat_counter else "Benign"
        
        time_label = chunk[0].get("timestamp", f"T+{i}")
        if len(time_label) > 10 and " " in time_label:
            time_label = time_label.split(" ")[1] # Keep HH:MM:SS
            
        time_series.append({
            "time": time_label,
            "total_flows": len(chunk),
            "normal_flows": chunk_normal,
            "attack_flows": chunk_attack,
            "risk_score": avg_risk,
            "threat": top_chunk_threat
        })

    # Recent window analysis (the last window_size flows)
    recent_flows = flow_results[-window_size:] if total_records >= window_size else flow_results
    recent_risks = [f["risk_score"] for f in recent_flows]
    current_risk_score = round(sum(recent_risks) / len(recent_risks), 1)
    
    # Calculate risk trajectory / acceleration
    if len(time_series) >= 2:
        prev_risk = time_series[-2]["risk_score"]
        curr_chunk_risk = time_series[-1]["risk_score"]
        delta_risk = curr_chunk_risk - prev_risk
        
        if delta_risk > 15:
            forecast_trend = "SURGING"
        elif delta_risk > 4:
            forecast_trend = "RISING"
        elif delta_risk < -8:
            forecast_trend = "DECLINING"
        else:
            forecast_trend = "STABLE"
    else:
        forecast_trend = "STABLE"

    # Identify dominant impending threat
    recent_threats = Counter(f["prediction"] for f in recent_flows if f["prediction"] != "Benign")
    if recent_threats:
        impending_threat = recent_threats.most_common(1)[0][0]
        confidence = round(recent_threats[impending_threat] / len(recent_flows), 2)
    elif attack_distribution:
        impending_threat = attack_distribution.most_common(1)[0][0]
        confidence = round(attack_distribution[impending_threat] / total_records, 2)
    else:
        impending_threat = "None (Traffic Nominal)"
        confidence = 0.95

    # Determine Forecasting Status & Early Warning Alert
    if current_risk_score >= settings.RISK_THRESHOLD_HIGH:
        risk_level = "HIGH"
        forecast_status = f"CRITICAL FORECAST: Active/Imminent {impending_threat} Attack Escalation"
        early_warning_alert = (
            f"HIGH RISK DETECTED ({current_risk_score}%): Impending {impending_threat} attack "
            f"detected in sliding time-window. Anomaly velocity indicates high-impact denial or breach phase."
        )
        recommended_action = get_mitre_mapping(impending_threat)["recommended_action"]
    elif current_risk_score >= settings.RISK_THRESHOLD_MEDIUM:
        risk_level = "MEDIUM"
        forecast_status = f"EARLY WARNING: Suspicious {impending_threat} Signature Rising"
        early_warning_alert = (
            f"SUSPICIOUS TRAFFIC DETECTED ({current_risk_score}%): Flow rates and payload metrics "
            f"deviate from baseline. Pre-attack probing / reconnaissance identified."
        )
        recommended_action = (
            f"Preemptively rate-limit originating subnet; inspect {impending_threat} telemetry "
            f"and alert SOC Level-2 analyst."
        )
    else:
        risk_level = "LOW"
        forecast_status = "NORMAL: Traffic Baseline Within Operating Boundaries"
        early_warning_alert = None
        recommended_action = "Routine passive monitoring; maintain standard telemetry retention."

    # Generate Alerts List for UI
    recent_alerts = []
    alert_id = 1
    # Check if we should synthesize alerts for high/medium attacks observed
    for attack_type, count in attack_distribution.items():
        mitre = get_mitre_mapping(attack_type)
        severity = "HIGH" if current_risk_score >= settings.RISK_THRESHOLD_HIGH else "MEDIUM"
        recent_alerts.append({
            "id": alert_id,
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "attack_type": attack_type,
            "severity": severity,
            "mitre_id": mitre["technique_id"],
            "mitre_name": mitre["technique_name"],
            "alert_message": f"Time-window detected {count} anomalous flows matching {attack_type} signature ({mitre['technique_id']}).",
            "recommended_action": mitre["recommended_action"],
            "status": "ACTIVE"
        })
        alert_id += 1

    return {
        "window_size": window_size,
        "total_records": total_records,
        "normal_traffic": normal_count,
        "suspicious_traffic": suspicious_count,
        "predicted_attacks": attack_count,
        "current_risk_score": current_risk_score,
        "risk_level": risk_level,
        "forecast_status": forecast_status,
        "forecast_trend": forecast_trend,
        "impending_threat": impending_threat,
        "confidence": confidence,
        "early_warning_alert": early_warning_alert,
        "recommended_action": recommended_action,
        "attack_distribution": dict(attack_distribution),
        "time_series": time_series,
        "recent_alerts": recent_alerts
    }

def _empty_window_summary() -> dict:
    return {
        "window_size": 15,
        "total_records": 0,
        "normal_traffic": 0,
        "suspicious_traffic": 0,
        "predicted_attacks": 0,
        "current_risk_score": 5.0,
        "risk_level": "LOW",
        "forecast_status": "System initialized. Awaiting network traffic ingestion.",
        "forecast_trend": "STABLE",
        "impending_threat": "None",
        "confidence": 1.0,
        "early_warning_alert": None,
        "recommended_action": "System standby. Upload CSV or start live stream simulation.",
        "attack_distribution": {},
        "time_series": [],
        "recent_alerts": []
    }
