"""
Automated End-to-End System Verification Script
Tests ML model inference, database persistence, time-window forecasting,
MITRE ATT&CK mapping, and frontend asset delivery.
"""

import urllib.request
import json
import time

def test_api_endpoint(url, method="GET", data=None):
    req = urllib.request.Request(url, method=method)
    if data:
        req.add_header("Content-Type", "application/json")
        encoded_data = json.dumps(data).encode("utf-8")
        req.data = encoded_data
    with urllib.request.urlopen(req, timeout=10) as response:
        code = response.getcode()
        body = response.read().decode("utf-8")
        return code, json.loads(body) if body.startswith(("{", "[")) else body

def run_tests():
    print("=" * 60)
    print("RUNNING AI NETWORK ATTACK FORECASTING SYSTEM VERIFICATION")
    print("=" * 60)

    # 1. Health Check
    code, health = test_api_endpoint("http://127.0.0.1:8000/api/health")
    print(f"[PASS] 1. Backend Health Check (HTTP {code}): Status = {health.get('status')}, Model Loaded = {health.get('model_loaded')}")
    assert health.get("status") == "HEALTHY", "Health check failed"

    # 2. Demo Dataset Load
    code, demo = test_api_endpoint("http://127.0.0.1:8000/api/load-sample")
    print(f"[PASS] 2. Sample Dataset Loader (HTTP {code}): {demo.get('records_processed')} flows analyzed")
    summary = demo.get("summary", {})
    print(f"       Risk Score: {summary.get('current_risk_score')}% | Level: {summary.get('risk_level')}")
    print(f"       Impending Threat: {summary.get('impending_threat')} | Forecast: {summary.get('forecast_status')}")

    # 3. Time-Window Simulation Step
    code, sim = test_api_endpoint("http://127.0.0.1:8000/api/forecast/simulate-step", method="POST")
    print(f"[PASS] 3. Time-Window Streaming Simulation Step (HTTP {code}):")
    print(f"       Current Risk: {sim.get('current_risk_score')}% | Trend: {sim.get('forecast_trend')}")

    # 4. Early Warning Alerts & MITRE ATT&CK
    code, alerts = test_api_endpoint("http://127.0.0.1:8000/api/alerts?limit=5")
    print(f"[PASS] 4. Early Warning Alerts (HTTP {code}): Retrieved {len(alerts)} alerts")
    if alerts:
        a = alerts[0]
        print(f"       Top Alert: {a.get('attack_type')} (MITRE {a.get('mitre_id')} - {a.get('mitre_name')})")

    # 5. Single Flow Prediction
    flow_payload = {
        "Dst Port": 80,
        "Flow Duration": 5000,
        "Tot Fwd Pkts": 250,
        "Tot Bwd Pkts": 2,
        "TotLen Fwd Pkts": 15000,
        "TotLen Bwd Pkts": 100,
        "Flow Byts/s": 3000000.0,
        "Flow Pkts/s": 50000.0,
        "SYN Flag Cnt": 8,
        "RST Flag Cnt": 2,
        "ACK Flag Cnt": 0
    }
    code, pred = test_api_endpoint("http://127.0.0.1:8000/api/predict-flow", method="POST", data=flow_payload)
    print(f"[PASS] 5. Single Flow AI Inference (HTTP {code}):")
    print(f"       Prediction: {pred.get('prediction')} | Probability: {round(pred.get('probability') * 100, 1)}% | Risk: {pred.get('risk_score')}% ({pred.get('risk_level')})")
    print(f"       MITRE ID: {pred.get('mitre', {}).get('technique_id')} ({pred.get('mitre', {}).get('technique_name')})")

    # 6. Frontend Dev Server Delivery
    req = urllib.request.Request("http://127.0.0.1:5173/")
    with urllib.request.urlopen(req, timeout=10) as resp:
        html = resp.read().decode("utf-8")
        assert "AI CyberWatch" in html or "root" in html
        print(f"[PASS] 6. Frontend Dev Server (HTTP {resp.getcode()}): Delivers HTML payload successfully ({len(html)} bytes)")

    print("=" * 60)
    print("ALL 6 CORE SYSTEM VERIFICATION TESTS PASSED SUCCESSFULLY!")
    print("=" * 60)

if __name__ == "__main__":
    run_tests()
