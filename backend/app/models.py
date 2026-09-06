from datetime import datetime
from sqlalchemy import Column, Integer, String, Float, DateTime, Text
from app.database import Base

class PredictionRecord(Base):
    __tablename__ = "prediction_history"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)
    src_ip = Column(String(45), default="192.168.1.100")
    dst_port = Column(Integer, nullable=False)
    flow_duration = Column(Integer, default=0)
    tot_fwd_pkts = Column(Integer, default=0)
    tot_bwd_pkts = Column(Integer, default=0)
    attack_type = Column(String(64), nullable=False, index=True)
    probability = Column(Float, nullable=False)
    risk_score = Column(Float, nullable=False)
    risk_level = Column(String(16), nullable=False, index=True)
    forecast_status = Column(String(128), nullable=False)
    recommended_action = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)

class SecurityAlert(Base):
    __tablename__ = "security_alerts"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)
    attack_type = Column(String(64), nullable=False)
    severity = Column(String(16), nullable=False, index=True)
    mitre_id = Column(String(32), nullable=False)
    mitre_name = Column(String(128), nullable=False)
    alert_message = Column(Text, nullable=False)
    recommended_action = Column(Text, nullable=False)
    status = Column(String(32), default="ACTIVE")
    created_at = Column(DateTime, default=datetime.utcnow)

class TrafficWindowStat(Base):
    __tablename__ = "traffic_window_stats"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)
    window_size_flows = Column(Integer, default=15)
    total_flows = Column(Integer, nullable=False)
    benign_count = Column(Integer, default=0)
    suspicious_count = Column(Integer, default=0)
    attack_count = Column(Integer, default=0)
    avg_risk_score = Column(Float, nullable=False)
    top_threat = Column(String(64), default="None")
    forecast_trend = Column(String(64), default="STABLE")
    created_at = Column(DateTime, default=datetime.utcnow)
