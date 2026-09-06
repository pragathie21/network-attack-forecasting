from datetime import datetime
from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field

class MitreInfo(BaseModel):
    technique_id: str
    technique_name: str
    tactic: str
    description: str
    recommended_action: str

class FlowFeatures(BaseModel):
    dst_port: int = Field(80, alias="Dst Port")
    flow_duration: int = Field(100000, alias="Flow Duration")
    tot_fwd_pkts: int = Field(10, alias="Tot Fwd Pkts")
    tot_bwd_pkts: int = Field(8, alias="Tot Bwd Pkts")
    tot_len_fwd: int = Field(800, alias="TotLen Fwd Pkts")
    tot_len_bwd: int = Field(1200, alias="TotLen Bwd Pkts")
    fwd_pkt_len_max: Optional[int] = Field(200, alias="Fwd Pkt Len Max")
    fwd_pkt_len_min: Optional[int] = Field(40, alias="Fwd Pkt Len Min")
    fwd_pkt_len_mean: Optional[float] = Field(80.0, alias="Fwd Pkt Len Mean")
    bwd_pkt_len_mean: Optional[float] = Field(150.0, alias="Bwd Pkt Len Mean")
    flow_byts_s: Optional[float] = Field(20000.0, alias="Flow Byts/s")
    flow_pkts_s: Optional[float] = Field(180.0, alias="Flow Pkts/s")
    flow_iat_mean: Optional[float] = Field(5000.0, alias="Flow IAT Mean")
    flow_iat_std: Optional[float] = Field(1200.0, alias="Flow IAT Std")
    flow_iat_max: Optional[float] = Field(15000.0, alias="Flow IAT Max")
    flow_iat_min: Optional[float] = Field(200.0, alias="Flow IAT Min")
    fwd_iat_tot: Optional[float] = Field(50000.0, alias="Fwd IAT Tot")
    bwd_iat_tot: Optional[float] = Field(40000.0, alias="Bwd IAT Tot")
    fwd_header_len: Optional[int] = Field(200, alias="Fwd Header Len")
    bwd_header_len: Optional[int] = Field(160, alias="Bwd Header Len")
    fwd_pkts_s: Optional[float] = Field(100.0, alias="Fwd Pkts/s")
    bwd_pkts_s: Optional[float] = Field(80.0, alias="Bwd Pkts/s")
    pkt_len_min: Optional[int] = Field(40, alias="Pkt Len Min")
    pkt_len_max: Optional[int] = Field(1400, alias="Pkt Len Max")
    pkt_len_mean: Optional[float] = Field(110.0, alias="Pkt Len Mean")
    pkt_len_std: Optional[float] = Field(55.0, alias="Pkt Len Std")
    syn_flag_cnt: Optional[int] = Field(1, alias="SYN Flag Cnt")
    rst_flag_cnt: Optional[int] = Field(0, alias="RST Flag Cnt")
    psh_flag_cnt: Optional[int] = Field(1, alias="PSH Flag Cnt")
    ack_flag_cnt: Optional[int] = Field(10, alias="ACK Flag Cnt")
    urg_flag_cnt: Optional[int] = Field(0, alias="URG Flag Cnt")
    down_up_ratio: Optional[float] = Field(0.8, alias="Down/Up Ratio")
    init_fwd_win: Optional[int] = Field(8192, alias="Init Fwd Win Byts")
    init_bwd_win: Optional[int] = Field(8192, alias="Init Bwd Win Byts")

    class Config:
        populate_by_name = True

class FlowPredictionResponse(BaseModel):
    prediction: str
    probability: float
    risk_score: float
    risk_level: str
    forecast: str
    recommended_action: str
    mitre: Optional[MitreInfo] = None
    timestamp: str

class AlertResponse(BaseModel):
    id: int
    timestamp: str
    attack_type: str
    severity: str
    mitre_id: str
    mitre_name: str
    alert_message: str
    recommended_action: str
    status: str

class TrafficTimeSeriesPoint(BaseModel):
    time: str
    total_flows: int
    normal_flows: int
    attack_flows: int
    risk_score: float
    threat: str

class WindowForecastSummary(BaseModel):
    window_size: int
    total_records: int
    normal_traffic: int
    suspicious_traffic: int
    predicted_attacks: int
    current_risk_score: float
    risk_level: str
    forecast_status: str
    forecast_trend: str
    impending_threat: str
    confidence: float
    early_warning_alert: Optional[str] = None
    recommended_action: str
    attack_distribution: Dict[str, int]
    time_series: List[TrafficTimeSeriesPoint]
    recent_alerts: List[AlertResponse]

class TrafficStatsOverview(BaseModel):
    network_status: str
    total_traffic_records: int
    normal_traffic: int
    suspicious_traffic: int
    predicted_attacks: int
    current_risk_score: float
    risk_level: str
    active_threat: str
    forecast: str
    last_updated: str

class UploadResponse(BaseModel):
    message: str
    filename: str
    records_processed: int
    summary: WindowForecastSummary
