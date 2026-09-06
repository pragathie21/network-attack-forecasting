"""
CIC-IDS2018 High-Fidelity Network Traffic Dataset Generator
Generates realistic network flow records matching the official CIC-IDS2018 feature schema,
covering Benign baseline traffic and 6 representative attack vectors:
- DDoS (e.g. LOIC / HOIC high-velocity packet flood)
- DoS (e.g. Slowloris / GoldenEye connection exhaustion)
- Brute Force (e.g. SSH / FTP / RDP dictionary attempts)
- Botnet (e.g. Ares / Mirai periodic C2 beaconing)
- Infiltration (e.g. lateral scanning & remote service exploits)
- Web Attack (e.g. SQL Injection / XSS abnormal payload bursts)
"""

import os
import random
import numpy as np
import pandas as pd
from datetime import datetime, timedelta

def generate_flow_record(label: str, timestamp: datetime) -> dict:
    """Generate a single realistic network flow record according to CIC-IDS2018 schema."""
    
    if label == "Benign":
        dst_port = random.choice([80, 443, 53, 8080, 22, 123, 8443])
        flow_duration = random.randint(500, 2_000_000) # microseconds
        tot_fwd_pkts = random.randint(2, 25)
        tot_bwd_pkts = random.randint(1, 30)
        tot_len_fwd = tot_fwd_pkts * random.randint(40, 400)
        tot_len_bwd = tot_bwd_pkts * random.randint(50, 1400)
        syn_cnt = 1 if random.random() < 0.35 else 0
        rst_cnt = 0 if random.random() < 0.95 else 1
        psh_cnt = random.randint(0, 3)
        ack_cnt = random.randint(1, tot_fwd_pkts + tot_bwd_pkts)
        flow_iat_mean = random.uniform(500, 50_000)
        init_fwd_win = random.choice([8192, 14600, 29200, 65535])
        init_bwd_win = random.choice([8192, 14600, 29200, 65535])

    elif label == "DDoS":
        # Flooding target web/DNS servers with massive packet rates, tiny payload or SYN flood
        dst_port = random.choice([80, 443, 8080, 53])
        flow_duration = random.randint(50, 50_000)
        tot_fwd_pkts = random.randint(50, 400)
        tot_bwd_pkts = random.randint(0, 5) # Few or no responses
        tot_len_fwd = tot_fwd_pkts * random.randint(20, 70) # small malicious packets
        tot_len_bwd = tot_bwd_pkts * random.randint(0, 50)
        syn_cnt = random.randint(1, 10)
        rst_cnt = random.randint(0, 5)
        psh_cnt = random.randint(0, 2)
        ack_cnt = random.randint(0, 4)
        flow_iat_mean = random.uniform(5, 500) # Extremely tight packet intervals
        init_fwd_win = random.choice([1024, 2048, 4096])
        init_bwd_win = 0

    elif label == "DoS":
        # Slowloris / GoldenEye: low bandwidth, long duration, keeping sockets open
        dst_port = random.choice([80, 443, 8080])
        flow_duration = random.randint(5_000_000, 60_000_000) # very long
        tot_fwd_pkts = random.randint(5, 40)
        tot_bwd_pkts = random.randint(2, 20)
        tot_len_fwd = tot_fwd_pkts * random.randint(30, 90)
        tot_len_bwd = tot_bwd_pkts * random.randint(40, 100)
        syn_cnt = 1
        rst_cnt = 0
        psh_cnt = random.randint(1, 5)
        ack_cnt = random.randint(5, 30)
        flow_iat_mean = random.uniform(500_000, 3_000_000) # Slow drip intervals
        init_fwd_win = 8192
        init_bwd_win = 8192

    elif label == "Brute Force":
        # Rapid authentication attempts on SSH/FTP/RDP
        dst_port = random.choice([22, 21, 3389, 23])
        flow_duration = random.randint(10_000, 400_000)
        tot_fwd_pkts = random.randint(8, 28)
        tot_bwd_pkts = random.randint(6, 24)
        tot_len_fwd = tot_fwd_pkts * random.randint(60, 120)
        tot_len_bwd = tot_bwd_pkts * random.randint(80, 150)
        syn_cnt = 1
        rst_cnt = random.choice([0, 1])
        psh_cnt = random.randint(2, 6)
        ack_cnt = random.randint(8, 25)
        flow_iat_mean = random.uniform(2_000, 25_000)
        init_fwd_win = 65535
        init_bwd_win = 65535

    elif label == "Botnet":
        # Periodic C2 beaconing with fixed intervals, DNS lookups, or IRC/HTTP commands
        dst_port = random.choice([80, 443, 6667, 8000, 9050])
        flow_duration = random.randint(50_000, 1_200_000)
        tot_fwd_pkts = random.randint(4, 15)
        tot_bwd_pkts = random.randint(3, 12)
        tot_len_fwd = tot_fwd_pkts * random.randint(50, 200)
        tot_len_bwd = tot_bwd_pkts * random.randint(80, 300)
        syn_cnt = 1
        rst_cnt = 0
        psh_cnt = random.randint(1, 4)
        ack_cnt = random.randint(4, 18)
        flow_iat_mean = random.uniform(10_000, 60_000) # Regular rhythm
        init_fwd_win = 14600
        init_bwd_win = 14600

    elif label == "Infiltration":
        # Network reconnaissance, SMB/RDP exploitation, lateral port probing
        dst_port = random.choice([445, 139, 135, 3389, 4444, 8888])
        flow_duration = random.randint(2_000, 800_000)
        tot_fwd_pkts = random.randint(3, 20)
        tot_bwd_pkts = random.randint(1, 15)
        tot_len_fwd = tot_fwd_pkts * random.randint(70, 350)
        tot_len_bwd = tot_bwd_pkts * random.randint(60, 400)
        syn_cnt = random.choice([1, 2])
        rst_cnt = random.choice([0, 1])
        psh_cnt = random.randint(1, 3)
        ack_cnt = random.randint(2, 16)
        flow_iat_mean = random.uniform(1_000, 40_000)
        init_fwd_win = 29200
        init_bwd_win = 29200

    elif label == "Web Attack":
        # SQL Injection / XSS injection attempts on HTTP/HTTPS
        dst_port = random.choice([80, 443, 8080, 3000])
        flow_duration = random.randint(8_000, 600_000)
        tot_fwd_pkts = random.randint(5, 30)
        tot_bwd_pkts = random.randint(4, 25)
        tot_len_fwd = tot_fwd_pkts * random.randint(250, 950) # Heavy payloads (SQL injections)
        tot_len_bwd = tot_bwd_pkts * random.randint(100, 600)
        syn_cnt = 1
        rst_cnt = 0
        psh_cnt = random.randint(2, 8)
        ack_cnt = random.randint(6, 30)
        flow_iat_mean = random.uniform(1_500, 35_000)
        init_fwd_win = 65535
        init_bwd_win = 65535

    else:
        raise ValueError(f"Unknown label: {label}")

    duration_sec = max(flow_duration / 1_000_000.0, 0.00001)
    tot_pkts = tot_fwd_pkts + tot_bwd_pkts
    tot_bytes = tot_len_fwd + tot_len_bwd

    fwd_pkt_len_mean = tot_len_fwd / max(tot_fwd_pkts, 1)
    bwd_pkt_len_mean = tot_len_bwd / max(tot_bwd_pkts, 1)
    pkt_len_mean = tot_bytes / max(tot_pkts, 1)

    return {
        "Timestamp": timestamp.strftime("%Y-%m-%d %H:%M:%S"),
        "Dst Port": dst_port,
        "Flow Duration": flow_duration,
        "Tot Fwd Pkts": tot_fwd_pkts,
        "Tot Bwd Pkts": tot_bwd_pkts,
        "TotLen Fwd Pkts": tot_len_fwd,
        "TotLen Bwd Pkts": tot_len_bwd,
        "Fwd Pkt Len Max": int(fwd_pkt_len_mean * random.uniform(1.2, 1.8)),
        "Fwd Pkt Len Min": max(0, int(fwd_pkt_len_mean * random.uniform(0.4, 0.8))),
        "Fwd Pkt Len Mean": round(fwd_pkt_len_mean, 2),
        "Bwd Pkt Len Mean": round(bwd_pkt_len_mean, 2),
        "Flow Byts/s": round(tot_bytes / duration_sec, 2),
        "Flow Pkts/s": round(tot_pkts / duration_sec, 2),
        "Flow IAT Mean": round(flow_iat_mean, 2),
        "Flow IAT Std": round(flow_iat_mean * random.uniform(0.2, 0.9), 2),
        "Flow IAT Max": round(flow_iat_mean * random.uniform(1.5, 3.0), 2),
        "Flow IAT Min": round(flow_iat_mean * random.uniform(0.05, 0.3), 2),
        "Fwd IAT Tot": round(flow_iat_mean * tot_fwd_pkts, 2),
        "Bwd IAT Tot": round(flow_iat_mean * tot_bwd_pkts, 2),
        "Fwd Header Len": tot_fwd_pkts * 20,
        "Bwd Header Len": tot_bwd_pkts * 20,
        "Fwd Pkts/s": round(tot_fwd_pkts / duration_sec, 2),
        "Bwd Pkts/s": round(tot_bwd_pkts / duration_sec, 2),
        "Pkt Len Min": max(20, int(pkt_len_mean * 0.3)),
        "Pkt Len Max": int(pkt_len_mean * 2.2),
        "Pkt Len Mean": round(pkt_len_mean, 2),
        "Pkt Len Std": round(pkt_len_mean * 0.5, 2),
        "SYN Flag Cnt": syn_cnt,
        "RST Flag Cnt": rst_cnt,
        "PSH Flag Cnt": psh_cnt,
        "ACK Flag Cnt": ack_cnt,
        "URG Flag Cnt": 0,
        "Down/Up Ratio": round(tot_bwd_pkts / max(tot_fwd_pkts, 1), 2),
        "Init Fwd Win Byts": init_fwd_win,
        "Init Bwd Win Byts": init_bwd_win,
        "Label": label
    }

def generate_dataset(num_records: int = 14000, output_csv: str = None) -> pd.DataFrame:
    """
    Generate a balanced multi-class dataset according to realistic traffic distributions:
    ~45% Benign, ~15% DDoS, ~10% DoS, ~10% Brute Force, ~8% Botnet, ~6% Infiltration, ~6% Web Attack.
    """
    labels_weights = [
        ("Benign", 0.46),
        ("DDoS", 0.15),
        ("DoS", 0.10),
        ("Brute Force", 0.10),
        ("Botnet", 0.07),
        ("Infiltration", 0.06),
        ("Web Attack", 0.06),
    ]
    
    records = []
    current_time = datetime.now() - timedelta(hours=2)
    
    for label, weight in labels_weights:
        count = int(num_records * weight)
        for _ in range(count):
            current_time += timedelta(milliseconds=random.randint(50, 600))
            record = generate_flow_record(label, current_time)
            records.append(record)
            
    random.shuffle(records)
    df = pd.DataFrame(records)
    
    if output_csv:
        os.makedirs(os.path.dirname(output_csv), exist_ok=True)
        df.to_csv(output_csv, index=False)
        print(f"Dataset generated with {len(df)} records saved to: {output_csv}")
        print(df["Label"].value_counts())
        
    return df

def generate_sample_test_traffic(output_csv: str):
    """
    Generate a realistic sequential time-series CSV for dashboard testing.
    Progression:
    1. 25 Benign baseline flows (Low risk, 0-25%)
    2. 15 Reconnaissance / Slow drip flows (Medium risk ramp-up, 35-65%)
    3. 30 Intense DDoS / Brute Force attacks (High risk, 80-98%)
    4. 10 Mitigation / Returning to benign
    """
    records = []
    base_time = datetime.now() - timedelta(minutes=15)
    
    # Phase 1: Baseline Benign
    for _ in range(25):
        base_time += timedelta(seconds=random.uniform(0.8, 2.5))
        records.append(generate_flow_record("Benign", base_time))
        
    # Phase 2: Suspicious Early Reconnaissance (Infiltration / Botnet probe)
    for _ in range(15):
        base_time += timedelta(seconds=random.uniform(0.4, 1.2))
        lbl = random.choice(["Infiltration", "Botnet", "Benign"])
        records.append(generate_flow_record(lbl, base_time))
        
    # Phase 3: Active Attack Flood (DDoS / DoS / Brute Force)
    for _ in range(35):
        base_time += timedelta(seconds=random.uniform(0.05, 0.3))
        lbl = random.choice(["DDoS", "DoS", "Brute Force", "Web Attack"])
        records.append(generate_flow_record(lbl, base_time))
        
    # Phase 4: Cool down
    for _ in range(15):
        base_time += timedelta(seconds=random.uniform(1.0, 3.0))
        records.append(generate_flow_record("Benign", base_time))
        
    df = pd.DataFrame(records)
    os.makedirs(os.path.dirname(output_csv), exist_ok=True)
    df.to_csv(output_csv, index=False)
    print(f"Sample test sequence saved with {len(df)} records to: {output_csv}")

if __name__ == "__main__":
    train_path = os.path.join(os.path.dirname(__file__), "..", "data", "cicids2018_train.csv")
    test_path = os.path.join(os.path.dirname(__file__), "..", "data", "sample_cicids2018_test.csv")
    
    generate_dataset(num_records=12000, output_csv=train_path)
    generate_sample_test_traffic(test_path)
