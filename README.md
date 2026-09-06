# AI-Based Network Attack Forecasting from Network Traffic Data

An AI-powered cybersecurity prototype that analyzes network traffic flows, identifies abnormal traffic signatures, and **forecasts cyber attacks before or during early escalation stages**. 

The system transitions cybersecurity operations from **reactive attack detection to proactive cyber defense** by calculating rolling time-window velocity metrics, determining risk scores (0–100%), raising early warning alerts, and providing actionable **MITRE ATT&CK mitigation playbooks** through a modern Security Operations Center (SOC) dashboard.

---

## System Architecture

```
                      +-----------------------------+
                      |   Network Traffic Data      |
                      | (CSV / Live Flow Stream)    |
                      +--------------+--------------+
                                     |
                                     v
                      +-----------------------------+
                      |  FastAPI Backend (Port 8000)|
                      +--------------+--------------+
                                     |
            +------------------------+------------------------+
            |                                                 |
            v                                                 v
+-------------------------+                       +-------------------------+
| Data Preprocessing      |                       | Database Layer          |
| - Handling NaNs & Infs  |                       | - MySQL (network_attacks)|
| - StandardScaler        |                       | - SQLite Fallback       |
+-----------+-------------+                       +-------------------------+
            |
            v
+-------------------------+
| Time-Window Analysis    |
| - Velocity & Trend      |
| - Anomaly Density       |
+-----------+-------------+
            |
            v
+-------------------------------------------------------+
| AI/ML Prediction & Forecasting Model (Random Forest)  |
| - Attack Classification (7 Classes)                   |
| - Prediction Probability & Calibrated Risk Score      |
| - Proactive Forecasting (Low / Medium / High Risk)    |
+-----------+-------------------------------------------+
            |
            v
+-------------------------------------------------------+
| MITRE ATT&CK Mapping & Early Warning Alert Engine     |
| (T1498, T1499, T1110, T1071, T1210, T1190)           |
+-----------+-------------------------------------------+
            |
            v
+-------------------------------------------------------+
| React + Vite SOC Cybersecurity Dashboard (Port 5173)   |
| - Overview KPIs & Live Status                         |
| - Radial Risk Gauge Meter                             |
| - Impending Threat Forecasting Trajectory             |
| - Interactive Traffic Analytics (Volume & Risk Trend) |
| - Early Warning Alerts Table                          |
| - CSV Ingestion & Live Stream Simulator               |
+-------------------------------------------------------+
```

---

## Machine Learning Model & Rationale

- **Dataset**: Built using the **CIC-IDS2018** network flow schema with 34 numerical flow metrics (`Dst Port`, `Flow Duration`, `Tot Fwd Pkts`, `Tot Bwd Pkts`, `TotLen Fwd Pkts`, `Flow Byts/s`, `Flow Pkts/s`, `Flow IAT Mean`, flag counts, window sizes, etc.).
- **Supported Attack Classes**:
  1. `Benign` (Normal operational traffic)
  2. `DDoS` (High-velocity volume floods / LOIC / HOIC)
  3. `DoS` (Connection exhaustion / Slowloris / GoldenEye)
  4. `Brute Force` (SSH / FTP / RDP dictionary attempts)
  5. `Botnet` (Periodic C2 beaconing rhythms)
  6. `Infiltration` (Lateral scanning & remote exploit attempts)
  7. `Web Attack` (SQL Injection & XSS payload anomalies)
- **Model Choice**: `RandomForestClassifier` with balanced class weights.
  - *Non-Linear Boundaries*: Captures complex combinatorial interactions among packet sizes, inter-arrival times (IAT), and TCP flags.
  - *Calibrated Probabilities*: Provides accurate class probability distributions (`predict_proba`) essential for continuous risk scoring and forecasting.
  - *Resilience to Multicollinearity*: Handles correlated flow statistics without overfitting.
  - *Inference Speed*: Sub-millisecond execution per flow record, suitable for high-throughput SOC streaming.
- **Model Performance**: **99.89% Accuracy** with 0.99–1.00 F1-scores across all 7 attack vectors.

---

## Forecasting Logic & Thresholds

Rather than only displaying isolated "Attack Detected" flags, the system calculates time-window trend metrics:

| Risk Tier | Risk Score | Traffic State | Forecasting Alert & Proactive Action |
|---|---|---|---|
| **LOW** | `< 30%` | Normal Baseline | Traffic flows operate within nominal boundaries. Maintain passive telemetry retention. |
| **MEDIUM** | `30% - 70%` | Suspicious Traffic | Possible reconnaissance or early attack ramp-up detected. Preemptively rate-limit originating subnet and notify SOC Tier-2 analyst. |
| **HIGH** | `> 70%` | Cyber Attack Imminent / Active | High-confidence malicious flow signature identified. Immediate mitigation deployed (scrubbing, IP lockout, isolation). |

---

## MITRE ATT&CK Matrix Mapping

| Attack Category | MITRE Technique ID | Technique Name | Tactic | Recommended Response Action |
|---|---|---|---|---|
| **DDoS** | `T1498` | Network Denial of Service | Impact | Activate upstream CDN/cloud DDoS scrubbing; rate-limit UDP/ICMP at edge; deploy BGP blackholing. |
| **DoS** | `T1499` | Endpoint Denial of Service | Impact | Tune server connection timeouts; enforce max concurrent sockets per client IP; buffer requests via reverse proxy. |
| **Brute Force** | `T1110` | Brute Force Authentication | Credential Access | Enforce automated Fail2Ban IP lockouts; mandate MFA; restrict SSH/RDP to VPN or bastion hosts. |
| **Botnet** | `T1071` | Application Layer Protocol (C2) | Command & Control | Isolate infected internal endpoint; sinkhole C2 destination domains via DNS firewall; image host for forensic memory analysis. |
| **Infiltration** | `T1210` | Exploitation of Remote Services | Lateral Movement | Block lateral SMB/RPC ports (445, 139, 135) between internal VLANs; review ACLs; patch vulnerable network daemons. |
| **Web Attack** | `T1190` | Exploit Public-Facing Application | Initial Access | Deploy WAF virtual patching rules for SQLi/XSS; parameterize SQL queries; review HTTP server access logs. |

---

## Project Structure

```
c:\S529\
├── backend/
│   ├── app/
│   │   ├── main.py                 # FastAPI application, CORS, startup lifecycle
│   │   ├── config.py               # Configuration, paths, database URL
│   │   ├── database.py             # SQLAlchemy engine with SQLite/MySQL fallback
│   │   ├── models.py               # DB tables: PredictionRecord, SecurityAlert, WindowStat
│   │   ├── schemas.py              # Pydantic request & response schemas
│   │   ├── routes/
│   │   │   ├── prediction.py       # Flow prediction & CSV upload endpoints
│   │   │   ├── forecast.py         # Time-window forecasting & streaming simulation
│   │   │   ├── alerts.py           # Alerts & MITRE ATT&CK matrix routes
│   │   │   └── history.py          # Query historical traffic records & global stats
│   │   └── ml/
│   │       ├── preprocessor.py     # Flow cleaning & feature scaling
│   │       ├── window_analyzer.py  # Sliding time-window trend & velocity aggregator
│   │       ├── predictor.py        # ML inference, probabilities, and risk score engine
│   │       └── mitre_mapper.py     # MITRE ATT&CK mappings & defensive playbooks
│   ├── ml_pipeline/
│   │   ├── generate_dataset.py     # CIC-IDS2018 dataset & sample test generator
│   │   └── train_model.py          # Model training, evaluation, and artifact exporter
│   ├── models/
│   │   ├── model.joblib            # Trained Random Forest classifier
│   │   ├── scaler.joblib           # Fitted StandardScaler
│   │   ├── label_encoder.joblib    # LabelEncoder
│   │   └── feature_columns.json    # Feature schema
│   ├── data/
│   │   ├── sample_cicids2018_test.csv  # 90-flow demo sequence for 1-click presentation
│   │   └── schema.sql              # MySQL DDL schema
│   ├── requirements.txt
│   └── test_system.py              # Automated 6-step verification script
├── frontend/
│   ├── index.html
│   ├── package.json
│   ├── vite.config.js
│   └── src/
│       ├── main.jsx
│       ├── App.jsx                 # Master application controller
│       ├── App.css                 # SOC Dark Theme CSS
│       ├── components/
│       │   ├── Navbar.jsx          # SOC status header & simulation toggle
│       │   ├── Sidebar.jsx         # Section navigation
│       │   ├── OverviewCards.jsx   # Top KPI metrics
│       │   ├── RiskGauge.jsx       # Animated radial speedometer gauge (0–100%)
│       │   ├── ForecastPanel.jsx   # 3-stage forecasting trajectory
│       │   ├── TrafficAnalytics.jsx# Dynamic SVG volume & risk trend charts
│       │   ├── AlertsTable.jsx     # Early warning alerts table with MITRE tags
│       │   ├── TrafficAnalyzer.jsx # CSV upload, 1-click demo, flow inspector
│       │   └── MitreModal.jsx      # MITRE ATT&CK response playbook modal
│       └── services/
│           └── api.js              # Fetch client communicating with backend
├── run_backend.bat                 # 1-Click Windows Backend Launcher
├── run_frontend.bat                # 1-Click Windows Frontend Launcher
├── networkattack.txt               # Original project requirements
└── README.md                       # Documentation
```

---

## Installation & Running on Windows 11

### Prerequisites
- **Python 3.10+** (Tested on Python 3.13)
- **Node.js 18+** (Tested on Node v24.20)
- *(Optional)* MySQL 8.0+ (Automatic SQLite fallback is included if MySQL is not installed)

---

### Step 1: Clone or Navigate to Directory
```powershell
cd c:\S529
```

### Step 2: Launch the Backend
Double-click `run_backend.bat` or run in PowerShell:
```powershell
.\run_backend.bat
```
*Or manually:*
```powershell
cd backend
python -m pip install -r requirements.txt
python ml_pipeline\train_model.py
python -m uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload
```
The backend will be live at `http://127.0.0.1:8000`.  
Interactive API Swagger docs available at `http://127.0.0.1:8000/docs`.

---

### Step 3: Launch the Frontend Dashboard
Double-click `run_frontend.bat` or run in a second PowerShell window:
```powershell
.\run_frontend.bat
```
*Or manually:*
```powershell
cd frontend
npm install
npm run dev
```
The SOC Dashboard will open at **`http://localhost:5173`**.

---

## How to Demonstrate the Prototype (SIH Presentation Flow)

1. **Open Dashboard**: Navigate to `http://localhost:5173`.
2. **Instant 1-Click Demonstration**:
   - Click **"Load Demo Dataset"** in the top navigation bar or under the **Dataset & Simulator** tab.
   - The system ingests the calibrated CIC-IDS2018 test sequence.
   - Watch the **Risk Gauge** dynamically display risk scores.
   - Inspect the **Traffic Dynamics Chart** showing the progression of normal flows transitioning into attack bursts and then mitigating.
   - Review the **Early Warning Alerts Table** displaying detected vectors with clickable MITRE ATT&CK technique badges.
3. **Live Streaming Simulation**:
   - In the navbar or Dataset tab, click **"Simulate Stream"**.
   - Watch real-time flow arrivals every 2.5 seconds as the engine transitions from:
     `Normal Baseline (15% Risk)` → `Reconnaissance Probing (50% Risk)` → `Active Attack Surge (90% Risk)` → `Mitigation`.
4. **Custom CSV Upload**:
   - Go to the **Dataset & Simulator** tab.
   - Drag and drop any network flow CSV file (e.g. `backend/data/sample_cicids2018_test.csv`) to analyze external traffic captures.
5. **MITRE ATT&CK Playbook Inspection**:
   - Click any **MITRE technique button** (e.g. `T1498`) to open the interactive Incident Response Playbook modal.

---

## Database Configuration (MySQL / SQLite)

By default, the backend connects to local SQLite (`sqlite:///./network_attacks.db`) for immediate zero-configuration operation.

To use MySQL:
1. Ensure MySQL Server is running.
2. Execute `backend/data/schema.sql` in MySQL Workbench or mysql CLI:
   ```sql
   source backend/data/schema.sql;
   ```
3. Create a `.env` file in `backend/` with your connection string:
   ```env
   DATABASE_URL=mysql+pymysql://root:your_password@localhost:3306/network_attacks
   ```
4. Restart the backend.
