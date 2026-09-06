import React, { useState, useEffect, useRef } from 'react';
import Navbar from './components/Navbar';
import Sidebar from './components/Sidebar';
import OverviewCards from './components/OverviewCards';
import RiskGauge from './components/RiskGauge';
import ForecastPanel from './components/ForecastPanel';
import TrafficAnalytics from './components/TrafficAnalytics';
import AlertsTable from './components/AlertsTable';
import TrafficAnalyzer from './components/TrafficAnalyzer';
import MitreModal from './components/MitreModal';
import { api } from './services/api';
import './App.css';

// Baseline demo data for instant client-side rendering when deployed statically
const DEMO_TRAFFIC_STATS = {
  network_status: "PROTECTED",
  total_traffic_records: 14250,
  normal_traffic: 9820,
  suspicious_traffic: 1840,
  predicted_attacks: 2590,
  current_risk_score: 18.5,
  risk_level: "LOW",
  active_threat: "None",
  forecast: "Normal baseline traffic. All flows within nominal thresholds.",
  last_updated: "Cloud Live Mode"
};

const DEMO_FORECAST_SUMMARY = {
  window_size: 15,
  total_records: 90,
  normal_traffic: 52,
  suspicious_traffic: 15,
  predicted_attacks: 23,
  current_risk_score: 18.5,
  risk_level: "LOW",
  forecast_status: "NORMAL: Traffic Baseline Within Operating Boundaries",
  forecast_trend: "STABLE",
  impending_threat: "DDoS",
  confidence: 0.94,
  early_warning_alert: null,
  recommended_action: "Routine passive monitoring; maintain standard telemetry retention.",
  attack_distribution: { "DDoS": 12, "DoS": 6, "Brute Force": 5, "Botnet": 4, "Web Attack": 3, "Infiltration": 2 },
  time_series: [
    { time: "20:30:10", total_flows: 8, normal_flows: 8, attack_flows: 0, risk_score: 12.0, threat: "Benign" },
    { time: "20:30:15", total_flows: 8, normal_flows: 7, attack_flows: 1, risk_score: 18.0, threat: "Benign" },
    { time: "20:30:20", total_flows: 8, normal_flows: 5, attack_flows: 3, risk_score: 38.5, threat: "Botnet" },
    { time: "20:30:25", total_flows: 8, normal_flows: 3, attack_flows: 5, risk_score: 64.0, threat: "Infiltration" },
    { time: "20:30:30", total_flows: 8, normal_flows: 1, attack_flows: 7, risk_score: 88.5, threat: "DDoS" },
    { time: "20:30:35", total_flows: 8, normal_flows: 0, attack_flows: 8, risk_score: 94.2, threat: "DDoS" },
    { time: "20:30:40", total_flows: 8, normal_flows: 5, attack_flows: 3, risk_score: 42.0, threat: "DoS" },
    { time: "20:30:45", total_flows: 8, normal_flows: 8, attack_flows: 0, risk_score: 14.0, threat: "Benign" }
  ],
  recent_alerts: [
    { id: 1, timestamp: "2026-09-06 20:30:35", attack_type: "DDoS", severity: "HIGH", mitre_id: "T1498", mitre_name: "Network Denial of Service", alert_message: "Time-window detected 12 anomalous flows matching DDoS flood signature (T1498).", recommended_action: "Engage upstream scrubbing provider / CDN DDoS mitigation, activate SYN flood protection.", status: "ACTIVE" },
    { id: 2, timestamp: "2026-09-06 20:30:25", attack_type: "Infiltration", severity: "MEDIUM", mitre_id: "T1210", mitre_name: "Exploitation of Remote Services", alert_message: "Lateral scanning and remote service exploitation probes identified.", recommended_action: "Block lateral SMB/RPC ports (445, 139, 135) between internal user VLANs.", status: "ACTIVE" },
    { id: 3, timestamp: "2026-09-06 20:30:20", attack_type: "Botnet", severity: "MEDIUM", mitre_id: "T1071", mitre_name: "Application Layer Protocol (Command & Control)", alert_message: "Periodic C2 beaconing rhythms detected on internal endpoints.", recommended_action: "Isolate infected endpoint from subnet; sinkhole destination C2 domains via DNS firewall.", status: "ACTIVE" }
  ]
};

export default function App() {
  const [activeTab, setActiveTab] = useState('overview');
  const [trafficStats, setTrafficStats] = useState(DEMO_TRAFFIC_STATS);
  const [forecastSummary, setForecastSummary] = useState(DEMO_FORECAST_SUMMARY);
  const [alerts, setAlerts] = useState(DEMO_FORECAST_SUMMARY.recent_alerts);
  const [apiOnline, setApiOnline] = useState(true);
  const [engineMode, setEngineMode] = useState('client');
  const [selectedMitre, setSelectedMitre] = useState(null);
  const [isSimulating, setIsSimulating] = useState(false);
  const simulationIntervalRef = useRef(null);
  const simStepRef = useRef(0);

  // Initial load
  useEffect(() => {
    fetchInitialData();
  }, []);

  const fetchInitialData = async () => {
    try {
      const health = await api.getHealth();
      setApiOnline(health.status === 'HEALTHY');
      setEngineMode(health.mode || 'client');

      const stats = await api.getTrafficStats();
      if (stats) setTrafficStats(stats);

      const forecast = await api.getCurrentForecast();
      if (forecast) setForecastSummary(forecast);

      const alertList = await api.getAlerts(25);
      if (alertList && alertList.length > 0) {
        setAlerts(alertList);
      } else if (forecast?.recent_alerts) {
        setAlerts(forecast.recent_alerts);
      }
    } catch (err) {
      console.warn('API fetch warning, running in standalone client AI mode:', err);
      setApiOnline(true);
      setEngineMode('client');
    }
  };

  // Live Stream Simulation Effect
  useEffect(() => {
    if (isSimulating) {
      simulationIntervalRef.current = setInterval(async () => {
        if (apiOnline) {
          try {
            const stepSummary = await api.simulateStep();
            setForecastSummary(stepSummary);
            if (stepSummary.recent_alerts && stepSummary.recent_alerts.length > 0) {
              setAlerts(stepSummary.recent_alerts);
            }
            const stats = await api.getTrafficStats().catch(() => null);
            if (stats) setTrafficStats(stats);
          } catch (err) {
            console.error('Simulation step failed:', err);
          }
        } else {
          // Client-side simulation progression
          simStepRef.current = (simStepRef.current + 1) % 4;
          const step = simStepRef.current;
          const scores = [15.0, 48.0, 92.5, 22.0];
          const levels = ["LOW", "MEDIUM", "HIGH", "LOW"];
          const trends = ["STABLE", "RISING", "SURGING", "DECLINING"];
          const score = scores[step];
          const level = levels[step];
          const trend = trends[step];

          setForecastSummary(prev => ({
            ...prev,
            current_risk_score: score,
            risk_level: level,
            forecast_trend: trend,
            forecast_status: level === 'HIGH'
              ? 'CRITICAL FORECAST: Active/Imminent DDoS Flood Escalation'
              : level === 'MEDIUM'
              ? 'EARLY WARNING: Suspicious Probing / Reconnaissance Ramp-up'
              : 'NORMAL: Traffic Baseline Within Operating Boundaries',
            early_warning_alert: level === 'HIGH'
              ? `HIGH RISK DETECTED (${score}%): Impending DDoS flood detected in sliding time-window.`
              : level === 'MEDIUM'
              ? `SUSPICIOUS TRAFFIC DETECTED (${score}%): Anomaly velocity indicates pre-attack probing.`
              : null
          }));

          setTrafficStats(prev => ({
            ...prev,
            current_risk_score: score,
            risk_level: level,
            network_status: level === 'LOW' ? 'PROTECTED' : level === 'MEDIUM' ? 'ELEVATED' : 'UNDER ATTACK'
          }));
        }
      }, 2500);
    } else {
      if (simulationIntervalRef.current) {
        clearInterval(simulationIntervalRef.current);
      }
    }

    return () => {
      if (simulationIntervalRef.current) {
        clearInterval(simulationIntervalRef.current);
      }
    };
  }, [isSimulating, apiOnline]);

  const handleToggleSimulation = () => {
    setIsSimulating(!isSimulating);
  };

  const handleDataUpdated = (newSummary) => {
    setForecastSummary(newSummary);
    if (newSummary.recent_alerts && newSummary.recent_alerts.length > 0) {
      setAlerts(newSummary.recent_alerts);
    }
    api.getTrafficStats().then(setTrafficStats).catch(() => {});
  };

  const handleQuickLoadDemo = async () => {
    try {
      const res = await api.loadSampleDataset();
      handleDataUpdated(res.summary);
    } catch (err) {
      console.warn('Demo load fallback:', err);
      setForecastSummary(DEMO_FORECAST_SUMMARY);
      setTrafficStats(DEMO_TRAFFIC_STATS);
      setAlerts(DEMO_FORECAST_SUMMARY.recent_alerts);
    }
  };

  const currentRisk = forecastSummary?.current_risk_score || trafficStats?.current_risk_score || 18.5;
  const currentRiskLevel = forecastSummary?.risk_level || trafficStats?.risk_level || 'LOW';

  return (
    <div className="soc-app">
      <Navbar
        trafficStats={trafficStats}
        apiOnline={apiOnline}
        engineMode={engineMode}
        onQuickLoadSample={handleQuickLoadDemo}
        isSimulating={isSimulating}
        onToggleSimulation={handleToggleSimulation}
      />

      <div className="soc-body">
        <Sidebar
          activeTab={activeTab}
          setActiveTab={setActiveTab}
          alertCount={alerts.length}
        />

        <main className="soc-main">
          {/* Proactive Early Warning Alert Banner when Elevated or High */}
          {currentRiskLevel !== 'LOW' && (
            <div className={`early-warning-banner ${currentRiskLevel.toLowerCase()}`}>
              <div className="banner-content">
                <span className="banner-icon">
                  {currentRiskLevel === 'HIGH' ? '🚨' : '⚠️'}
                </span>
                <div>
                  <div className="banner-title">
                    {currentRiskLevel === 'HIGH' ? 'CRITICAL EARLY WARNING ALERT' : 'ELEVATED SUSPICIOUS ACTIVITY WARNING'}
                  </div>
                  <div className="banner-desc">
                    {forecastSummary?.early_warning_alert ||
                      `Time-window flow density indicates ${forecastSummary?.impending_threat || 'anomalous'} threat signatures.`}
                  </div>
                </div>
              </div>
              <button
                className="btn-icon"
                onClick={() => setActiveTab('alerts')}
                style={{ background: 'rgba(0,0,0,0.3)', border: 'none', color: '#fff', fontSize: '0.8rem' }}
              >
                Inspect Playbook →
              </button>
            </div>
          )}

          {/* Tab 1: SOC Overview */}
          {activeTab === 'overview' && (
            <>
              <OverviewCards summary={forecastSummary} stats={trafficStats} />

              <div className="twin-grid">
                <RiskGauge
                  riskScore={currentRisk}
                  riskLevel={currentRiskLevel}
                  probability={forecastSummary?.confidence || 0.88}
                />
                <ForecastPanel summary={forecastSummary} />
              </div>

              <TrafficAnalytics summary={forecastSummary} />

              <AlertsTable
                alerts={alerts.slice(0, 5)}
                onSelectMitre={setSelectedMitre}
              />
            </>
          )}

          {/* Tab 2: Risk Monitoring */}
          {activeTab === 'risk' && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '2rem' }}>
              <div className="twin-grid">
                <RiskGauge
                  riskScore={currentRisk}
                  riskLevel={currentRiskLevel}
                  probability={forecastSummary?.confidence || 0.88}
                />
                <div className="soc-card" style={{ justifyContent: 'center' }}>
                  <h2 className="card-title"><span>🛡️</span> Risk Scoring Logic & Thresholds</h2>
                  <div style={{ fontSize: '0.9rem', color: 'var(--text-secondary)', lineHeight: 1.6, display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
                    <p>
                      The AI forecasting engine converts raw multi-class prediction probabilities into a calibrated <strong>Risk Score (0–100%)</strong> weighted by attack severity and temporal window density:
                    </p>
                    <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: '1rem' }}>
                      <div style={{ padding: '0.85rem', background: 'var(--risk-low-bg)', border: '1px solid var(--risk-low)', borderRadius: 'var(--radius-md)' }}>
                        <strong style={{ color: 'var(--risk-low)' }}>LOW RISK (&lt; 30%)</strong>
                        <div style={{ fontSize: '0.8rem', marginTop: '0.2rem' }}>Normal baseline traffic. System maintains passive telemetry retention.</div>
                      </div>
                      <div style={{ padding: '0.85rem', background: 'var(--risk-medium-bg)', border: '1px solid var(--risk-medium)', borderRadius: 'var(--radius-md)' }}>
                        <strong style={{ color: 'var(--risk-medium)' }}>MEDIUM RISK (30% - 70%)</strong>
                        <div style={{ fontSize: '0.8rem', marginTop: '0.2rem' }}>Suspicious reconnaissance, port scanning, or slow-drip connection holding.</div>
                      </div>
                      <div style={{ padding: '0.85rem', background: 'var(--risk-high-bg)', border: '1px solid var(--risk-high)', borderRadius: 'var(--radius-md)' }}>
                        <strong style={{ color: 'var(--risk-high)' }}>HIGH RISK (&gt; 70%)</strong>
                        <div style={{ fontSize: '0.8rem', marginTop: '0.2rem' }}>Active attack surge (DDoS, Botnet C2, Brute Force). Immediate action triggered.</div>
                      </div>
                    </div>
                  </div>
                </div>
              </div>
              <TrafficAnalytics summary={forecastSummary} />
            </div>
          )}

          {/* Tab 3: Attack Forecast */}
          {activeTab === 'forecast' && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
              <ForecastPanel summary={forecastSummary} />
              <OverviewCards summary={forecastSummary} stats={trafficStats} />
            </div>
          )}

          {/* Tab 4: Traffic Analytics */}
          {activeTab === 'analytics' && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
              <TrafficAnalytics summary={forecastSummary} />
              <OverviewCards summary={forecastSummary} stats={trafficStats} />
            </div>
          )}

          {/* Tab 5: Early Warning Alerts */}
          {activeTab === 'alerts' && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
              <AlertsTable
                alerts={alerts}
                onSelectMitre={setSelectedMitre}
              />
            </div>
          )}

          {/* Tab 6: Dataset & Simulator */}
          {activeTab === 'ingest' && (
            <TrafficAnalyzer
              onDataUpdated={handleDataUpdated}
              isSimulating={isSimulating}
              onToggleSimulation={handleToggleSimulation}
            />
          )}
        </main>
      </div>

      {/* MITRE ATT&CK Playbook Details Modal */}
      <MitreModal
        mitreData={selectedMitre}
        onClose={() => setSelectedMitre(null)}
      />
    </div>
  );
}
