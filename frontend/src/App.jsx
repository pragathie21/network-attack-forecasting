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

export default function App() {
  const [activeTab, setActiveTab] = useState('overview');
  const [trafficStats, setTrafficStats] = useState(null);
  const [forecastSummary, setForecastSummary] = useState(null);
  const [alerts, setAlerts] = useState([]);
  const [apiOnline, setApiOnline] = useState(false);
  const [selectedMitre, setSelectedMitre] = useState(null);
  const [isSimulating, setIsSimulating] = useState(false);
  const simulationIntervalRef = useRef(null);

  // Initial load
  useEffect(() => {
    fetchInitialData();
  }, []);

  const fetchInitialData = async () => {
    try {
      const health = await api.getHealth();
      setApiOnline(health.status === 'HEALTHY');

      const stats = await api.getTrafficStats();
      setTrafficStats(stats);

      const forecast = await api.getCurrentForecast();
      setForecastSummary(forecast);

      const alertList = await api.getAlerts(25);
      setAlerts(alertList.length > 0 ? alertList : (forecast.recent_alerts || []));
    } catch (err) {
      console.warn('Backend not reachable yet:', err);
      setApiOnline(false);
    }
  };

  // Live Stream Simulation Effect
  useEffect(() => {
    if (isSimulating) {
      simulationIntervalRef.current = setInterval(async () => {
        try {
          const stepSummary = await api.simulateStep();
          setForecastSummary(stepSummary);
          if (stepSummary.recent_alerts && stepSummary.recent_alerts.length > 0) {
            setAlerts(stepSummary.recent_alerts);
          }
          // Refresh global stats
          const stats = await api.getTrafficStats().catch(() => null);
          if (stats) setTrafficStats(stats);
        } catch (err) {
          console.error('Simulation step failed:', err);
          setIsSimulating(false);
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
  }, [isSimulating]);

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
      alert(`Demo load failed: ${err.message}`);
    }
  };

  const currentRisk = forecastSummary?.current_risk_score || trafficStats?.current_risk_score || 12;
  const currentRiskLevel = forecastSummary?.risk_level || trafficStats?.risk_level || 'LOW';

  return (
    <div className="soc-app">
      <Navbar
        trafficStats={trafficStats}
        apiOnline={apiOnline}
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
