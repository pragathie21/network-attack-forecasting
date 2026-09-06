import React from 'react';

export default function ForecastPanel({ summary }) {
  const trend = summary?.forecast_trend || 'STABLE';
  const threat = summary?.impending_threat || 'Benign';
  const forecastStatus = summary?.forecast_status || 'System normal. Monitoring baseline traffic.';
  const action = summary?.recommended_action || 'Routine passive monitoring; maintain standard telemetry retention.';
  const earlyWarning = summary?.early_warning_alert;
  const riskScore = summary?.current_risk_score || 10;
  const riskLevel = summary?.risk_level || 'LOW';

  const trendClass = trend.toLowerCase();

  return (
    <div className="soc-card forecast-panel" style={{ height: '100%' }}>
      <div className="card-title-row">
        <h2 className="card-title">
          <span>🔮</span> Attack Forecasting Engine
        </h2>
        <div className={`forecast-trend-badge ${trendClass}`}>
          <span>⚡</span> Trend: {trend}
        </div>
      </div>

      {/* Main Forecast Status Box */}
      <div className="forecast-banner-box">
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <div style={{ fontSize: '0.75rem', fontWeight: 600, color: 'var(--neon-cyan)', textTransform: 'uppercase', letterSpacing: '0.06em' }}>
            Time-Window Predictive Intelligence
          </div>
          <div style={{ fontSize: '0.8rem', color: 'var(--text-secondary)' }}>
            Window: {summary?.window_size || 15} flows
          </div>
        </div>

        <div style={{ fontSize: '1.05rem', fontWeight: 700, color: '#fff', lineHeight: 1.4 }}>
          {forecastStatus}
        </div>

        {earlyWarning && (
          <div style={{ padding: '0.65rem 0.85rem', background: 'rgba(239, 68, 68, 0.1)', border: '1px solid var(--risk-high)', borderRadius: 'var(--radius-sm)', fontSize: '0.82rem', color: '#fca5a5' }}>
            <strong>⚠️ Early Warning:</strong> {earlyWarning}
          </div>
        )}
      </div>

      {/* 3-Stage Trajectory Pipeline */}
      <div>
        <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', textTransform: 'uppercase', marginBottom: '0.5rem', fontWeight: 600 }}>
          Attack Progression Trajectory
        </div>
        <div className="forecast-trajectory-steps">
          {/* Stage 1: Baseline */}
          <div className={`trajectory-step ${riskScore < 30 ? 'active' : ''}`}>
            <div className="trajectory-step-title">Stage 1: Normal</div>
            <div className="trajectory-step-val" style={{ color: 'var(--risk-low)' }}>
              Baseline Flows
            </div>
            <div style={{ fontSize: '0.7rem', color: 'var(--text-muted)' }}>Risk &lt; 30%</div>
          </div>

          {/* Stage 2: Suspicious Recon */}
          <div className={`trajectory-step ${riskScore >= 30 && riskScore < 70 ? 'active' : ''}`}>
            <div className="trajectory-step-title">Stage 2: Probing</div>
            <div className="trajectory-step-val" style={{ color: 'var(--risk-medium)' }}>
              Anomalous Ramp-up
            </div>
            <div style={{ fontSize: '0.7rem', color: 'var(--text-muted)' }}>Risk 30% - 70%</div>
          </div>

          {/* Stage 3: Attack Imminent */}
          <div className={`trajectory-step ${riskScore >= 70 ? 'active' : ''}`}>
            <div className="trajectory-step-title">Stage 3: Threat Surge</div>
            <div className="trajectory-step-val" style={{ color: 'var(--risk-high)' }}>
              Attack Active / Imminent
            </div>
            <div style={{ fontSize: '0.7rem', color: 'var(--text-muted)' }}>Risk &gt; 70%</div>
          </div>
        </div>
      </div>

      {/* Recommended Preventive Action */}
      <div style={{ background: 'rgba(0, 242, 254, 0.04)', border: '1px solid rgba(0, 242, 254, 0.2)', borderRadius: 'var(--radius-md)', padding: '1rem' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', color: 'var(--neon-cyan)', fontSize: '0.8rem', fontWeight: 700, textTransform: 'uppercase', marginBottom: '0.35rem' }}>
          <span>🛡️</span> Recommended Preventive Action
        </div>
        <div style={{ fontSize: '0.85rem', color: 'var(--text-secondary)', lineHeight: 1.45 }}>
          {action}
        </div>
      </div>
    </div>
  );
}
