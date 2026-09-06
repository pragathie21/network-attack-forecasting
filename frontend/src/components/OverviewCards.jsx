import React from 'react';

export default function OverviewCards({ summary, stats }) {
  const total = summary?.total_records || stats?.total_traffic_records || 0;
  const normal = summary?.normal_traffic || stats?.normal_traffic || 0;
  const suspicious = summary?.suspicious_traffic || stats?.suspicious_traffic || 0;
  const attacks = summary?.predicted_attacks || stats?.predicted_attacks || 0;
  const threat = summary?.impending_threat || stats?.active_threat || 'None';

  return (
    <section className="overview-grid">
      {/* Total Records */}
      <div className="stat-card">
        <div className="stat-header">
          <span>Total Traffic Records</span>
          <span>📁</span>
        </div>
        <div className="stat-value">{total.toLocaleString()}</div>
        <div className="stat-subtext">Ingested network flow records</div>
      </div>

      {/* Normal Traffic */}
      <div className="stat-card">
        <div className="stat-header">
          <span>Normal Traffic</span>
          <span style={{ color: 'var(--risk-low)' }}>●</span>
        </div>
        <div className="stat-value" style={{ color: 'var(--risk-low)' }}>
          {normal.toLocaleString()}
        </div>
        <div className="stat-subtext">
          {total > 0 ? `${Math.round((normal / total) * 100)}% of total volume` : 'Baseline flows'}
        </div>
      </div>

      {/* Suspicious Traffic */}
      <div className="stat-card">
        <div className="stat-header">
          <span>Suspicious Traffic</span>
          <span style={{ color: 'var(--risk-medium)' }}>▲</span>
        </div>
        <div className="stat-value" style={{ color: 'var(--risk-medium)' }}>
          {suspicious.toLocaleString()}
        </div>
        <div className="stat-subtext">Pre-attack probing / deviations</div>
      </div>

      {/* Predicted Attacks */}
      <div className="stat-card">
        <div className="stat-header">
          <span>Predicted Attacks</span>
          <span style={{ color: 'var(--risk-high)' }}>⚠️</span>
        </div>
        <div className="stat-value" style={{ color: 'var(--risk-high)' }}>
          {attacks.toLocaleString()}
        </div>
        <div className="stat-subtext">High-confidence malicious flows</div>
      </div>

      {/* Active / Impending Threat */}
      <div className="stat-card">
        <div className="stat-header">
          <span>Impending Threat</span>
          <span>🎯</span>
        </div>
        <div className="stat-value" style={{ fontSize: '1.4rem', color: threat === 'Benign' || threat === 'None' ? 'var(--text-secondary)' : 'var(--neon-cyan)' }}>
          {threat}
        </div>
        <div className="stat-subtext">
          {summary?.confidence ? `${Math.round(summary.confidence * 100)}% forecasting confidence` : 'Time-window analysis'}
        </div>
      </div>
    </section>
  );
}
