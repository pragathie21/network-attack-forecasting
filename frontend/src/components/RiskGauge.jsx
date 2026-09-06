import React from 'react';

export default function RiskGauge({ riskScore = 15, riskLevel = 'LOW', probability = 0.85 }) {
  // Arc math for semi-circle
  // Radius = 85, Center = (120, 105)
  // Stroke perimeter for half circle = PI * 85 ~= 267
  const radius = 85;
  const circumference = Math.PI * radius;
  const safeScore = Math.min(100, Math.max(0, riskScore));
  const strokeDashoffset = circumference - (circumference * safeScore) / 100;

  const levelLower = riskLevel.toLowerCase();
  const strokeColor = 
    levelLower === 'high' ? 'var(--risk-high)' : 
    levelLower === 'medium' ? 'var(--risk-medium)' : 'var(--risk-low)';

  const glowColor = 
    levelLower === 'high' ? 'var(--risk-high-glow)' : 
    levelLower === 'medium' ? 'var(--risk-medium-glow)' : 'var(--risk-low-glow)';

  return (
    <div className="soc-card" style={{ height: '100%' }}>
      <div className="card-title-row">
        <h2 className="card-title">
          <span>🎯</span> Real-Time Risk Monitor
        </h2>
        <span className={`status-pill ${levelLower}`}>
          {riskLevel} RISK
        </span>
      </div>

      <div className="gauge-container">
        <svg className="gauge-svg" viewBox="0 0 240 140">
          {/* Defs for Glow Filter */}
          <defs>
            <filter id="gaugeGlow" x="-20%" y="-20%" width="140%" height="140%">
              <feGaussianBlur stdDeviation="6" result="blur" />
              <feComposite in="SourceGraphic" in2="blur" operator="over" />
            </filter>
          </defs>

          {/* Background Arc */}
          <path
            d="M 35 110 A 85 85 0 0 1 205 110"
            fill="none"
            stroke="rgba(255, 255, 255, 0.08)"
            strokeWidth="16"
            strokeLinecap="round"
          />

          {/* Segment ticks */}
          <circle cx="35" cy="110" r="3" fill="#64748b" />
          <circle cx="120" cy="25" r="3" fill="#64748b" />
          <circle cx="205" cy="110" r="3" fill="#64748b" />

          {/* Value Arc with Glow */}
          <path
            d="M 35 110 A 85 85 0 0 1 205 110"
            fill="none"
            stroke={strokeColor}
            strokeWidth="16"
            strokeLinecap="round"
            strokeDasharray={circumference}
            strokeDashoffset={strokeDashoffset}
            filter="url(#gaugeGlow)"
            style={{ transition: 'stroke-dashoffset 0.8s cubic-bezier(0.16, 1, 0.3, 1), stroke 0.4s ease' }}
          />
        </svg>

        {/* Center Text */}
        <div className="gauge-meter-val">
          <div className={`gauge-score ${levelLower}`}>
            {Math.round(safeScore)}%
          </div>
          <div className="gauge-badge" style={{ background: `${strokeColor}22`, color: strokeColor }}>
            STATUS: {riskLevel}
          </div>
        </div>
      </div>

      {/* Metrics Row */}
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0.75rem', marginTop: 'auto', borderTop: '1px solid var(--border-subtle)', paddingTop: '0.85rem' }}>
        <div>
          <div style={{ fontSize: '0.7rem', color: 'var(--text-muted)', textTransform: 'uppercase' }}>Attack Probability</div>
          <div style={{ fontSize: '1.1rem', fontWeight: 700, fontFamily: 'var(--font-mono)' }}>
            {(probability * 100).toFixed(1)}%
          </div>
        </div>
        <div>
          <div style={{ fontSize: '0.7rem', color: 'var(--text-muted)', textTransform: 'uppercase' }}>Threshold Tier</div>
          <div style={{ fontSize: '0.9rem', fontWeight: 600, color: strokeColor }}>
            {safeScore < 30 ? '< 30% (Nominal)' : safeScore < 70 ? '30-70% (Elevated)' : '> 70% (Critical)'}
          </div>
        </div>
      </div>
    </div>
  );
}
