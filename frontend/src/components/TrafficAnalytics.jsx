import React, { useState } from 'react';

export default function TrafficAnalytics({ summary }) {
  const [chartMode, setChartMode] = useState('volume'); // 'volume' or 'risk'
  const timeSeries = summary?.time_series || [];
  const distribution = summary?.attack_distribution || {};

  // Attack categories color palette
  const attackColors = {
    'DDoS': '#ef4444',
    'DoS': '#f97316',
    'Brute Force': '#eab308',
    'Botnet': '#a855f7',
    'Infiltration': '#06b6d4',
    'Web Attack': '#ec4899',
    'Benign': '#10b981',
  };

  const totalAttacks = Object.entries(distribution)
    .filter(([k]) => k !== 'Benign')
    .reduce((sum, [, v]) => sum + v, 0);

  // SVG Chart Geometry
  const width = 640;
  const height = 220;
  const padding = { top: 20, right: 30, bottom: 35, left: 45 };
  const chartW = width - padding.left - padding.right;
  const chartH = height - padding.top - padding.bottom;

  // Compute Scales
  const maxFlows = Math.max(10, ...timeSeries.map(d => d.total_flows || 0));
  const pointsCount = Math.max(1, timeSeries.length);

  // Helper coordinate getters
  const getX = (idx) => padding.left + (idx / Math.max(1, pointsCount - 1)) * chartW;
  const getYFlow = (val) => padding.top + chartH - (val / maxFlows) * chartH;
  const getYRisk = (risk) => padding.top + chartH - (risk / 100) * chartH;

  // Generate SVG Path for Risk Trend
  const riskPath = timeSeries.length > 0
    ? timeSeries.map((d, i) => `${i === 0 ? 'M' : 'L'} ${getX(i)} ${getYRisk(d.risk_score)}`).join(' ')
    : '';

  // Generate Area Fill under Risk Curve
  const riskArea = timeSeries.length > 0
    ? `${riskPath} L ${getX(timeSeries.length - 1)} ${padding.top + chartH} L ${getX(0)} ${padding.top + chartH} Z`
    : '';

  return (
    <div className="charts-grid">
      {/* Time-Series Chart Card */}
      <div className="soc-card">
        <div className="card-title-row">
          <h2 className="card-title">
            <span>📈</span> Traffic Flow Dynamics & Risk Trend
          </h2>
          <div style={{ display: 'flex', gap: '0.4rem' }}>
            <button
              className={`btn-icon ${chartMode === 'volume' ? 'btn-primary' : ''}`}
              onClick={() => setChartMode('volume')}
              style={{ fontSize: '0.75rem', padding: '0.3rem 0.65rem' }}
            >
              Flow Volume
            </button>
            <button
              className={`btn-icon ${chartMode === 'risk' ? 'btn-primary' : ''}`}
              onClick={() => setChartMode('risk')}
              style={{ fontSize: '0.75rem', padding: '0.3rem 0.65rem' }}
            >
              Risk Trend
            </button>
          </div>
        </div>

        {timeSeries.length === 0 ? (
          <div style={{ display: 'flex', height: '220px', alignItems: 'center', justifyContent: 'center', color: 'var(--text-muted)' }}>
            Awaiting traffic flow data... Upload CSV or trigger Live Simulation.
          </div>
        ) : (
          <div className="svg-chart-container">
            <svg className="chart-svg" viewBox={`0 0 ${width} ${height}`}>
              <defs>
                <linearGradient id="riskFillGrad" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="0%" stopColor="#ef4444" stopOpacity="0.4" />
                  <stop offset="50%" stopColor="#f59e0b" stopOpacity="0.2" />
                  <stop offset="100%" stopColor="#10b981" stopOpacity="0.0" />
                </linearGradient>
                <linearGradient id="attackBarGrad" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="0%" stopColor="#ef4444" stopOpacity="0.9" />
                  <stop offset="100%" stopColor="#b91c1c" stopOpacity="0.7" />
                </linearGradient>
                <linearGradient id="normalBarGrad" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="0%" stopColor="#10b981" stopOpacity="0.9" />
                  <stop offset="100%" stopColor="#047857" stopOpacity="0.7" />
                </linearGradient>
              </defs>

              {/* Grid Lines */}
              {[0, 0.25, 0.5, 0.75, 1].map((ratio, idx) => {
                const y = padding.top + chartH * (1 - ratio);
                const label = chartMode === 'volume' ? Math.round(maxFlows * ratio) : `${Math.round(ratio * 100)}%`;
                return (
                  <g key={idx}>
                    <line
                      x1={padding.left}
                      y1={y}
                      x2={width - padding.right}
                      y2={y}
                      stroke="rgba(255, 255, 255, 0.06)"
                      strokeDasharray="4 4"
                    />
                    <text
                      x={padding.left - 8}
                      y={y + 3}
                      fill="#64748b"
                      fontSize="10"
                      textAnchor="end"
                      fontFamily="var(--font-mono)"
                    >
                      {label}
                    </text>
                  </g>
                );
              })}

              {/* Volume Stacked Bars Mode */}
              {chartMode === 'volume' && (
                <g>
                  {timeSeries.map((d, i) => {
                    const barW = Math.max(6, Math.min(28, (chartW / pointsCount) * 0.65));
                    const x = getX(i) - barW / 2;
                    const normalH = (d.normal_flows / maxFlows) * chartH;
                    const attackH = (d.attack_flows / maxFlows) * chartH;
                    const normalY = padding.top + chartH - normalH;
                    const attackY = normalY - attackH;

                    return (
                      <g key={i} className="chart-bar-group">
                        {/* Normal Flow Bar */}
                        {normalH > 0 && (
                          <rect
                            x={x}
                            y={normalY}
                            width={barW}
                            height={normalH}
                            fill="url(#normalBarGrad)"
                            rx="2"
                          />
                        )}
                        {/* Attack Flow Bar */}
                        {attackH > 0 && (
                          <rect
                            x={x}
                            y={attackY}
                            width={barW}
                            height={attackH}
                            fill="url(#attackBarGrad)"
                            rx="2"
                          />
                        )}
                      </g>
                    );
                  })}
                </g>
              )}

              {/* Risk Trend Curve Mode */}
              {chartMode === 'risk' && (
                <g>
                  <path d={riskArea} fill="url(#riskFillGrad)" />
                  <path
                    d={riskPath}
                    fill="none"
                    stroke="#00f2fe"
                    strokeWidth="3"
                    strokeLinecap="round"
                    strokeLinejoin="round"
                  />
                  {timeSeries.map((d, i) => (
                    <circle
                      key={i}
                      cx={getX(i)}
                      cy={getYRisk(d.risk_score)}
                      r="4"
                      fill={d.risk_score >= 70 ? '#ef4444' : d.risk_score >= 30 ? '#f59e0b' : '#10b981'}
                      stroke="#0d1322"
                      strokeWidth="2"
                    />
                  ))}
                </g>
              )}

              {/* X-Axis Labels */}
              {timeSeries.map((d, i) => {
                if (pointsCount > 8 && i % Math.ceil(pointsCount / 6) !== 0 && i !== pointsCount - 1) return null;
                return (
                  <text
                    key={i}
                    x={getX(i)}
                    y={padding.top + chartH + 18}
                    fill="#94a3b8"
                    fontSize="10"
                    textAnchor="middle"
                    fontFamily="var(--font-mono)"
                  >
                    {d.time}
                  </text>
                );
              })}
            </svg>
          </div>
        )}

        {/* Legend */}
        <div style={{ display: 'flex', gap: '1.25rem', justifyContent: 'center', fontSize: '0.75rem', color: 'var(--text-secondary)' }}>
          {chartMode === 'volume' ? (
            <>
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.4rem' }}>
                <span style={{ width: '10px', height: '10px', borderRadius: '2px', background: 'var(--risk-low)' }}></span>
                Normal Flows
              </div>
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.4rem' }}>
                <span style={{ width: '10px', height: '10px', borderRadius: '2px', background: 'var(--risk-high)' }}></span>
                Attack Flows
              </div>
            </>
          ) : (
            <>
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.4rem' }}>
                <span style={{ width: '12px', height: '3px', background: 'var(--neon-cyan)' }}></span>
                Time-Window Risk Curve (%)
              </div>
            </>
          )}
        </div>
      </div>

      {/* Attack Distribution Breakdown Card */}
      <div className="soc-card">
        <div className="card-title-row">
          <h2 className="card-title">
            <span>🛡️</span> Threat Vector Breakdown
          </h2>
          <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>
            {totalAttacks} malicious flows
          </span>
        </div>

        {Object.keys(distribution).length === 0 ? (
          <div style={{ display: 'flex', height: '220px', alignItems: 'center', justifyContent: 'center', color: 'var(--text-muted)' }}>
            No attack vectors recorded yet.
          </div>
        ) : (
          <div className="dist-list">
            {Object.entries(distribution)
              .filter(([name]) => name !== 'Benign')
              .map(([name, count]) => {
                const pct = totalAttacks > 0 ? Math.round((count / totalAttacks) * 100) : 0;
                const color = attackColors[name] || 'var(--neon-cyan)';

                return (
                  <div key={name} className="dist-item">
                    <div className="dist-header">
                      <span style={{ display: 'flex', alignItems: 'center', gap: '0.4rem' }}>
                        <span style={{ width: '8px', height: '8px', borderRadius: '50%', background: color }}></span>
                        {name}
                      </span>
                      <span style={{ fontFamily: 'var(--font-mono)', color: 'var(--text-secondary)' }}>
                        {count} ({pct}%)
                      </span>
                    </div>
                    <div className="dist-bar-track">
                      <div
                        className="dist-bar-fill"
                        style={{ width: `${pct}%`, background: color }}
                      ></div>
                    </div>
                  </div>
                );
              })}
          </div>
        )}
      </div>
    </div>
  );
}
