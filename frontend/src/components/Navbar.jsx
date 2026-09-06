import React from 'react';

export default function Navbar({ trafficStats, apiOnline, engineMode, onQuickLoadSample, isSimulating, onToggleSimulation }) {
  const status = trafficStats?.network_status || 'PROTECTED';
  const statusClass = status.toLowerCase().replace(' ', '_');

  const modeLabel = engineMode === 'backend' 
    ? 'BACKEND API ONLINE' 
    : (apiOnline ? 'BROWSER AI ENGINE' : 'OFFLINE');
  const modeColor = engineMode === 'backend' 
    ? '#10b981' 
    : (apiOnline ? '#00f2fe' : '#ef4444');

  return (
    <header className="soc-navbar">
      <div className="nav-brand">
        <div className="brand-icon-wrapper">
          <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
            <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" stroke="#00f2fe" fill="rgba(0, 242, 254, 0.2)" />
            <path d="m9 12 2 2 4-4" stroke="#00f2fe" />
          </svg>
        </div>
        <div>
          <h1 className="brand-title">AI CYBERWATCH</h1>
          <div className="brand-subtitle">Network Attack Forecasting & Threat Intelligence</div>
        </div>
      </div>

      <div className="nav-actions">
        {/* Live Simulation Button */}
        <button 
          className={`btn-icon ${isSimulating ? 'btn-primary' : ''}`}
          onClick={onToggleSimulation}
          title={isSimulating ? "Pause real-time stream simulation" : "Start real-time stream simulation"}
        >
          <span className="status-pulse" style={{ background: isSimulating ? '#10b981' : '#64748b' }}></span>
          {isSimulating ? 'Simulation Active' : 'Simulate Stream'}
        </button>

        {/* 1-Click Demo Loader */}
        <button 
          className="btn-icon" 
          onClick={onQuickLoadSample}
          title="Load pre-packaged CIC-IDS2018 test dataset"
        >
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
            <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4" />
            <polyline points="7 10 12 15 17 10" />
            <line x1="12" y1="15" x2="12" y2="3" />
          </svg>
          Load Demo Dataset
        </button>

        {/* Network Threat Status Pill */}
        <div className={`status-pill ${statusClass}`}>
          <span className="status-pulse"></span>
          {status}
        </div>

        {/* API / Engine Health */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.4rem', fontSize: '0.75rem', color: modeColor }}>
          <span style={{ width: '6px', height: '6px', borderRadius: '50%', background: modeColor }}></span>
          {modeLabel}
        </div>
      </div>
    </header>
  );
}
