import React from 'react';

export default function Sidebar({ activeTab, setActiveTab, alertCount = 0 }) {
  const navItems = [
    { id: 'overview', label: 'SOC Overview', icon: '📊' },
    { id: 'risk', label: 'Risk Monitoring', icon: '🎯' },
    { id: 'forecast', label: 'Attack Forecast', icon: '🔮' },
    { id: 'analytics', label: 'Traffic Analytics', icon: '📈' },
    { id: 'alerts', label: 'Early Warning Alerts', icon: '🚨', badge: alertCount },
    { id: 'ingest', label: 'Dataset & Simulator', icon: '⚡' },
  ];

  return (
    <aside className="soc-sidebar">
      <div style={{ padding: '0.5rem 1rem 1rem', fontSize: '0.75rem', fontWeight: 600, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.06em' }}>
        Intelligence Console
      </div>
      {navItems.map((item) => (
        <button
          key={item.id}
          className={`nav-item ${activeTab === item.id ? 'active' : ''}`}
          onClick={() => setActiveTab(item.id)}
        >
          <span>{item.icon}</span>
          <span>{item.label}</span>
          {item.badge > 0 && (
            <span className="nav-item-badge">{item.badge}</span>
          )}
        </button>
      ))}

      <div style={{ marginTop: 'auto', padding: '1rem', background: 'rgba(255,255,255,0.02)', borderRadius: 'var(--radius-md)', border: '1px solid var(--border-subtle)', fontSize: '0.75rem', color: 'var(--text-muted)' }}>
        <div style={{ fontWeight: 600, color: 'var(--neon-cyan)', marginBottom: '0.2rem' }}>CIC-IDS2018 Engine</div>
        <div>Model: Random Forest</div>
        <div>Inference: Multi-Class & Window Trend</div>
      </div>
    </aside>
  );
}
