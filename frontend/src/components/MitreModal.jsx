import React from 'react';

export default function MitreModal({ mitreData, onClose }) {
  if (!mitreData) return null;

  return (
    <div className="modal-overlay" onClick={onClose}>
      <div className="modal-card" onClick={(e) => e.stopPropagation()}>
        <div className="modal-header">
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.6rem' }}>
            <span style={{ fontSize: '1.4rem' }}>🛡️</span>
            <div>
              <h2 style={{ fontFamily: 'var(--font-heading)', fontSize: '1.25rem', color: '#fff' }}>
                MITRE ATT&CK Playbook
              </h2>
              <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
                Technique Reference & Incident Response Playbook
              </div>
            </div>
          </div>
          <button className="btn-close" onClick={onClose}>&times;</button>
        </div>

        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1rem', background: 'rgba(255,255,255,0.02)', padding: '1rem', borderRadius: 'var(--radius-md)', border: '1px solid var(--border-subtle)' }}>
          <div>
            <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', textTransform: 'uppercase' }}>Technique ID</div>
            <div style={{ fontSize: '1.2rem', fontWeight: 700, color: 'var(--neon-cyan)', fontFamily: 'var(--font-mono)' }}>
              {mitreData.technique_id}
            </div>
          </div>
          <div>
            <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', textTransform: 'uppercase' }}>Threat Category</div>
            <div style={{ fontSize: '1rem', fontWeight: 600, color: '#fff' }}>
              {mitreData.attack_type}
            </div>
          </div>
        </div>

        <div>
          <div style={{ fontSize: '0.8rem', fontWeight: 600, color: 'var(--text-secondary)', textTransform: 'uppercase', marginBottom: '0.4rem' }}>
            Technique Name
          </div>
          <div style={{ fontSize: '0.95rem', color: '#fff', fontWeight: 600 }}>
            {mitreData.technique_name}
          </div>
        </div>

        <div>
          <div style={{ fontSize: '0.8rem', fontWeight: 600, color: 'var(--text-secondary)', textTransform: 'uppercase', marginBottom: '0.4rem' }}>
            Recommended Incident Response Playbook
          </div>
          <div style={{ background: 'rgba(0, 242, 254, 0.05)', border: '1px solid rgba(0, 242, 254, 0.3)', padding: '1rem', borderRadius: 'var(--radius-md)', fontSize: '0.88rem', color: '#e2e8f0', lineHeight: 1.5 }}>
            {mitreData.recommended_action}
          </div>
        </div>

        <div style={{ display: 'flex', justifyContent: 'flex-end', marginTop: '0.5rem' }}>
          <button className="btn-primary" onClick={onClose}>
            Acknowledge & Close
          </button>
        </div>
      </div>
    </div>
  );
}
