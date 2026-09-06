import React from 'react';

export default function AlertsTable({ alerts = [], onSelectMitre }) {
  return (
    <div className="soc-card">
      <div className="card-title-row">
        <h2 className="card-title">
          <span>🚨</span> Early Warning Alerts & MITRE ATT&CK Mapping
        </h2>
        <span style={{ fontSize: '0.8rem', color: 'var(--text-secondary)' }}>
          {alerts.length} Early Warning Triggers
        </span>
      </div>

      {alerts.length === 0 ? (
        <div style={{ padding: '2.5rem', textAlign: 'center', color: 'var(--text-muted)' }}>
          <div>🛡️ No critical early warning alerts active.</div>
          <div style={{ fontSize: '0.8rem', marginTop: '0.4rem' }}>
            System telemetry indicates traffic flows are operating within baseline thresholds.
          </div>
        </div>
      ) : (
        <div className="table-container">
          <table className="soc-table">
            <thead>
              <tr>
                <th>Timestamp</th>
                <th>Severity</th>
                <th>Threat Vector</th>
                <th>MITRE ATT&CK</th>
                <th>Early Warning Message</th>
                <th>Recommended Action</th>
                <th>Action</th>
              </tr>
            </thead>
            <tbody>
              {alerts.map((alert, idx) => {
                const sevLower = (alert.severity || 'medium').toLowerCase();

                return (
                  <tr key={alert.id || idx}>
                    <td style={{ fontFamily: 'var(--font-mono)', fontSize: '0.78rem', color: 'var(--text-muted)', whiteSpace: 'nowrap' }}>
                      {alert.timestamp}
                    </td>
                    <td>
                      <span className={`status-pill ${sevLower}`} style={{ fontSize: '0.7rem', padding: '0.2rem 0.6rem' }}>
                        {alert.severity}
                      </span>
                    </td>
                    <td style={{ fontWeight: 600 }}>
                      {alert.attack_type}
                    </td>
                    <td>
                      <button
                        className="badge-mitre"
                        onClick={() => onSelectMitre({
                          technique_id: alert.mitre_id,
                          technique_name: alert.mitre_name,
                          attack_type: alert.attack_type,
                          recommended_action: alert.recommended_action
                        })}
                        title="View MITRE Playbook & Mitigation"
                      >
                        <span>🔗</span> {alert.mitre_id || 'T1000'}
                      </button>
                    </td>
                    <td style={{ maxWidth: '280px', fontSize: '0.8rem', color: 'var(--text-secondary)' }}>
                      {alert.alert_message}
                    </td>
                    <td style={{ maxWidth: '260px', fontSize: '0.8rem', color: 'var(--text-muted)' }}>
                      {alert.recommended_action}
                    </td>
                    <td>
                      <button
                        className="btn-icon"
                        style={{ fontSize: '0.75rem', padding: '0.25rem 0.55rem' }}
                        onClick={() => onSelectMitre({
                          technique_id: alert.mitre_id,
                          technique_name: alert.mitre_name,
                          attack_type: alert.attack_type,
                          recommended_action: alert.recommended_action
                        })}
                      >
                        Playbook
                      </button>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
