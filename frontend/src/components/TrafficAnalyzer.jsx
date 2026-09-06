import React, { useState, useRef } from 'react';
import { api, RAW_GITHUB_SAMPLE_URL, GITHUB_VIEW_URL } from '../services/api';

export default function TrafficAnalyzer({ onDataUpdated, isSimulating, onToggleSimulation }) {
  const [isUploading, setIsUploading] = useState(false);
  const [uploadStatus, setUploadStatus] = useState(null);
  const [isDragging, setIsDragging] = useState(false);
  const [activeSubTab, setActiveSubTab] = useState('upload'); // 'upload' | 'single'
  const [csvUrl, setCsvUrl] = useState('');
  const fileInputRef = useRef(null);

  // Single Flow Form State
  const [flowForm, setFlowForm] = useState({
    'Dst Port': 80,
    'Flow Duration': 120000,
    'Tot Fwd Pkts': 12,
    'Tot Bwd Pkts': 10,
    'TotLen Fwd Pkts': 900,
    'TotLen Bwd Pkts': 1400,
    'Flow Byts/s': 19000,
    'Flow Pkts/s': 180,
    'SYN Flag Cnt': 1,
    'RST Flag Cnt': 0,
    'ACK Flag Cnt': 15,
  });
  const [singleResult, setSingleResult] = useState(null);
  const [isPredictingSingle, setIsPredictingSingle] = useState(false);

  // CSV Drag and Drop Handlers
  const handleDragOver = (e) => {
    e.preventDefault();
    setIsDragging(true);
  };

  const handleDragLeave = () => {
    setIsDragging(false);
  };

  const handleDrop = async (e) => {
    e.preventDefault();
    setIsDragging(false);
    if (e.dataTransfer.files && e.dataTransfer.files[0]) {
      await processFileUpload(e.dataTransfer.files[0]);
    }
  };

  const handleFileSelect = async (e) => {
    if (e.target.files && e.target.files[0]) {
      const file = e.target.files[0];
      e.target.value = ''; // Reset so same file can be re-selected
      await processFileUpload(file);
    }
  };

  const processFileUpload = async (file) => {
    if (!file || !file.name.toLowerCase().endsWith('.csv')) {
      setUploadStatus({ type: 'error', message: 'Please select a valid CSV file (*.csv).' });
      return;
    }
    if (file.size === 0) {
      setUploadStatus({ type: 'error', message: 'The selected CSV file is empty (0 bytes).' });
      return;
    }
    setIsUploading(true);
    setUploadStatus(null);
    try {
      const res = await api.uploadTrafficCsv(file);
      setUploadStatus({
        type: 'success',
        message: `Successfully analyzed ${res.records_processed} flows from "${file.name}".`,
      });
      if (onDataUpdated) onDataUpdated(res.summary);
    } catch (err) {
      setUploadStatus({
        type: 'error',
        message: err.message || 'Failed to analyze traffic CSV.',
      });
    } finally {
      setIsUploading(false);
    }
  };

  const handleLoadSample = async () => {
    setIsUploading(true);
    setUploadStatus(null);
    try {
      const res = await api.loadSampleDataset();
      setUploadStatus({
        type: 'success',
        message: `Loaded demonstration dataset (${res.records_processed} network flows).`,
      });
      if (onDataUpdated) onDataUpdated(res.summary);
    } catch (err) {
      setUploadStatus({
        type: 'error',
        message: err.message || 'Failed to load demo dataset.',
      });
    } finally {
      setIsUploading(false);
    }
  };

  const handleDownloadSample = () => {
    // Attempt relative path first, fallback to raw GitHub link
    const link = document.createElement('a');
    link.href = './data/sample_cicids2018_test.csv';
    link.download = 'sample_cicids2018_test.csv';
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    setUploadStatus({
      type: 'success',
      message: 'Downloaded sample_cicids2018_test.csv. You can now drag and drop it into the analyzer.',
    });
  };

  const handleLoadUrl = async () => {
    if (!csvUrl.trim()) {
      setUploadStatus({ type: 'error', message: 'Please enter a valid CSV URL.' });
      return;
    }
    setIsUploading(true);
    setUploadStatus(null);
    try {
      const res = await api.loadCsvFromUrl(csvUrl);
      setUploadStatus({
        type: 'success',
        message: `Loaded ${res.records_processed} flows from remote CSV URL.`,
      });
      if (onDataUpdated) onDataUpdated(res.summary);
    } catch (err) {
      setUploadStatus({
        type: 'error',
        message: err.message || 'Failed to fetch CSV from URL.',
      });
    } finally {
      setIsUploading(false);
    }
  };

  const handlePredictSingle = async (e) => {
    e.preventDefault();
    setIsPredictingSingle(true);
    try {
      const res = await api.predictSingleFlow(flowForm);
      setSingleResult(res);
    } catch (err) {
      alert(`Prediction failed: ${err.message}`);
    } finally {
      setIsPredictingSingle(false);
    }
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
      {/* Tab Selector */}
      <div style={{ display: 'flex', gap: '0.6rem' }}>
        <button
          className={`btn-icon ${activeSubTab === 'upload' ? 'btn-primary' : ''}`}
          onClick={() => setActiveSubTab('upload')}
        >
          📁 Batch CSV Ingestion & Simulation
        </button>
        <button
          className={`btn-icon ${activeSubTab === 'single' ? 'btn-primary' : ''}`}
          onClick={() => setActiveSubTab('single')}
        >
          🔬 Single Flow Deep Inspector
        </button>
      </div>

      {activeSubTab === 'upload' && (
        <div className="soc-card">
          <div className="card-title-row">
            <h2 className="card-title">
              <span>⚡</span> Ingest Network Flow Data
            </h2>
            <div className="action-row">
              <button
                className={`btn-icon ${isSimulating ? 'btn-primary' : ''}`}
                onClick={onToggleSimulation}
              >
                <span className="status-pulse" style={{ background: isSimulating ? '#10b981' : '#64748b' }}></span>
                {isSimulating ? 'Pause Stream Simulation' : 'Start Live Stream Simulation'}
              </button>
              <button
                className="btn-secondary"
                onClick={handleLoadSample}
                disabled={isUploading}
                title="Directly load and analyze sample dataset"
              >
                Load Pre-Packaged CIC-IDS2018 Demo
              </button>
              <button
                className="btn-icon"
                onClick={handleDownloadSample}
                title="Download sample_cicids2018_test.csv to test drag-and-drop upload"
              >
                📥 Download Sample CSV
              </button>
            </div>
          </div>

          {/* Drag & Drop Box */}
          <div
            className={`upload-dropzone ${isDragging ? 'dragging' : ''}`}
            onDragOver={handleDragOver}
            onDragLeave={handleDragLeave}
            onDrop={handleDrop}
            onClick={() => fileInputRef.current?.click()}
          >
            <input
              type="file"
              ref={fileInputRef}
              style={{ display: 'none' }}
              accept=".csv"
              onChange={handleFileSelect}
            />
            <div style={{ fontSize: '2.5rem' }}>📤</div>
            <div style={{ fontSize: '1.1rem', fontWeight: 700 }}>
              {isUploading ? 'Analyzing Flow Telemetry...' : 'Drag and drop Network Traffic CSV here'}
            </div>
            <div style={{ fontSize: '0.85rem', color: 'var(--text-muted)' }}>
              Supports official CIC-IDS2018 schema and custom flow captures
            </div>
            <button className="btn-primary" style={{ marginTop: '0.5rem' }} disabled={isUploading}>
              {isUploading ? 'Processing...' : 'Browse CSV Files'}
            </button>
          </div>

          {/* Status Alert */}
          {uploadStatus && (
            <div
              style={{
                padding: '0.85rem 1.2rem',
                borderRadius: 'var(--radius-md)',
                background: uploadStatus.type === 'success' ? 'rgba(16, 185, 129, 0.1)' : 'rgba(239, 68, 68, 0.1)',
                border: `1px solid ${uploadStatus.type === 'success' ? 'var(--risk-low)' : 'var(--risk-high)'}`,
                color: uploadStatus.type === 'success' ? '#6ee7b7' : '#fca5a5',
                fontSize: '0.88rem',
              }}
            >
              {uploadStatus.type === 'success' ? '✅ ' : '❌ '} {uploadStatus.message}
            </div>
          )}

          {/* URL & GitHub Link Ingestion Card */}
          <div style={{ background: 'rgba(255,255,255,0.02)', padding: '1.1rem', borderRadius: 'var(--radius-md)', border: '1px solid var(--border-subtle)', display: 'flex', flexDirection: 'column', gap: '0.6rem' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '0.5rem' }}>
              <div style={{ fontSize: '0.88rem', fontWeight: 700, color: '#fff', display: 'flex', alignItems: 'center', gap: '0.4rem' }}>
                <span>🌐</span> Ingest CSV via Web or GitHub Link
              </div>
              <div style={{ display: 'flex', gap: '0.4rem' }}>
                <a
                  href={RAW_GITHUB_SAMPLE_URL}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="btn-icon"
                  style={{ fontSize: '0.75rem', padding: '0.25rem 0.55rem', textDecoration: 'none', color: 'var(--neon-cyan)', border: '1px solid rgba(0, 242, 254, 0.3)' }}
                >
                  Direct Raw CSV Link ↗
                </a>
                <button
                  type="button"
                  className="btn-icon"
                  style={{ fontSize: '0.75rem', padding: '0.25rem 0.55rem' }}
                  onClick={() => setCsvUrl(RAW_GITHUB_SAMPLE_URL)}
                >
                  Auto-fill Sample Link
                </button>
              </div>
            </div>

            <div style={{ display: 'flex', gap: '0.5rem', flexWrap: 'wrap' }}>
              <input
                type="url"
                placeholder="Paste CSV URL (e.g. raw GitHub or GitHub file link)..."
                value={csvUrl}
                onChange={(e) => setCsvUrl(e.target.value)}
                style={{
                  flex: '1 1 260px',
                  background: 'var(--bg-secondary)',
                  border: '1px solid var(--border-subtle)',
                  borderRadius: 'var(--radius-sm)',
                  padding: '0.5rem 0.8rem',
                  color: '#fff',
                  fontSize: '0.85rem',
                  fontFamily: 'var(--font-mono)'
                }}
              />
              <button
                type="button"
                className="btn-primary"
                onClick={handleLoadUrl}
                disabled={isUploading || !csvUrl.trim()}
                style={{ whiteSpace: 'nowrap' }}
              >
                {isUploading ? 'Fetching...' : 'Fetch & Ingest CSV'}
              </button>
            </div>

            <div style={{ fontSize: '0.78rem', color: 'var(--text-muted)', lineHeight: 1.4 }}>
              <strong>Notice:</strong> Standard GitHub links with <code>/blob/</code> contain HTML wrappers. Our system automatically rectifies them to <code>raw.githubusercontent.com</code> direct CSV data.
            </div>
          </div>

          {/* Simulation Info Callout */}
          <div style={{ background: 'rgba(255,255,255,0.02)', padding: '1rem', borderRadius: 'var(--radius-md)', border: '1px solid var(--border-subtle)', fontSize: '0.82rem', color: 'var(--text-secondary)' }}>
            <strong style={{ color: 'var(--neon-cyan)' }}>Proactive Forecasting Demo Tip:</strong> Clicking <em>"Start Live Stream Simulation"</em> mimics incoming live packets, demonstrating the full transition from <strong>Normal baseline (15% risk)</strong> → <strong>Reconnaissance / Probing (55% risk)</strong> → <strong>High-Impact Attack Wave (92% risk)</strong> → <strong>Mitigation</strong>.
          </div>
        </div>
      )}

      {activeSubTab === 'single' && (
        <div className="soc-card">
          <div className="card-title-row">
            <h2 className="card-title">
              <span>🔬</span> Test Individual Network Flow Parameters
            </h2>
            {/* Presets */}
            <div style={{ display: 'flex', gap: '0.4rem' }}>
              <button
                type="button"
                className="btn-icon"
                style={{ fontSize: '0.75rem' }}
                onClick={() => setFlowForm({
                  'Dst Port': 80,
                  'Flow Duration': 450000,
                  'Tot Fwd Pkts': 10,
                  'Tot Bwd Pkts': 8,
                  'TotLen Fwd Pkts': 700,
                  'TotLen Bwd Pkts': 1200,
                  'Flow Byts/s': 18000,
                  'Flow Pkts/s': 150,
                  'SYN Flag Cnt': 1,
                  'RST Flag Cnt': 0,
                  'ACK Flag Cnt': 14,
                })}
              >
                Preset: Benign
              </button>
              <button
                type="button"
                className="btn-icon"
                style={{ fontSize: '0.75rem' }}
                onClick={() => setFlowForm({
                  'Dst Port': 80,
                  'Flow Duration': 2500,
                  'Tot Fwd Pkts': 150,
                  'Tot Bwd Pkts': 0,
                  'TotLen Fwd Pkts': 8500,
                  'TotLen Bwd Pkts': 0,
                  'Flow Byts/s': 3400000,
                  'Flow Pkts/s': 60000,
                  'SYN Flag Cnt': 6,
                  'RST Flag Cnt': 2,
                  'ACK Flag Cnt': 0,
                })}
              >
                Preset: DDoS Flood
              </button>
              <button
                type="button"
                className="btn-icon"
                style={{ fontSize: '0.75rem' }}
                onClick={() => setFlowForm({
                  'Dst Port': 22,
                  'Flow Duration': 85000,
                  'Tot Fwd Pkts': 20,
                  'Tot Bwd Pkts': 18,
                  'TotLen Fwd Pkts': 1800,
                  'TotLen Bwd Pkts': 2200,
                  'Flow Byts/s': 47000,
                  'Flow Pkts/s': 440,
                  'SYN Flag Cnt': 1,
                  'RST Flag Cnt': 1,
                  'ACK Flag Cnt': 18,
                })}
              >
                Preset: SSH Brute Force
              </button>
            </div>
          </div>

          <form onSubmit={handlePredictSingle} style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))', gap: '1rem' }}>
            {Object.keys(flowForm).map((key) => (
              <div key={key} style={{ display: 'flex', flexDirection: 'column', gap: '0.3rem' }}>
                <label style={{ fontSize: '0.75rem', color: 'var(--text-secondary)' }}>{key}</label>
                <input
                  type="number"
                  step="any"
                  value={flowForm[key]}
                  onChange={(e) => setFlowForm({ ...flowForm, [key]: parseFloat(e.target.value) || 0 })}
                  style={{
                    background: 'var(--bg-secondary)',
                    border: '1px solid var(--border-subtle)',
                    borderRadius: 'var(--radius-sm)',
                    padding: '0.5rem',
                    color: '#fff',
                    fontFamily: 'var(--font-mono)',
                    fontSize: '0.85rem',
                  }}
                />
              </div>
            ))}

            <div style={{ gridColumn: '1 / -1', marginTop: '0.5rem' }}>
              <button type="submit" className="btn-primary" disabled={isPredictingSingle}>
                {isPredictingSingle ? 'Analyzing...' : 'Run AI Flow Inference'}
              </button>
            </div>
          </form>

          {/* Single Prediction Output */}
          {singleResult && (
            <div style={{ marginTop: '1rem', background: 'rgba(0,242,254,0.04)', border: '1px solid var(--border-active)', borderRadius: 'var(--radius-md)', padding: '1.2rem', display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <div style={{ fontSize: '1.1rem', fontWeight: 700, color: singleResult.risk_level === 'HIGH' ? 'var(--risk-high)' : singleResult.risk_level === 'MEDIUM' ? 'var(--risk-medium)' : 'var(--risk-low)' }}>
                  Prediction: {singleResult.prediction}
                </div>
                <div className={`status-pill ${singleResult.risk_level.toLowerCase()}`}>
                  Risk: {singleResult.risk_score}% ({singleResult.risk_level})
                </div>
              </div>

              <div style={{ fontSize: '0.85rem', color: 'var(--text-secondary)' }}>
                <strong>Forecast:</strong> {singleResult.forecast}
              </div>

              <div style={{ fontSize: '0.85rem', color: 'var(--text-muted)' }}>
                <strong>Mitigation:</strong> {singleResult.recommended_action}
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
