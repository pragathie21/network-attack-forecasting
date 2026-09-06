// Determine API base URL dynamically:
// In local dev (port 5173), target backend on port 8000.
// In production/deployment (unified server), use relative '/api' so it works on any domain or public URL!
const API_BASE_URL = 
  (typeof window !== 'undefined' && window.location.port === '5173')
    ? 'http://127.0.0.1:8000/api'
    : '/api';

async function request(endpoint, options = {}) {
  try {
    const res = await fetch(`${API_BASE_URL}${endpoint}`, options);
    if (!res.ok) {
      const errData = await res.json().catch(() => ({}));
      throw new Error(errData.detail || `Request failed with status ${res.status}`);
    }
    return await res.json();
  } catch (err) {
    console.error(`API Error on ${endpoint}:`, err);
    throw err;
  }
}

export const api = {
  // System Health
  getHealth: () => request('/health'),

  // Traffic Stats & Overview
  getTrafficStats: () => request('/traffic-stats'),

  // Time-Window Forecasting
  getCurrentForecast: () => request('/forecast/current'),
  simulateStep: () => request('/forecast/simulate-step', { method: 'POST' }),
  resetSimulation: () => request('/forecast/reset', { method: 'POST' }),

  // Alerts & MITRE ATT&CK
  getAlerts: (limit = 30) => request(`/alerts?limit=${limit}`),
  getMitreMatrix: () => request('/alerts/mitre-matrix'),

  // Historical Traffic Logs
  getHistory: (limit = 50) => request(`/history?limit=${limit}`),

  // Ingestion & Inferences
  loadSampleDataset: () => request('/load-sample'),
  
  uploadTrafficCsv: async (file) => {
    const formData = new FormData();
    formData.append('file', file);
    return request('/upload-traffic', {
      method: 'POST',
      body: formData,
    });
  },

  predictSingleFlow: (flowData) => {
    return request('/predict-flow', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(flowData),
    });
  },
};
