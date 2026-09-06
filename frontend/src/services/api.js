/**
 * AI CyberWatch API Service Layer
 * Supports dual-mode operation:
 * 1. Live Backend Mode: connects to FastAPI backend via VITE_API_URL or local dev server.
 * 2. Client-Side Edge Mode: runs real 120-tree Random Forest ML inference in the browser
 *    when deployed on static hosting (e.g., GitHub Pages) without making failing POST calls.
 */

import {
  clientProcessCsv,
  clientPredictSingle,
  getMitreMapping,
  analyzeTrafficWindows
} from './clientMlPipeline.js';
import rfBundle from './rf_model_bundle.js';

// Canonical GitHub links for CIC-IDS2018 sample CSV
export const RAW_GITHUB_SAMPLE_URL = 'https://raw.githubusercontent.com/pragathie21/network-attack-forecasting/main/backend/data/sample_cicids2018_test.csv';
export const GITHUB_VIEW_URL = 'https://github.com/pragathie21/network-attack-forecasting/blob/main/backend/data/sample_cicids2018_test.csv';

/**
 * Rectifies any GitHub web link (blob/raw viewer) to the direct raw downloadable content URL.
 * Example: https://github.com/user/repo/blob/main/path/to.csv -> https://raw.githubusercontent.com/user/repo/main/path/to.csv
 */
export function rectifyGitHubUrl(url) {
  if (!url || typeof url !== 'string') return url;
  let cleanUrl = url.trim();
  if (cleanUrl.includes('github.com/') && cleanUrl.includes('/blob/')) {
    cleanUrl = cleanUrl
      .replace('github.com/', 'raw.githubusercontent.com/')
      .replace('/blob/', '/');
  } else if (cleanUrl.includes('github.com/') && !cleanUrl.includes('raw.githubusercontent.com') && cleanUrl.includes('/raw/')) {
    cleanUrl = cleanUrl
      .replace('github.com/', 'raw.githubusercontent.com/')
      .replace('/raw/', '/');
  }
  return cleanUrl;
}

// Resolve environment and backend target URL
const ENV_API_URL = typeof import.meta !== 'undefined' && import.meta.env ? import.meta.env.VITE_API_URL : null;

const isBrowser = typeof window !== 'undefined';
const isLocalDev = isBrowser && (
  window.location.port === '5173' ||
  window.location.hostname === 'localhost' ||
  window.location.hostname === '127.0.0.1'
);
const isGitHubPages = isBrowser && (
  window.location.hostname.endsWith('github.io') ||
  window.location.hostname.includes('pages.dev')
);

// Determine API base URL
let API_BASE_URL = '';
let isStaticMode = false;

if (ENV_API_URL && ENV_API_URL.trim() !== '') {
  API_BASE_URL = ENV_API_URL.trim().replace(/\/+$/, '');
  isStaticMode = false;
} else if (isLocalDev) {
  API_BASE_URL = 'http://127.0.0.1:8000/api';
  isStaticMode = false;
} else {
  // Static deployment (e.g., GitHub Pages) without an explicit external backend
  isStaticMode = true;
  API_BASE_URL = '';
}

// In-memory state for client-side mode
const clientState = {
  activeSummary: null,
  processedRecords: [],
  alerts: [],
  simStep: 0
};

async function request(endpoint, options = {}) {
  if (isStaticMode || !API_BASE_URL) {
    throw new Error(`Static hosting active; direct backend call to ${endpoint} skipped.`);
  }

  const url = `${API_BASE_URL}${endpoint}`;
  const res = await fetch(url, options);
  if (!res.ok) {
    const errData = await res.json().catch(() => ({}));
    throw new Error(errData.detail || `Request failed with status ${res.status}`);
  }
  return await res.json();
}

/**
 * Updates client in-memory state after a CSV is analyzed.
 */
function updateClientState(processResult) {
  clientState.activeSummary = processResult.summary;
  if (processResult.flow_results && processResult.flow_results.length > 0) {
    clientState.processedRecords = [
      ...processResult.flow_results.slice(0, 100),
      ...clientState.processedRecords
    ].slice(0, 200);
  }
  if (processResult.summary.recent_alerts && processResult.summary.recent_alerts.length > 0) {
    clientState.alerts = processResult.summary.recent_alerts;
  }
}

/**
 * Computes global traffic stats from client state.
 */
function computeClientTrafficStats() {
  const summary = clientState.activeSummary;
  const records = clientState.processedRecords;
  const total = records.length > 0 ? records.length : (summary?.total_records || 90);
  const normal = summary?.normal_traffic ?? Math.round(total * 0.6);
  const attacks = summary?.predicted_attacks ?? (total - normal);
  const suspicious = summary?.suspicious_traffic ?? Math.round(attacks * 0.4);
  const riskScore = summary?.current_risk_score ?? 18.5;
  const riskLevel = summary?.risk_level ?? "LOW";
  const activeThreat = summary?.impending_threat ?? "None";
  const forecast = summary?.forecast_status ?? "Normal baseline traffic. In-browser AI active.";

  const networkStatus = riskLevel === "LOW" ? "PROTECTED" : (riskLevel === "MEDIUM" ? "ELEVATED" : "UNDER ATTACK");

  return {
    network_status: networkStatus,
    total_traffic_records: total,
    normal_traffic: normal,
    suspicious_traffic: suspicious,
    predicted_attacks: attacks,
    current_risk_score: riskScore,
    risk_level: riskLevel,
    active_threat: activeThreat,
    forecast: forecast,
    last_updated: "In-Browser Edge AI Engine"
  };
}

export const api = {
  isStaticMode: () => isStaticMode,
  getBaseUrl: () => API_BASE_URL,

  // System Health
  getHealth: async () => {
    if (!isStaticMode && API_BASE_URL) {
      try {
        const data = await request('/health');
        return { ...data, mode: 'backend' };
      } catch (err) {
        console.warn('Backend /health unreachable, falling back to client mode:', err.message);
      }
    }
    return {
      status: 'HEALTHY',
      model_loaded: true,
      database: 'IN_MEMORY',
      mode: 'client',
      engine: 'In-Browser AI (120-Tree Random Forest)',
      supported_attacks: rfBundle.classes
    };
  },

  // Traffic Stats & Overview
  getTrafficStats: async () => {
    if (!isStaticMode && API_BASE_URL) {
      try {
        return await request('/traffic-stats');
      } catch (err) {
        console.warn('Backend /traffic-stats unreachable, calculating from client state:', err.message);
      }
    }
    return computeClientTrafficStats();
  },

  // Time-Window Forecasting
  getCurrentForecast: async () => {
    if (!isStaticMode && API_BASE_URL) {
      try {
        return await request('/forecast/current');
      } catch (err) {
        console.warn('Backend /forecast/current unreachable, using client state:', err.message);
      }
    }
    return clientState.activeSummary || analyzeTrafficWindows(clientState.processedRecords);
  },

  simulateStep: async () => {
    if (!isStaticMode && API_BASE_URL) {
      try {
        return await request('/forecast/simulate-step', { method: 'POST' });
      } catch (err) {
        console.warn('Backend simulateStep unreachable, simulating in client:', err.message);
      }
    }

    clientState.simStep = (clientState.simStep + 1) % 4;
    const step = clientState.simStep;
    const scenarios = [
      { threat: "Benign", risk: 14.2, level: "LOW", trend: "STABLE", status: "NORMAL: Traffic Baseline Nominal", flows: 10, attacks: 0 },
      { threat: "Botnet", risk: 44.8, level: "MEDIUM", trend: "RISING", status: "EARLY WARNING: Suspicious Botnet Signature Rising", flows: 12, attacks: 4 },
      { threat: "DDoS", risk: 91.5, level: "HIGH", trend: "SURGING", status: "CRITICAL FORECAST: Active DDoS Flood Attack Escalation", flows: 20, attacks: 18 },
      { threat: "Benign", risk: 21.0, level: "LOW", trend: "DECLINING", status: "RECOVERY: Threat Scrubbed, Traffic Stabilizing", flows: 10, attacks: 1 },
    ];
    const s = scenarios[step];

    const updatedSummary = {
      window_size: 15,
      total_records: (clientState.activeSummary?.total_records || 90) + s.flows,
      normal_traffic: (clientState.activeSummary?.normal_traffic || 50) + (s.flows - s.attacks),
      suspicious_traffic: s.attacks > 0 ? s.attacks : 2,
      predicted_attacks: (clientState.activeSummary?.predicted_attacks || 20) + s.attacks,
      current_risk_score: s.risk,
      risk_level: s.level,
      forecast_status: s.status,
      forecast_trend: s.trend,
      impending_threat: s.threat,
      confidence: 0.94,
      early_warning_alert: s.level === "HIGH" ? `CRITICAL FORECAST: Active ${s.threat} attack underway.` : null,
      recommended_action: getMitreMapping(s.threat).recommended_action,
      attack_distribution: { [s.threat]: s.attacks || 1 },
      time_series: clientState.activeSummary?.time_series || [],
      recent_alerts: clientState.alerts
    };

    clientState.activeSummary = updatedSummary;
    return updatedSummary;
  },

  resetSimulation: async () => {
    if (!isStaticMode && API_BASE_URL) {
      try {
        return await request('/forecast/reset', { method: 'POST' });
      } catch (err) {
        console.warn('Backend reset unreachable:', err.message);
      }
    }
    clientState.simStep = 0;
    return { message: "Simulation reset to baseline." };
  },

  // Alerts & MITRE ATT&CK
  getAlerts: async (limit = 30) => {
    if (!isStaticMode && API_BASE_URL) {
      try {
        return await request(`/alerts?limit=${limit}`);
      } catch (err) {
        console.warn('Backend /alerts unreachable, using client alerts:', err.message);
      }
    }
    return clientState.alerts.slice(0, limit);
  },

  getMitreMatrix: async () => {
    if (!isStaticMode && API_BASE_URL) {
      try {
        return await request('/alerts/mitre-matrix');
      } catch (err) {
        console.warn('Backend /alerts/mitre-matrix unreachable, using bundle mapping:', err.message);
      }
    }
    return rfBundle.mitre_mapping;
  },

  // Historical Traffic Logs
  getHistory: async (limit = 50) => {
    if (!isStaticMode && API_BASE_URL) {
      try {
        return await request(`/history?limit=${limit}`);
      } catch (err) {
        console.warn('Backend /history unreachable, using client logs:', err.message);
      }
    }
    return clientState.processedRecords.slice(0, limit).map((r, idx) => ({
      id: idx + 1,
      timestamp: r.timestamp,
      dst_port: r.dst_port,
      attack_type: r.prediction,
      probability: r.probability,
      risk_score: r.risk_score,
      risk_level: r.risk_level,
      forecast_status: r.forecast
    }));
  },

  // Ingestion & Inferences
  loadSampleDataset: async () => {
    // 1. If live backend is configured, attempt backend route first
    if (!isStaticMode && API_BASE_URL) {
      try {
        const res = await request('/load-sample');
        return res;
      } catch (err) {
        console.warn('Backend /load-sample failed or unreachable, falling back to client sample dataset:', err.message);
      }
    }

    // 2. Client-side static loading (works natively on GitHub Pages via GET)
    const base = typeof import.meta !== 'undefined' && import.meta.env?.BASE_URL ? import.meta.env.BASE_URL : './';
    const cleanBase = base.endsWith('/') ? base : `${base}/`;
    const candidateUrls = [
      `${cleanBase}data/sample_cicids2018_test.csv`,
      './data/sample_cicids2018_test.csv',
      '/data/sample_cicids2018_test.csv',
      'data/sample_cicids2018_test.csv',
      RAW_GITHUB_SAMPLE_URL
    ];

    let csvText = null;
    let lastError = null;

    for (const url of candidateUrls) {
      try {
        const res = await fetch(url);
        if (res.ok) {
          csvText = await res.text();
          if (csvText && csvText.trim().length > 0) {
            break;
          }
        }
      } catch (e) {
        lastError = e;
      }
    }

    if (!csvText) {
      throw new Error(
        `Unable to fetch sample dataset file. Ensure sample_cicids2018_test.csv is accessible in public/data/. ${lastError ? lastError.message : ''}`
      );
    }

    // Execute real ML pipeline client-side
    const result = await clientProcessCsv(csvText, 'sample_cicids2018_test.csv');
    updateClientState(result);
    return result;
  },

  uploadTrafficCsv: async (file) => {
    // 1. Client validation before network dispatch
    if (!file) {
      throw new Error("No file selected.");
    }
    if (!file.name || !file.name.toLowerCase().endsWith('.csv')) {
      throw new Error("Only CSV files are supported. Please select a valid .csv file.");
    }
    if (file.size === 0) {
      throw new Error("The selected CSV file is empty (0 bytes).");
    }

    // 2. If live backend is configured, attempt multipart/form-data POST
    if (!isStaticMode && API_BASE_URL) {
      try {
        const formData = new FormData();
        formData.append('file', file);
        const res = await request('/upload-traffic', {
          method: 'POST',
          body: formData,
        });
        return res;
      } catch (err) {
        console.warn('Backend upload failed or returned status error. Falling back to in-browser AI engine:', err.message);
        // Fallback to client processing so user workflow never breaks
      }
    }

    // 3. In-browser client-side ML pipeline (120-tree Random Forest)
    const result = await clientProcessCsv(file, file.name);
    updateClientState(result);
    return result;
  },

  predictSingleFlow: async (flowData) => {
    if (!isStaticMode && API_BASE_URL) {
      try {
        return await request('/predict-flow', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(flowData),
        });
      } catch (err) {
        console.warn('Backend predict-flow failed, falling back to in-browser AI inference:', err.message);
      }
    }

    return clientPredictSingle(flowData);
  },

  loadCsvFromUrl: async (url) => {
    if (!url || !url.trim()) {
      throw new Error("Please enter a valid URL to a CSV file.");
    }
    const rectifiedUrl = rectifyGitHubUrl(url);
    const res = await fetch(rectifiedUrl);
    if (!res.ok) {
      throw new Error(`Failed to download CSV from URL (HTTP ${res.status}): ${res.statusText}`);
    }
    const csvText = await res.text();
    if (!csvText || csvText.trim().length === 0) {
      throw new Error("The target URL returned an empty response (0 bytes).");
    }
    if (csvText.trim().toLowerCase().startsWith('<!doctype html') || csvText.trim().toLowerCase().startsWith('<html')) {
      throw new Error("The provided link returned an HTML webpage instead of raw CSV data. Use raw.githubusercontent.com or let our auto-rectifier convert it.");
    }
    const filename = rectifiedUrl.split('/').pop().split('?')[0] || 'remote_sample.csv';
    const result = await clientProcessCsv(csvText, filename);
    updateClientState(result);
    return result;
  },
};
