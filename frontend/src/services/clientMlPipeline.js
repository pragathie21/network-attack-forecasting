/**
 * Client-Side Machine Learning & Time-Window Attack Forecasting Engine
 * Evaluates the trained 120-tree Random Forest model, StandardScaler,
 * Risk Scoring, and Window Trend Analysis directly in the browser.
 */

import rfBundle from './rf_model_bundle.js';

const FEATURE_COLUMNS = rfBundle.feature_columns;
const CLASSES = rfBundle.classes;
const SCALER = rfBundle.scaler;
const TREES = rfBundle.trees;
const MITRE_MAPPING = rfBundle.mitre_mapping;

const COLUMN_ALIASES = {
  "destination port": "Dst Port",
  "dst port": "Dst Port",
  "total fwd packets": "Tot Fwd Pkts",
  "tot fwd pkts": "Tot Fwd Pkts",
  "total backward packets": "Tot Bwd Pkts",
  "tot bwd pkts": "Tot Bwd Pkts",
  "total length of fwd packets": "TotLen Fwd Pkts",
  "totlen fwd pkts": "TotLen Fwd Pkts",
  "total length of bwd packets": "TotLen Bwd Pkts",
  "totlen bwd pkts": "TotLen Bwd Pkts",
  "flow bytes/s": "Flow Byts/s",
  "flow byts/s": "Flow Byts/s",
  "flow packets/s": "Flow Pkts/s",
  "flow pkts/s": "Flow Pkts/s",
};

/**
 * Parses a CSV string into headers and array of row objects.
 * Handles RFC-4180 quoting, CRLF/LF, and whitespace.
 */
export function parseCsv(csvText) {
  if (!csvText || !csvText.trim()) {
    throw new Error("Uploaded CSV file is empty.");
  }

  const lines = [];
  let currentLine = [];
  let currentField = '';
  let inQuotes = false;

  for (let i = 0; i < csvText.length; i++) {
    const char = csvText[i];
    const nextChar = csvText[i + 1];

    if (inQuotes) {
      if (char === '"') {
        if (nextChar === '"') {
          currentField += '"';
          i++; // Skip escaped quote
        } else {
          inQuotes = false;
        }
      } else {
        currentField += char;
      }
    } else {
      if (char === '"') {
        inQuotes = true;
      } else if (char === ',') {
        currentLine.push(currentField.trim());
        currentField = '';
      } else if (char === '\r') {
        if (nextChar === '\n') i++;
        currentLine.push(currentField.trim());
        if (currentLine.some(f => f.length > 0)) lines.push(currentLine);
        currentLine = [];
        currentField = '';
      } else if (char === '\n') {
        currentLine.push(currentField.trim());
        if (currentLine.some(f => f.length > 0)) lines.push(currentLine);
        currentLine = [];
        currentField = '';
      } else {
        currentField += char;
      }
    }
  }

  if (currentField || currentLine.length > 0) {
    currentLine.push(currentField.trim());
    if (currentLine.some(f => f.length > 0)) lines.push(currentLine);
  }

  if (lines.length < 2) {
    throw new Error("CSV file must contain at least a header row and one data record.");
  }

  const rawHeaders = lines[0];
  // Map headers to canonical names
  const headers = rawHeaders.map(h => {
    const cleaned = h.trim();
    const lower = cleaned.toLowerCase();
    return COLUMN_ALIASES[lower] || cleaned;
  });

  // Validate that CSV contains at least some recognized network flow features
  const matchedFeatures = headers.filter(h => FEATURE_COLUMNS.includes(h) || h === "Dst Port" || h === "Timestamp" || h === "Protocol");
  if (matchedFeatures.length < 3 && headers.length < 5) {
    throw new Error("Invalid CSV format. The file does not contain recognized network traffic flow features.");
  }

  const rows = [];
  for (let i = 1; i < lines.length; i++) {
    const line = lines[i];
    if (!line || line.length === 0 || (line.length === 1 && line[0] === '')) continue;
    
    const rowObj = {};
    for (let j = 0; j < headers.length; j++) {
      rowObj[headers[j]] = line[j] !== undefined ? line[j] : '';
    }
    rows.push(rowObj);
  }

  if (rows.length === 0) {
    throw new Error("CSV file does not contain any valid traffic records.");
  }

  return { headers, rows };
}

/**
 * Retrieves MITRE ATT&CK details for a classified attack type.
 */
export function getMitreMapping(attackType) {
  const normalized = (attackType || "").trim();
  return MITRE_MAPPING[normalized] || {
    technique_id: "T1000",
    technique_name: "Uncategorized Anomaly",
    tactic: "Suspicious Activity",
    description: "Unclassified abnormal traffic signature deviating from baseline metrics.",
    recommended_action: "Inspect packet headers and quarantine originating IP address."
  };
}

/**
 * Calculates risk score (0-100), risk level (LOW/MEDIUM/HIGH),
 * forecast status, and recommended defensive action.
 */
export function computeRiskScore(prediction, probDict) {
  const benignProb = probDict["Benign"] ?? 0.0;
  const attackProb = 1.0 - benignProb;

  let riskScore = 5.0;
  let riskLevel = "LOW";
  let forecast = "Normal baseline operations";
  let action = "Routine passive monitoring; maintain standard telemetry retention.";

  if (prediction === "Benign") {
    riskScore = Number(Math.max(5.0, (1.0 - benignProb) * 60.0).toFixed(1));
    riskLevel = "LOW";
    forecast = "Normal baseline operations";
    action = "Routine passive monitoring; maintain standard telemetry retention.";
  } else {
    const predProb = probDict[prediction] ?? attackProb;
    const severityWeights = {
      "DDoS": 1.0,
      "DoS": 0.92,
      "Brute Force": 0.88,
      "Botnet": 0.95,
      "Infiltration": 0.93,
      "Web Attack": 0.90,
    };
    const weight = severityWeights[prediction] ?? 0.85;
    const rawScore = (45.0 + (predProb * 50.0)) * weight;
    riskScore = Number(Math.min(99.0, Math.max(30.0, rawScore)).toFixed(1));

    if (riskScore >= 70.0) {
      riskLevel = "HIGH";
      forecast = "Cyber attack likely or underway. Immediate preventive action recommended.";
    } else if (riskScore >= 40.0) {
      riskLevel = "MEDIUM";
      forecast = "Suspicious traffic detected. Possible attack reconnaissance or early ramp-up.";
    } else {
      riskLevel = "LOW";
      forecast = "Minor anomaly detected, but confidence remains low.";
    }

    const mitre = getMitreMapping(prediction);
    action = mitre.recommended_action || "Investigate origin IP and restrict traffic.";
  }

  return { riskScore, riskLevel, forecast, action };
}

/**
 * Preprocesses a raw flow object into scaled numeric features.
 */
export function preprocessFlow(flowData) {
  const rawFeatures = new Float64Array(FEATURE_COLUMNS.length);

  for (let i = 0; i < FEATURE_COLUMNS.length; i++) {
    const colName = FEATURE_COLUMNS[i];
    let val = flowData[colName];

    // Check alias if missing
    if (val === undefined || val === null || val === '') {
      const lower = colName.toLowerCase();
      for (const [aliasLower, targetCol] of Object.entries(COLUMN_ALIASES)) {
        if (targetCol === colName && flowData[aliasLower] !== undefined) {
          val = flowData[aliasLower];
          break;
        }
      }
    }

    let num = parseFloat(val);
    if (isNaN(num) || !isFinite(num)) {
      num = 0.0;
    }

    // Apply StandardScaler: (x - mean) / scale
    const mean = SCALER.mean[i];
    const scale = SCALER.scale[i];
    rawFeatures[i] = scale !== 0 ? (num - mean) / scale : 0.0;
  }

  return rawFeatures;
}

/**
 * Predicts class probabilities for a single preprocessed feature vector
 * using the 120 Decision Trees in the Random Forest.
 */
export function predictProbabilities(scaledFeatures) {
  const numClasses = CLASSES.length;
  const numTrees = TREES.length;
  const accumulatedProbs = new Float64Array(numClasses);

  for (let t = 0; t < numTrees; t++) {
    const tree = TREES[t];
    const left = tree.left;
    const right = tree.right;
    const feat = tree.feat;
    const th = tree.th;
    const leaves = tree.leaves;

    let curr = 0;
    while (left[curr] !== -1) {
      const f = feat[curr];
      if (scaledFeatures[f] <= th[curr]) {
        curr = left[curr];
      } else {
        curr = right[curr];
      }
    }

    const leafDistribution = leaves[curr];
    if (leafDistribution) {
      for (let c = 0; c < numClasses; c++) {
        accumulatedProbs[c] += leafDistribution[c] || 0.0;
      }
    } else {
      accumulatedProbs[0] += 1.0; // fallback to Benign
    }
  }

  const probDict = {};
  let bestClassIdx = 0;
  let highestProb = -1.0;

  for (let c = 0; c < numClasses; c++) {
    const p = Math.round((accumulatedProbs[c] / numTrees) * 10000) / 10000;
    const className = CLASSES[c];
    probDict[className] = p;
    if (p > highestProb) {
      highestProb = p;
      bestClassIdx = c;
    }
  }

  const predictedClass = CLASSES[bestClassIdx];
  return { predictedClass, highestProb, probDict };
}

/**
 * Runs prediction on a single flow object (dict).
 */
export function clientPredictSingle(flowData) {
  const scaled = preprocessFlow(flowData);
  const { predictedClass, highestProb, probDict } = predictProbabilities(scaled);
  const { riskScore, riskLevel, forecast, action } = computeRiskScore(predictedClass, probDict);
  const mitre = getMitreMapping(predictedClass);

  return {
    prediction: predictedClass,
    probability: highestProb,
    probabilities: probDict,
    risk_score: riskScore,
    risk_level: riskLevel,
    forecast: forecast,
    recommended_action: action,
    mitre: mitre,
    timestamp: new Date().toISOString().replace('T', ' ').substring(0, 19)
  };
}

/**
 * Runs batch prediction on an array of flow records.
 */
export function clientPredictBatch(flowRows) {
  const results = [];
  for (let i = 0; i < flowRows.length; i++) {
    const row = flowRows[i];
    const scaled = preprocessFlow(row);
    const { predictedClass, highestProb, probDict } = predictProbabilities(scaled);
    const { riskScore, riskLevel, forecast, action } = computeRiskScore(predictedClass, probDict);
    const mitre = getMitreMapping(predictedClass);

    let dstPort = 80;
    if (row["Dst Port"] !== undefined && !isNaN(parseInt(row["Dst Port"]))) {
      dstPort = parseInt(row["Dst Port"]);
    } else if (row["Destination Port"] !== undefined && !isNaN(parseInt(row["Destination Port"]))) {
      dstPort = parseInt(row["Destination Port"]);
    }

    const timestamp = row["Timestamp"] || `2026-09-06 20:${String(i % 60).padStart(2, '0')}:00`;

    results.push({
      index: i,
      timestamp: String(timestamp),
      dst_port: dstPort,
      prediction: predictedClass,
      probability: highestProb,
      probabilities: probDict,
      risk_score: riskScore,
      risk_level: riskLevel,
      forecast: forecast,
      recommended_action: action,
      mitre: mitre
    });
  }

  return results;
}

/**
 * Performs time-window trend analysis on batch flow results.
 * Matches window_analyzer.py logic exactly.
 */
export function analyzeTrafficWindows(flowResults, windowSize = 15) {
  if (!flowResults || flowResults.length === 0) {
    return {
      window_size: 15,
      total_records: 0,
      normal_traffic: 0,
      suspicious_traffic: 0,
      predicted_attacks: 0,
      current_risk_score: 5.0,
      risk_level: "LOW",
      forecast_status: "System initialized. Awaiting network traffic ingestion.",
      forecast_trend: "STABLE",
      impending_threat: "None",
      confidence: 1.0,
      early_warning_alert: null,
      recommended_action: "System standby. Upload CSV or start live stream simulation.",
      attack_distribution: {},
      time_series: [],
      recent_alerts: []
    };
  }

  const totalRecords = flowResults.length;
  let normalCount = 0;
  let suspiciousCount = 0;
  let attackCount = 0;
  const attackDistribution = {};

  for (const item of flowResults) {
    const pred = item.prediction;
    const risk = item.risk_score;

    if (pred === "Benign") {
      if (risk > 25.0) {
        suspiciousCount++;
      } else {
        normalCount++;
      }
    } else {
      attackCount++;
      attackDistribution[pred] = (attackDistribution[pred] || 0) + 1;
      if (risk < 70.0) {
        suspiciousCount++;
      }
    }
  }

  // Segment into chronological time-series points (up to 12 chunks)
  const chunkSize = totalRecords > 12 ? Math.max(1, Math.floor(totalRecords / 12)) : 1;
  const timeSeries = [];

  for (let i = 0; i < totalRecords; i += chunkSize) {
    const chunk = flowResults.slice(i, i + chunkSize);
    const chunkNormal = chunk.filter(c => c.prediction === "Benign").length;
    const chunkAttack = chunk.length - chunkNormal;
    const avgRisk = Number((chunk.reduce((acc, c) => acc + c.risk_score, 0) / chunk.length).toFixed(1));

    // Top threat in this chunk
    const threatCounts = {};
    for (const c of chunk) {
      if (c.prediction !== "Benign") {
        threatCounts[c.prediction] = (threatCounts[c.prediction] || 0) + 1;
      }
    }
    let topThreat = "Benign";
    let maxTCount = 0;
    for (const [threat, cnt] of Object.entries(threatCounts)) {
      if (cnt > maxTCount) {
        maxTCount = cnt;
        topThreat = threat;
      }
    }

    let timeLabel = chunk[0].timestamp || `T+${i}`;
    if (timeLabel.length > 10 && timeLabel.includes(" ")) {
      timeLabel = timeLabel.split(" ")[1]; // Keep HH:MM:SS
    }

    timeSeries.push({
      time: timeLabel,
      total_flows: chunk.length,
      normal_flows: chunkNormal,
      attack_flows: chunkAttack,
      risk_score: avgRisk,
      threat: topThreat
    });
  }

  // Recent window analysis
  const recentFlows = totalRecords >= windowSize ? flowResults.slice(-windowSize) : flowResults;
  const currentRiskScore = Number(
    (recentFlows.reduce((acc, f) => acc + f.risk_score, 0) / recentFlows.length).toFixed(1)
  );

  // Trajectory / acceleration
  let forecastTrend = "STABLE";
  if (timeSeries.length >= 2) {
    const prevRisk = timeSeries[timeSeries.length - 2].risk_score;
    const currChunkRisk = timeSeries[timeSeries.length - 1].risk_score;
    const deltaRisk = currChunkRisk - prevRisk;

    if (deltaRisk > 15) {
      forecastTrend = "SURGING";
    } else if (deltaRisk > 4) {
      forecastTrend = "RISING";
    } else if (deltaRisk < -8) {
      forecastTrend = "DECLINING";
    } else {
      forecastTrend = "STABLE";
    }
  }

  // Impending threat
  const recentThreats = {};
  for (const f of recentFlows) {
    if (f.prediction !== "Benign") {
      recentThreats[f.prediction] = (recentThreats[f.prediction] || 0) + 1;
    }
  }

  let impendingThreat = "None (Traffic Nominal)";
  let confidence = 0.95;

  let maxRecentCnt = 0;
  let topRecentThreat = null;
  for (const [thr, cnt] of Object.entries(recentThreats)) {
    if (cnt > maxRecentCnt) {
      maxRecentCnt = cnt;
      topRecentThreat = thr;
    }
  }

  if (topRecentThreat) {
    impendingThreat = topRecentThreat;
    confidence = Number((maxRecentCnt / recentFlows.length).toFixed(2));
  } else {
    let maxDistCnt = 0;
    let topDistThreat = null;
    for (const [thr, cnt] of Object.entries(attackDistribution)) {
      if (cnt > maxDistCnt) {
        maxDistCnt = cnt;
        topDistThreat = thr;
      }
    }
    if (topDistThreat) {
      impendingThreat = topDistThreat;
      confidence = Number((maxDistCnt / totalRecords).toFixed(2));
    }
  }

  // Status & Alerts
  let riskLevel = "LOW";
  let forecastStatus = "NORMAL: Traffic Baseline Within Operating Boundaries";
  let earlyWarningAlert = null;
  let recommendedAction = "Routine passive monitoring; maintain standard telemetry retention.";

  if (currentRiskScore >= 70.0) {
    riskLevel = "HIGH";
    forecastStatus = `CRITICAL FORECAST: Active/Imminent ${impendingThreat} Attack Escalation`;
    earlyWarningAlert = `HIGH RISK DETECTED (${currentRiskScore}%): Impending ${impendingThreat} attack detected in sliding time-window. Anomaly velocity indicates high-impact denial or breach phase.`;
    recommendedAction = getMitreMapping(impendingThreat).recommended_action;
  } else if (currentRiskScore >= 40.0) {
    riskLevel = "MEDIUM";
    forecastStatus = `EARLY WARNING: Suspicious ${impendingThreat} Signature Rising`;
    earlyWarningAlert = `SUSPICIOUS TRAFFIC DETECTED (${currentRiskScore}%): Flow rates and payload metrics deviate from baseline. Pre-attack probing / reconnaissance identified.`;
    recommendedAction = `Preemptively rate-limit originating subnet; inspect ${impendingThreat} telemetry and alert SOC Level-2 analyst.`;
  }

  const nowStr = new Date().toISOString().replace('T', ' ').substring(0, 19);
  const recentAlerts = [];
  let alertId = 1;

  for (const [attackType, count] of Object.entries(attackDistribution)) {
    const mitre = getMitreMapping(attackType);
    const severity = currentRiskScore >= 70.0 ? "HIGH" : "MEDIUM";
    recentAlerts.push({
      id: alertId++,
      timestamp: nowStr,
      attack_type: attackType,
      severity: severity,
      mitre_id: mitre.technique_id,
      mitre_name: mitre.technique_name,
      alert_message: `Time-window detected ${count} anomalous flows matching ${attackType} signature (${mitre.technique_id}).`,
      recommended_action: mitre.recommended_action,
      status: "ACTIVE"
    });
  }

  return {
    window_size: windowSize,
    total_records: totalRecords,
    normal_traffic: normalCount,
    suspicious_traffic: suspiciousCount,
    predicted_attacks: attackCount,
    current_risk_score: currentRiskScore,
    risk_level: riskLevel,
    forecast_status: forecastStatus,
    forecast_trend: forecastTrend,
    impending_threat: impendingThreat,
    confidence: confidence,
    early_warning_alert: earlyWarningAlert,
    recommended_action: recommendedAction,
    attack_distribution: attackDistribution,
    time_series: timeSeries,
    recent_alerts: recentAlerts
  };
}

/**
 * End-to-end client-side CSV processing.
 * Parses file, runs ML inference, and generates window forecast summary.
 */
export async function clientProcessCsv(csvTextOrFile, fileName = "traffic.csv") {
  let text = "";
  if (typeof csvTextOrFile === "string") {
    text = csvTextOrFile;
  } else if (csvTextOrFile && typeof csvTextOrFile.text === "function") {
    text = await csvTextOrFile.text();
    fileName = csvTextOrFile.name || fileName;
  } else {
    throw new Error("Invalid CSV input provided.");
  }

  const { rows } = parseCsv(text);
  const flowResults = clientPredictBatch(rows);
  const summary = analyzeTrafficWindows(flowResults);

  return {
    message: "Traffic dataset processed successfully via in-browser AI engine.",
    filename: fileName,
    records_processed: rows.length,
    summary: summary,
    flow_results: flowResults
  };
}
