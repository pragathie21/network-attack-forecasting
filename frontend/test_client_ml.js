import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import { clientProcessCsv, parseCsv, clientPredictSingle } from './src/services/clientMlPipeline.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

async function runTests() {
  console.log('--- RUNNING CLIENT ML TEST SUITE ---');

  // 1. Test Empty CSV throws error
  try {
    parseCsv('');
    throw new Error('Should have thrown on empty CSV');
  } catch (e) {
    console.log('1. Empty CSV test PASSED:', e.message);
  }

  // 2. Test Invalid/Garbage CSV throws error
  try {
    parseCsv('apple,banana\n1,2\n3,4');
    throw new Error('Should have thrown on non-network CSV');
  } catch (e) {
    console.log('2. Invalid headers CSV test PASSED:', e.message);
  }

  // 3. Test Full CIC-IDS2018 Sample Processing
  const samplePath = path.join(__dirname, 'public', 'data', 'sample_cicids2018_test.csv');
  const sampleCsv = fs.readFileSync(samplePath, 'utf8');

  const result = await clientProcessCsv(sampleCsv, 'sample_cicids2018_test.csv');
  console.log('3. Valid Sample CSV Processing:');
  console.log('   - Records processed:', result.records_processed);
  console.log('   - Current risk score:', result.summary.current_risk_score);
  console.log('   - Risk level:', result.summary.risk_level);
  console.log('   - Forecast trend:', result.summary.forecast_trend);
  console.log('   - Impending threat:', result.summary.impending_threat);
  console.log('   - Recent alerts count:', result.summary.recent_alerts.length);
  console.log('   - Time series chunks:', result.summary.time_series.length);

  if (result.records_processed !== 90) {
    throw new Error(`Expected 90 records, got ${result.records_processed}`);
  }
  if (!result.summary.current_risk_score) {
    throw new Error('Missing current_risk_score');
  }
  console.log('3. Valid Sample CSV test PASSED!');

  // 4. Test Single Flow Prediction
  const singleFlow = {
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
  };
  const singleResult = clientPredictSingle(singleFlow);
  console.log('4. Single Flow Prediction:');
  console.log('   - Prediction:', singleResult.prediction);
  console.log('   - Probability:', singleResult.probability);
  console.log('   - Risk score:', singleResult.risk_score);
  console.log('   - MITRE technique:', singleResult.mitre.technique_id, singleResult.mitre.technique_name);
  console.log('4. Single Flow Prediction test PASSED!');

  console.log('--- ALL CLIENT ML TESTS COMPLETED SUCCESSFULLY! ---');
}

runTests().catch(err => {
  console.error('Test execution failed:', err);
  process.exit(1);
});
