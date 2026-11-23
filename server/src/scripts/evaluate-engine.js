/**
 * Phishing Detection Engine — Evaluation Harness
 * ----------------------------------------------
 * Runs the labeled corpus through the real pipeline and reports industry
 * metrics: accuracy, precision, recall, F1 and ROC-AUC, plus a per-sample
 * breakdown and a confusion matrix.
 *
 * Usage:
 *   npm run evaluate
 *
 * Env:
 *   EVAL_THRESHOLD       score at/above which a sample is called phishing (default 20)
 *   EVAL_STRICT=1        exit non-zero if precision/recall fall below EVAL_MIN_* 
 *   EVAL_MIN_PRECISION   minimum precision gate (default 0.60)
 *   EVAL_MIN_RECALL      minimum recall gate    (default 0.60)
 */

import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { buildDataset } from '../evaluation/buildDataset.js';
import { evaluate } from '../evaluation/metrics.js';
import { datasetStats } from '../dataset/scenarios.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const DATASET_OUT = path.resolve(__dirname, '../../data/featureDataset.json');

const THRESHOLD = Number(process.env.EVAL_THRESHOLD) || 20;
const STRICT = process.env.EVAL_STRICT === '1';
const MIN_PRECISION = Number(process.env.EVAL_MIN_PRECISION) || 0.6;
const MIN_RECALL = Number(process.env.EVAL_MIN_RECALL) || 0.6;

const pct = (value) => `${(value * 100).toFixed(1)}%`;
const pad = (value, width) => String(value).padEnd(width);
const padStart = (value, width) => String(value).padStart(width);

function writeDatasetFile(samples) {
  fs.mkdirSync(path.dirname(DATASET_OUT), { recursive: true });
  fs.writeFileSync(DATASET_OUT, JSON.stringify(samples, null, 2));
  return DATASET_OUT;
}

async function main() {
  const started = Date.now();
  const samples = await buildDataset();
  const elapsed = Date.now() - started;

  const scores = samples.map((s) => s.score);
  const labels = samples.map((s) => (s.label === 'phishing' ? 1 : 0));
  const report = evaluate(scores, labels, THRESHOLD);
  const stats = datasetStats();

  console.log('==================================================');
  console.log(' URL GUARDIAN — EVALUATION HARNESS');
  console.log('==================================================');
  console.log(`Corpus: ${stats.total} samples (${stats.positives} phishing / ${stats.negatives} benign)`);
  console.log(`Decision threshold: score >= ${THRESHOLD} ⇒ phishing`);
  console.log(`Build time: ${elapsed} ms\n`);

  // Per-sample breakdown
  const header = `${pad('RESULT', 7)}${pad('LABEL', 10)}${padStart('SCORE', 6)}  URL`;
  console.log(header);
  console.log('-'.repeat(header.length));
  for (const sample of samples) {
    const predicted = sample.score >= THRESHOLD ? 'phishing' : 'benign';
    const correct = predicted === sample.label;
    const mark = correct ? 'ok ' : 'XX ';
    console.log(
      `${mark}${pad(sample.label, 7)}${padStart(sample.score, 6)}  ${sample.url} [${sample.risk}]`
    );
  }
  console.log('');

  // Metrics
  console.log('==================================================');
  console.log(' METRICS');
  console.log('==================================================');
  console.log(`Accuracy : ${pct(report.accuracy)}`);
  console.log(`Precision: ${pct(report.precision)}  (of flagged, how many truly phishing)`);
  console.log(`Recall   : ${pct(report.recall)}  (of phishing, how many caught)`);
  console.log(`F1 Score : ${pct(report.f1)}`);
  console.log(`ROC-AUC  : ${report.auc === null ? 'n/a (single class)' : report.auc.toFixed(4)}`);
  console.log('');
  console.log('Confusion matrix:');
  console.log(`            predicted phishing   predicted benign`);
  console.log(`actual phishing      ${padStart(report.tp, 6)}              ${padStart(report.fn, 6)}`);
  console.log(`actual benign        ${padStart(report.fp, 6)}              ${padStart(report.tn, 6)}`);
  console.log('');

  // Persist the materialised dataset for the ML training step (#4).
  const datasetPath = writeDatasetFile(samples);
  console.log(`Feature dataset written to: ${datasetPath}`);
  console.log('==================================================\n');

  if (STRICT && (report.precision < MIN_PRECISION || report.recall < MIN_RECALL)) {
    console.error(
      `QUALITY GATE FAILED: precision ${pct(report.precision)} (min ${pct(MIN_PRECISION)}), ` +
        `recall ${pct(report.recall)} (min ${pct(MIN_RECALL)})`
    );
    process.exitCode = 1;
  } else {
    console.log('Evaluation complete.');
  }
}

main().catch((error) => {
  console.error('Evaluation failed:', error);
  process.exitCode = 1;
});