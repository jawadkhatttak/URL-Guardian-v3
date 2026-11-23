import test from 'node:test';
import assert from 'node:assert/strict';

import { buildDataset } from '../src/evaluation/buildDataset.js';
import { evaluate } from '../src/evaluation/metrics.js';
import { scenarios, datasetStats } from '../src/dataset/scenarios.js';

test('buildDataset materialises every scenario with a feature vector', async () => {
  const samples = await buildDataset();

  assert.equal(samples.length, scenarios.length);

  for (const sample of samples) {
    assert.ok(sample.id);
    assert.ok(sample.url);
    assert.ok(sample.label === 'benign' || sample.label === 'phishing');
    assert.equal(typeof sample.score, 'number');
    assert.ok(sample.score >= 0 && sample.score <= 100);
    assert.equal(typeof sample.featureVector, 'object');
    // Fixed-schema vector must always carry the core keys.
    assert.equal(typeof sample.featureVector.vt_positive_ratio, 'number');
    assert.equal(typeof sample.featureVector.html_risk_score, 'number');
  }
});

test('dataset label distribution matches the scenario declarations', async () => {
  const samples = await buildDataset();
  const stats = datasetStats();

  const phishing = samples.filter((s) => s.label === 'phishing').length;
  const benign = samples.filter((s) => s.label === 'benign').length;

  assert.equal(phishing, stats.positives);
  assert.equal(benign, stats.negatives);
  assert.ok(stats.positives > 0 && stats.negatives > 0, 'dataset needs both classes for AUC');
});

test('the engine separates classes on the corpus (quality guard)', async () => {
  const samples = await buildDataset();
  const scores = samples.map((s) => s.score);
  const labels = samples.map((s) => (s.label === 'phishing' ? 1 : 0));

  const report = evaluate(scores, labels, 20);

  // Guard rails: if a refactor breaks the pipeline, these fail loudly.
  assert.ok(report.auc > 0.8, `AUC too low: ${report.auc}`);
  assert.ok(report.recall > 0.8, `recall too low: ${report.recall}`);
  assert.ok(report.precision > 0.8, `precision too low: ${report.precision}`);
});