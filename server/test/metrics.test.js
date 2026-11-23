import test from 'node:test';
import assert from 'node:assert/strict';

import { confusionMatrix, classificationMetrics, rocAuc, evaluate } from '../src/evaluation/metrics.js';

test('confusionMatrix counts tp/fp/tn/fn at a threshold', () => {
  // scores: 90,60,80,5  labels: 1,0,1,0  threshold 50 → preds 1,1,1,0
  const cm = confusionMatrix([90, 60, 80, 5], [1, 0, 1, 0], 50);
  assert.deepEqual(cm, { tp: 2, fp: 1, tn: 1, fn: 0 });
});

test('classificationMetrics computes precision/recall/f1/accuracy', () => {
  const m = classificationMetrics({ tp: 2, fp: 1, tn: 1, fn: 0 });
  assert.equal(m.precision, 2 / 3);
  assert.equal(m.recall, 1);
  assert.equal(m.f1, 0.8);
  assert.equal(m.accuracy, 0.75);
});

test('classificationMetrics returns 0 when denominators are zero', () => {
  const m = classificationMetrics({ tp: 0, fp: 0, tn: 0, fn: 0 });
  assert.deepEqual(m, { precision: 0, recall: 0, f1: 0, accuracy: 0 });
});

test('rocAuc is 1.0 for perfectly separated scores', () => {
  // positives score strictly higher than negatives
  const auc = rocAuc([10, 90, 20, 80], [0, 1, 0, 1]);
  assert.equal(auc, 1);
});

test('rocAuc is 0.0 for perfectly inverted scores', () => {
  const auc = rocAuc([90, 10, 80, 20], [0, 1, 0, 1]);
  assert.equal(auc, 0);
});

test('rocAuc handles ties (average ranks)', () => {
  // two positives and two negatives, all tied at the same score → AUC 0.5
  const auc = rocAuc([50, 50, 50, 50], [1, 0, 1, 0]);
  assert.equal(auc, 0.5);
});

test('rocAuc returns null when only one class is present', () => {
  assert.equal(rocAuc([10, 20, 30], [1, 1, 1]), null);
  assert.equal(rocAuc([10, 20, 30], [0, 0, 0]), null);
});

test('evaluate bundles matrix, metrics and auc', () => {
  const report = evaluate([90, 60, 80, 5], [1, 0, 1, 0], 50);
  assert.equal(report.tp, 2);
  assert.equal(report.fp, 1);
  assert.equal(report.recall, 1);
  assert.equal(report.precision, 2 / 3);
  assert.equal(report.auc, 1);
  assert.deepEqual(report.support, { positives: 2, negatives: 2 });
});