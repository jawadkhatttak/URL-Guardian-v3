import test from 'node:test';
import assert from 'node:assert/strict';

import { fitModel, predictProba, fitStandardizer, sigmoid } from '../src/ml/logisticRegression.js';

test('sigmoid maps extremes toward 0 and 1', () => {
  assert.equal(sigmoid(0), 0.5);
  assert.ok(sigmoid(10) > 0.99);
  assert.ok(sigmoid(-10) < 0.01);
});

test('fitStandardizer centres data and avoids divide-by-zero', () => {
  const { mean, std } = fitStandardizer([[1, 5], [3, 5]]);
  assert.deepEqual(mean, [2, 5]);
  assert.deepEqual(std, [1, 1]); // second feature has zero variance → std 1
});

test('logistic regression learns a separable pattern', () => {
  // Label is driven by the first feature.
  const X = [[0, 0], [0, 1], [1, 0], [1, 1]];
  const y = [0, 0, 1, 1];
  const model = fitModel(X, y, { epochs: 4000, lr: 0.5, l2: 0.1 });

  assert.ok(model.predict([1, 0]) > 0.8, 'x0=1 should be phishing');
  assert.ok(model.predict([0, 1]) < 0.2, 'x0=0 should be benign');
});

test('predictProba agrees with the model predict function', () => {
  const X = [[0], [1], [2], [3]];
  const y = [0, 0, 1, 1];
  const model = fitModel(X, y, {});

  for (const row of X) {
    assert.equal(predictProba(row, model), model.predict(row));
  }
});

test('model weights are serialisable to JSON (no functions)', () => {
  const model = fitModel([[0], [1]], [0, 1], {});
  const { predict, ...serialisable } = model;
  assert.doesNotThrow(() => JSON.parse(JSON.stringify(serialisable)));
  assert.equal(typeof predict, 'function');
});