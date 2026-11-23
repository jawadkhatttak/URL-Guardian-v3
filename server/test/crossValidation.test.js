import test from 'node:test';
import assert from 'node:assert/strict';

import { stratifiedKFold, crossValidate } from '../src/ml/crossValidation.js';

test('stratifiedKFold covers every index exactly once', () => {
  const y = [0, 1, 0, 1, 0, 1, 0, 1];
  const folds = stratifiedKFold(y, 4);

  assert.equal(folds.length, 4);

  const covered = folds.flatMap((f) => f.testIdx).sort((a, b) => a - b);
  assert.deepEqual(covered, [0, 1, 2, 3, 4, 5, 6, 7]);
});

test('stratifiedKFold keeps class balance within each fold', () => {
  const y = [0, 1, 0, 1, 0, 1];
  const folds = stratifiedKFold(y, 3);

  for (const fold of folds) {
    const positives = fold.testIdx.filter((i) => y[i] === 1).length;
    const negatives = fold.testIdx.filter((i) => y[i] === 0).length;
    assert.equal(positives, 1);
    assert.equal(negatives, 1);
  }
});

test('stratifiedKFold is deterministic for a given seed', () => {
  const y = [0, 1, 0, 1, 0, 1, 0, 1];
  const a = stratifiedKFold(y, 4, 7);
  const b = stratifiedKFold(y, 4, 7);
  assert.deepEqual(a, b);
});

test('crossValidate returns one probability per sample in [0, 1]', () => {
  const X = [[0], [0], [1], [1], [0], [1], [0], [1]];
  const y = [0, 0, 1, 1, 0, 1, 0, 1];

  const oof = crossValidate(X, y, 4, { epochs: 2000, lr: 0.5, l2: 1.0 });

  assert.equal(oof.length, y.length);
  for (const p of oof) {
    assert.ok(p >= 0 && p <= 1, `probability out of range: ${p}`);
  }
});

test('crossValidate separates classes on a trivial dataset', () => {
  const X = Array.from({ length: 20 }, (_, i) => [i]);
  const y = X.map(([v]) => (v < 10 ? 0 : 1)); // 0-9 benign, 10-19 phishing

  const oof = crossValidate(X, y, 5, { epochs: 3000, lr: 0.5, l2: 0.1 });

  const benignMean = oof.slice(0, 10).reduce((a, b) => a + b, 0) / 10;
  const phishMean = oof.slice(10).reduce((a, b) => a + b, 0) / 10;
  assert.ok(phishMean > benignMean, `expected phishing mean > benign mean (${phishMean} vs ${benignMean})`);
});