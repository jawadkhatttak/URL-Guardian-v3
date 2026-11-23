import { fitModel, predictProba } from './logisticRegression.js';

/**
 * Deterministic PRNG (mulberry32) so cross-validation splits are reproducible.
 */
function mulberry32(seed) {
  return function random() {
    seed |= 0;
    seed = (seed + 0x6d2b79f5) | 0;
    let t = Math.imul(seed ^ (seed >>> 15), 1 | seed);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

function shuffle(array, random) {
  const copy = [...array];
  for (let i = copy.length - 1; i > 0; i--) {
    const j = Math.floor(random() * (i + 1));
    [copy[i], copy[j]] = [copy[j], copy[i]];
  }
  return copy;
}

/**
 * Stratified k-fold split: each fold preserves the class balance.
 * @returns {Array<{ trainIdx:number[], testIdx:number[] }>}
 */
export function stratifiedKFold(labels, k = 5, seed = 42) {
  const random = mulberry32(seed);
  const byClass = new Map();
  labels.forEach((label, index) => {
    if (!byClass.has(label)) byClass.set(label, []);
    byClass.get(label).push(index);
  });

  const folds = Array.from({ length: k }, () => []);
  for (const indices of byClass.values()) {
    const shuffled = shuffle(indices, random);
    shuffled.forEach((index, position) => {
      folds[position % k].push(index);
    });
  }

  return folds.map((testIdx) => {
    const testSet = new Set(testIdx);
    const trainIdx = labels.map((_, i) => i).filter((i) => !testSet.has(i));
    return { trainIdx, testIdx };
  });
}

/**
 * Out-of-fold cross-validation. Returns a probability per sample, each produced
 * by a model that never saw that sample during training.
 * @param {number[][]} X
 * @param {number[]} y
 * @param {number} k
 * @param {object} hyperparams
 * @returns {number[]} out-of-fold probabilities aligned to y
 */
export function crossValidate(X, y, k = 5, hyperparams = {}) {
  const folds = stratifiedKFold(y, k);
  const oof = new Array(y.length).fill(0);

  for (const { trainIdx, testIdx } of folds) {
    const Xtrain = trainIdx.map((i) => X[i]);
    const ytrain = trainIdx.map((i) => y[i]);
    const model = fitModel(Xtrain, ytrain, hyperparams);

    for (const testIndex of testIdx) {
      oof[testIndex] = predictProba(X[testIndex], model);
    }
  }

  return oof;
}