/**
 * Logistic Regression (from scratch)
 * ----------------------------------
 * A small, dependency-free L2-regularised logistic-regression implementation
 * with feature standardisation. Chosen for interpretability (the learned
 * weights map directly back to the engineered features, which matters for a
 * security tool) and because it trains instantly on a small corpus.
 *
 * The model bundle is a plain object so it serialises cleanly to JSON:
 *   { mean, std, w, b, featureKeys, ... }
 */

const sigmoid = (z) => 1 / (1 + Math.exp(-z));

/**
 * Fit a standardiser (per-feature mean / population std). Zero-variance
 * features get std = 1 so they contribute a centred 0 rather than dividing by 0.
 */
export function fitStandardizer(X) {
  const n = X.length;
  const d = X[0].length;
  const mean = new Array(d).fill(0);
  const std = new Array(d).fill(0);

  for (const row of X) {
    for (let j = 0; j < d; j++) mean[j] += row[j] / n;
  }
  for (const row of X) {
    for (let j = 0; j < d; j++) std[j] += (row[j] - mean[j]) ** 2 / n;
  }
  for (let j = 0; j < d; j++) std[j] = Math.sqrt(std[j]) || 1;

  return { mean, std };
}

export function applyStandardizer(X, { mean, std }) {
  return X.map((row) => row.map((value, j) => (value - mean[j]) / std[j]));
}

function trainGradientDescent(Xs, y, { epochs = 3000, lr = 0.5, l2 = 1.0 } = {}) {
  const n = Xs.length;
  const d = Xs[0].length;
  const w = new Array(d).fill(0);
  let b = 0;

  for (let epoch = 0; epoch < epochs; epoch++) {
    const gradW = new Array(d).fill(0);
    let gradB = 0;

    for (let i = 0; i < n; i++) {
      let z = b;
      for (let j = 0; j < d; j++) z += w[j] * Xs[i][j];
      const error = sigmoid(z) - y[i];
      for (let j = 0; j < d; j++) gradW[j] += error * Xs[i][j];
      gradB += error;
    }

    for (let j = 0; j < d; j++) {
      // Average gradient + L2 penalty (bias is not regularised).
      w[j] -= lr * (gradW[j] / n + (l2 * w[j]) / n);
    }
    b -= lr * (gradB / n);
  }

  return { w, b };
}

/**
 * Train a model on raw feature rows.
 * @param {number[][]} X
 * @param {number[]} y  (0/1)
 * @param {object} hyperparams { epochs, lr, l2 }
 * @returns {{ mean:number[], std:number[], w:number[], b:number, featureCount:number, predict:(x:number[])=>number }}
 */
export function fitModel(X, y, hyperparams = {}) {
  const { mean, std } = fitStandardizer(X);
  const Xs = applyStandardizer(X, { mean, std });
  const { w, b } = trainGradientDescent(Xs, y, hyperparams);

  const predict = (x) => {
    let z = b;
    for (let j = 0; j < w.length; j++) z += w[j] * ((x[j] - mean[j]) / std[j]);
    return sigmoid(z);
  };

  return { mean, std, w, b, featureCount: X[0].length, predict };
}

export function predictProba(x, model) {
  let z = model.b;
  for (let j = 0; j < model.w.length; j++) {
    z += model.w[j] * ((x[j] - model.mean[j]) / model.std[j]);
  }
  return sigmoid(z);
}

export { sigmoid };