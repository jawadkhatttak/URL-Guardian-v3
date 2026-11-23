/**
 * Evaluation Metrics
 * ------------------
 * Pure, dependency-free functions for scoring a binary classifier (benign vs
 * phishing). Kept side-effect free so they are trivially unit-testable and can
 * be reused by the ML evaluation in a later version.
 *
 * Conventions:
 *   - scores[i]  : continuous risk score (0–100); higher ⇒ more likely phishing.
 *   - labels[i]  : 1 = phishing (positive), 0 = benign (negative).
 *   - A sample is predicted phishing when score >= threshold.
 */

/**
 * Confusion matrix at a given threshold.
 * @returns {{ tp:number, fp:number, tn:number, fn:number }}
 */
export function confusionMatrix(scores, labels, threshold) {
  let tp = 0, fp = 0, tn = 0, fn = 0;

  for (let i = 0; i < labels.length; i++) {
    const predictedPositive = scores[i] >= threshold;
    const actualPositive = labels[i] === 1;

    if (predictedPositive && actualPositive) tp++;
    else if (predictedPositive && !actualPositive) fp++;
    else if (!predictedPositive && !actualPositive) tn++;
    else fn++;
  }

  return { tp, fp, tn, fn };
}

/**
 * Precision / recall / F1 / accuracy from a confusion matrix. All values are
 * fractions in [0, 1]; a zero denominator yields 0.
 */
export function classificationMetrics({ tp, fp, tn, fn }) {
  const precision = tp + fp > 0 ? tp / (tp + fp) : 0;
  const recall = tp + fn > 0 ? tp / (tp + fn) : 0;
  const f1 = precision + recall > 0 ? (2 * precision * recall) / (precision + recall) : 0;
  const accuracy = tp + fp + tn + fn > 0 ? (tp + tn) / (tp + fp + tn + fn) : 0;

  return { precision, recall, f1, accuracy };
}

/**
 * ROC-AUC via the rank (Mann–Whitney U) formulation, with tie handling.
 * Returns a value in [0, 1] (0.5 = random), or null when only one class exists.
 *
 * @param {number[]} scores
 * @param {number[]} labels
 * @returns {number|null}
 */
export function rocAuc(scores, labels) {
  const nPos = labels.reduce((sum, label) => sum + (label === 1 ? 1 : 0), 0);
  const nNeg = labels.length - nPos;
  if (nPos === 0 || nNeg === 0) return null;

  const ranked = scores
    .map((score, index) => ({ score, label: labels[index] }))
    .sort((a, b) => a.score - b.score);

  // Sum of ranks assigned to positive samples, averaging ranks within ties.
  let positiveRankSum = 0;
  let i = 0;
  while (i < ranked.length) {
    let j = i;
    while (j + 1 < ranked.length && ranked[j + 1].score === ranked[i].score) j++;

    const averageRank = (i + 1 + j + 1) / 2; // ranks are 1-based
    for (let k = i; k <= j; k++) {
      if (ranked[k].label === 1) positiveRankSum += averageRank;
    }
    i = j + 1;
  }

  return (positiveRankSum - (nPos * (nPos + 1)) / 2) / (nPos * nNeg);
}

/**
 * Full evaluation report for one set of predictions.
 * @param {number[]} scores
 * @param {number[]} labels
 * @param {number} threshold - score at/above which a sample is called phishing.
 */
export function evaluate(scores, labels, threshold) {
  const cm = confusionMatrix(scores, labels, threshold);
  const { precision, recall, f1, accuracy } = classificationMetrics(cm);
  const auc = rocAuc(scores, labels);
  const support = { positives: labels.filter((l) => l === 1).length, negatives: labels.filter((l) => l === 0).length };

  return { threshold, ...cm, precision, recall, f1, accuracy, auc, support };
}