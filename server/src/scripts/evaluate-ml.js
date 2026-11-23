/**
 * Evaluate the ML scorer against the heuristic baseline.
 *
 *   npm run evaluate:ml
 *
 * Reports, on the same corpus and with the same metric code:
 *   - Heuristic : the current rule-based score (computeRisk).
 *   - ML        : out-of-fold logistic-regression probabilities (threshold 0.5).
 *   - Hybrid    : out-of-fold ML probability blended with the heuristic score.
 *
 * ML and Hybrid use OUT-OF-FOLD predictions, so every score comes from a model
 * that never saw that sample — an honest generalisation estimate.
 */

import { buildDataset } from '../evaluation/buildDataset.js';
import { evaluate } from '../evaluation/metrics.js';
import { crossValidate } from '../ml/crossValidation.js';
import { FEATURE_KEYS } from '../ml/dataset.js';
import { combineScores } from '../ml/scoring.js';

const K = Number(process.env.EVAL_FOLDS) || 5;
const ML_WEIGHT = Math.min(1, Math.max(0, Number(process.env.ML_WEIGHT ?? 0.5)));
const HEURISTIC_THRESHOLD = 20;
const pct = (v) => `${(v * 100).toFixed(1)}%`;

function row(label, report) {
  return `${label.padEnd(10)}${pct(report.accuracy).padStart(8)}${pct(report.precision).padStart(10)}${pct(report.recall).padStart(9)}${pct(report.f1).padStart(8)}${(report.auc == null ? 'n/a' : report.auc.toFixed(4)).padStart(9)}`;
}

async function main() {
  const samples = await buildDataset();
  const X = samples.map((s) => FEATURE_KEYS.map((k) => Number(s.featureVector?.[k] ?? 0)));
  const y = samples.map((s) => (s.label === 'phishing' ? 1 : 0));
  const heuristicScores = samples.map((s) => s.score);

  const oof = crossValidate(X, y, K, { epochs: 3000, lr: 0.5, l2: 1.0 });

  const heuristicReport = evaluate(heuristicScores, y, HEURISTIC_THRESHOLD);

  const mlReport = evaluate(oof, y, 0.5);

  // Hybrid per-sample: same fail-safe blend the live pipeline uses.
  const hybridScores = samples.map((s, i) =>
    combineScores(s.score, oof[i], { mode: 'hybrid', mlWeight: ML_WEIGHT }).score
  );
  const hybridReport = evaluate(hybridScores, y, HEURISTIC_THRESHOLD);

  console.log('==================================================');
  console.log(' ML vs HEURISTIC — EVALUATION (out-of-fold)');
  console.log('==================================================');
  console.log(`Corpus: ${y.length} samples | folds: ${K} | hybrid ML weight: ${ML_WEIGHT}`);
  console.log('');
  console.log(`Model      ${'Accuracy'.padStart(8)}${'Precision'.padStart(10)}${'Recall'.padStart(9)}${'F1'.padStart(8)}${'ROC-AUC'.padStart(9)}`);
  console.log('-'.repeat(54));
  console.log(row('Heuristic', heuristicReport));
  console.log(row('ML', mlReport));
  console.log(row('Hybrid', hybridReport));
  console.log('');
  console.log('==================================================\n');

  if (process.env.EVAL_VERBOSE === '1') {
    console.log('Per-sample (h = heuristic, p = ML probability, y = hybrid):');
    const pad = (v, w) => String(v).padEnd(w);
    const padStart = (v, w) => String(v).padStart(w);
    for (let i = 0; i < samples.length; i++) {
      const mark = (hybridScores[i] >= HEURISTIC_THRESHOLD ? 1 : 0) === y[i] ? 'ok' : 'XX';
      console.log(
        `${mark} ${pad(samples[i].label, 9)} h=${padStart(Math.round(heuristicScores[i]), 3)} ` +
          `p=${oof[i].toFixed(2)} y=${padStart(hybridScores[i], 3)}  ${samples[i].url}`
      );
    }
    console.log('');
  }
}

main().catch((error) => {
  console.error('Evaluation failed:', error);
  process.exitCode = 1;
});