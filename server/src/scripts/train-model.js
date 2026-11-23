/**
 * Train the logistic-regression scoring model.
 *
 *   npm run train
 *
 * Builds the labeled corpus, trains an L2-regularised logistic-regression model
 * on all samples, reports both training and stratified 5-fold cross-validated
 * metrics (the honest generalisation estimate), lists the most influential
 * features, and writes data/model.json.
 */

import { buildDataset } from '../evaluation/buildDataset.js';
import { evaluate } from '../evaluation/metrics.js';
import { crossValidate } from '../ml/crossValidation.js';
import { fitModel } from '../ml/logisticRegression.js';
import { saveModel, MODEL_PATH } from '../ml/model.service.js';
import { FEATURE_KEYS } from '../ml/dataset.js';

const K = Number(process.env.EVAL_FOLDS) || 5;
const pct = (v) => `${(v * 100).toFixed(1)}%`;

async function main() {
  const samples = await buildDataset();
  const X = samples.map((s) => FEATURE_KEYS.map((k) => Number(s.featureVector?.[k] ?? 0)));
  const y = samples.map((s) => (s.label === 'phishing' ? 1 : 0));

  // Train on the full corpus (final model to deploy).
  const model = fitModel(X, y, { epochs: 3000, lr: 0.5, l2: 1.0 });

  // Honest estimate: out-of-fold predictions from models that never saw each sample.
  const oof = crossValidate(X, y, K, { epochs: 3000, lr: 0.5, l2: 1.0 });

  const trainReport = evaluate(X.map((x) => model.predict(x)), y, 0.5);
  const cvReport = evaluate(oof, y, 0.5);

  // Feature influence (standardised weights → comparable magnitude).
  const importance = FEATURE_KEYS
    .map((key, i) => ({ key, weight: model.w[i] }))
    .sort((a, b) => Math.abs(b.weight) - Math.abs(a.weight));

  saveModel(model, FEATURE_KEYS);

  console.log('==================================================');
  console.log(' MODEL TRAINING');
  console.log('==================================================');
  console.log(`Algorithm : L2-regularised logistic regression`);
  console.log(`Samples   : ${y.length} (${y.filter((v) => v === 1).length} phishing / ${y.filter((v) => v === 0).length} benign)`);
  console.log(`Features  : ${FEATURE_KEYS.length}`);
  console.log(`Folds     : ${K} (stratified, seeded)`);
  console.log('');
  console.log(`Training fit (optimistic): accuracy ${pct(trainReport.accuracy)}  AUC ${trainReport.auc.toFixed(4)}`);
  console.log(`Cross-validated (honest):  accuracy ${pct(cvReport.accuracy)}  precision ${pct(cvReport.precision)}  recall ${pct(cvReport.recall)}  F1 ${pct(cvReport.f1)}  AUC ${cvReport.auc.toFixed(4)}`);
  console.log('');
  console.log('Top features by |standardised weight|:');
  for (const { key, weight } of importance.slice(0, 10)) {
    const direction = weight >= 0 ? 'phishing ↑' : 'benign ↓';
    console.log(`  ${key.padEnd(26)} ${weight >= 0 ? '+' : ''}${weight.toFixed(3)}  (${direction})`);
  }
  console.log('');
  console.log(`Model written to: ${MODEL_PATH}`);
  console.log('==================================================\n');
}

main().catch((error) => {
  console.error('Training failed:', error);
  process.exitCode = 1;
});