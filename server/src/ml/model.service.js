import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { predictProba } from './logisticRegression.js';
import { FEATURE_KEYS } from './dataset.js';

/**
 * Model persistence + inference.
 *
 * The trained model is a plain JSON file (data/model.json) so it can be
 * inspected, diffed and loaded without any runtime dependency. When no model is
 * present, callers fall back to the heuristic score.
 */

const __dirname = path.dirname(fileURLToPath(import.meta.url));
export const MODEL_PATH = path.resolve(__dirname, '../../data/model.json');

let cachedModel = null;

export function hasModel() {
  return fs.existsSync(MODEL_PATH);
}

export function loadModel() {
  if (cachedModel) return cachedModel;
  if (!fs.existsSync(MODEL_PATH)) return null;
  cachedModel = JSON.parse(fs.readFileSync(MODEL_PATH, 'utf8'));
  return cachedModel;
}

export function saveModel(model, featureKeys = FEATURE_KEYS) {
  const serializable = {
    featureKeys,
    mean: model.mean,
    std: model.std,
    w: model.w,
    b: model.b,
    featureCount: model.featureCount,
    trainedAt: new Date().toISOString(),
  };
  fs.mkdirSync(path.dirname(MODEL_PATH), { recursive: true });
  fs.writeFileSync(MODEL_PATH, JSON.stringify(serializable, null, 2));
  cachedModel = serializable;
  return serializable;
}

/**
 * Predict phishing probability (0–1) for a feature-vector object, ordering the
 * values by the model's own featureKeys (falling back to the canonical order).
 * @returns {number|null} null when no model is loaded.
 */
export function predictFromVector(featureVector, model = loadModel()) {
  if (!model) return null;
  const keys = model.featureKeys || FEATURE_KEYS;
  const x = keys.map((key) => Number(featureVector?.[key] ?? 0));
  return predictProba(x, model);
}

export function clearModelCache() {
  cachedModel = null;
}