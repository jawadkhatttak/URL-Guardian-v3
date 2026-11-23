import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
export const DATASET_PATH = path.resolve(__dirname, '../../data/featureDataset.json');

/**
 * Ordered feature keys the model is trained on. This is the contract between
 * the feature extractor and the model — the same order is used for training and
 * for live prediction.
 */
export const FEATURE_KEYS = [
  'domain_age_days',
  'domain_age_is_new',
  'vt_positive_ratio',
  'vt_positives',
  'lexical_finding_count',
  'has_brand_impersonation',
  'has_typosquat',
  'has_homograph',
  'has_punycode',
  'has_ip_host',
  'has_shortener',
  'has_suspicious_keyword',
  'url_length',
  'brand_in_host',
  'is_legit_major_domain',
  'has_https',
  'tld_risk',
  'html_risk_score',
  'html_signal_count',
  'html_has_password_field',
  'html_has_external_form',
  'html_has_brand_mismatch',
  'correlation_count',
  'has_dynamic_dns',
];

/**
 * Load the materialised feature dataset produced by `npm run evaluate`.
 * @param {string} [datasetPath]
 * @returns {{ samples:Array, X:number[][], y:number[], featureKeys:string[] }}
 */
export function loadFeatureDataset(datasetPath = DATASET_PATH) {
  if (!fs.existsSync(datasetPath)) {
    throw new Error(`Feature dataset not found at ${datasetPath}. Run "npm run evaluate" first.`);
  }

  const samples = JSON.parse(fs.readFileSync(datasetPath, 'utf8'));
  const X = samples.map((sample) => FEATURE_KEYS.map((key) => Number(sample.featureVector?.[key] ?? 0)));
  const y = samples.map((sample) => (sample.label === 'phishing' ? 1 : 0));

  return { samples, X, y, featureKeys: FEATURE_KEYS };
}

/** Row-vector for a single feature vector object, ordered by FEATURE_KEYS. */
export function vectorToRow(featureVector, featureKeys = FEATURE_KEYS) {
  return featureKeys.map((key) => Number(featureVector?.[key] ?? 0));
}