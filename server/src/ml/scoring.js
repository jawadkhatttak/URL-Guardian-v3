import { levelForScore } from '../services/risk.service.js';
import { loadModel, predictFromVector } from './model.service.js';

/**
 * Resolves the final score for a scan given the heuristic score and the
 * feature vector. Supports three modes (env SCORING_MODE):
 *
 *   heuristic — use the heuristic score only.
 *   ml        — use the model's phishing probability × 100.
 *   hybrid    — blend the model probability with the heuristic score, with a
 *               fail-safe floor: a HIGH/CRITICAL heuristic verdict (>= 41) is
 *               preserved as-is, and the ML only modulates borderline scores.
 *               This is the default mode.
 *
 * When no trained model is available the heuristic score is always used, so the
 * system degrades gracefully.
 */

const HIGH_THRESHOLD = 41; // score at which the heuristic verdict is HIGH

export function combineScores(heuristicScore, mlProbability, { mode = 'hybrid', mlWeight = 0.5 } = {}) {
  const mlScore = mlProbability == null ? null : mlProbability * 100;

  let score;
  if (mode === 'ml' && mlScore != null) {
    score = mlScore;
  } else if (mode !== 'hybrid' || mlScore == null) {
    score = heuristicScore;
  } else {
    const blended = mlWeight * mlScore + (1 - mlWeight) * heuristicScore;
    // Fail-safe: trust a strong heuristic verdict; only modulate borderline ones.
    score = heuristicScore >= HIGH_THRESHOLD ? heuristicScore : blended;
  }

  score = Math.min(100, Math.max(0, Math.round(score)));
  return { score, mlScore: mlScore == null ? null : Math.round(mlScore * 10) / 10 };
}

export function resolveScoring(featureVector, heuristicScore) {
  const mode = (process.env.SCORING_MODE || 'hybrid').toLowerCase();
  const mlWeight = Math.min(1, Math.max(0, Number(process.env.ML_WEIGHT ?? 0.5)));

  const fallback = (effectiveMode) => ({
    mode: effectiveMode,
    score: heuristicScore,
    risk: levelForScore(heuristicScore),
    heuristicScore,
    mlScore: null,
    mlProbability: null,
    mlWeight,
  });

  if (mode === 'heuristic') return fallback('heuristic');

  const model = loadModel();
  if (!model) return fallback('heuristic');

  const mlProbability = predictFromVector(featureVector, model);
  const { score, mlScore } = combineScores(heuristicScore, mlProbability, { mode, mlWeight });

  return {
    mode: mode === 'ml' ? 'ml' : 'hybrid',
    score,
    risk: levelForScore(score),
    heuristicScore,
    mlScore,
    mlProbability,
    mlWeight,
  };
}