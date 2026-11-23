import { extractAll } from './features/featureExtractor.service.js';
import { DEVELOPER_PLATFORMS, round1 } from './features/featureWeights.js';

/**
 * Risk Engine
 * -----------
 * Consumes the unified feature list produced by featureExtractor.service.js and
 * turns it into a 0–100 risk score through a single code path:
 *
 *   extract features → mitigate (host context) → sum weights → cap at 100 →
 *   rank contributions → derive transparency metadata.
 *
 * All per-source weighting lives in the extractor; this module only handles the
 * scoring mechanics (mitigation, aggregation, level thresholds, explanation).
 */

/**
 * Mitigates false positives dynamically based on host reputation context.
 */
function applyMitigations(features, hostname) {
  const isCloudHost = DEVELOPER_PLATFORMS.some((platform) => hostname.endsWith(platform));
  const isLocalHost = hostname === 'localhost' || hostname === '127.0.0.1' || hostname.endsWith('.local');

  return features.map((feature) => {
    let mitigatedValue = feature.weight;
    let note = null;

    if (isCloudHost) {
      if (feature.id === 'CORR_DYNAMIC_DNS_HOSTING') {
        mitigatedValue = round1(feature.weight * 0.2);
        note = 'Mitigated: Expected dynamic/shared infrastructure on developer cloud host.';
      }
      if (feature.id === 'CORR_HIGH_RISK_PHISHING_CANDIDATE' || feature.id === 'WHOIS_NEW_REGISTRATION') {
        mitigatedValue = round1(feature.weight * 0.5);
        note = 'Mitigated: Young registration weight reduced for trusted cloud provider platform.';
      }
    }

    if (isLocalHost) {
      mitigatedValue = 0;
      note = 'Mitigated: Development environments ignored by policy.';
    }

    return {
      ...feature,
      contribution: mitigatedValue,
      mitigated: mitigatedValue !== feature.weight,
      mitigationReason: note,
    };
  });
}

export function levelForScore(score) {
  if (score >= 71) return 'CRITICAL';
  if (score >= 41) return 'HIGH';
  if (score >= 21) return 'MEDIUM';
  if (score >= 1) return 'LOW';
  return 'SAFE';
}

function calculateVerdictConfidence(contributions) {
  const activeSignals = contributions.filter((c) => c.contribution > 0);
  const uniqueSources = new Set(activeSignals.map((c) => c.source));
  const uniqueCount = uniqueSources.size;

  if (uniqueCount >= 3) return 'HIGH';
  if (uniqueCount === 2) return 'MEDIUM';
  if (uniqueCount === 1) return 'LOW';
  return 'NONE';
}

function generateVerdictJustification(score, contributions) {
  if (score === 0) {
    return 'No indicators of threat activity or structural deception were detected during scanning.';
  }

  const activeContributions = contributions.filter((c) => c.contribution > 0);
  if (activeContributions.length === 0) {
    return 'All scan indicators were contextually mitigated to SAFE for this environment.';
  }

  const heaviestContribution = activeContributions[0];
  let text = `Score driven primarily by ${heaviestContribution.title} (+${heaviestContribution.contribution} risk points)`;
  if (activeContributions.length > 1) {
    text += `, supported by ${activeContributions.length - 1} other security observations.`;
  }
  return text;
}

export function computeRisk(masterFindings, correlatedFindings, targetUrl) {
  const hostname = new URL(targetUrl.toLowerCase()).hostname;

  const { features, featureVector } = extractAll(masterFindings, correlatedFindings, targetUrl);

  const mitigatedFeatures = applyMitigations(features, hostname);
  const total = mitigatedFeatures.reduce((sum, feature) => sum + feature.contribution, 0);
  const score = Math.min(100, Math.round(total));

  const sortedFeatures = [...mitigatedFeatures].sort((a, b) => b.contribution - a.contribution);

  return {
    score,
    risk: levelForScore(score),
    // `contributions` is kept for backward compatibility; `features` is the new
    // canonical name for the same unified, mitigated list.
    contributions: sortedFeatures,
    features: sortedFeatures,
    featureVector,
    transparency: {
      verdictConfidence: calculateVerdictConfidence(sortedFeatures),
      justification: generateVerdictJustification(score, sortedFeatures),
      totalSignalsProcessed: sortedFeatures.length,
      mitigationsApplied: sortedFeatures.filter((f) => f.mitigated).length,
    },
  };
}