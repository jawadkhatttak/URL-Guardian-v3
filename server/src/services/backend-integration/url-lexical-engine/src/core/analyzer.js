import { parseUrl } from './parser.js';
import { annotateSuppression } from './ruleDependencies.js';
import { describe } from './describe.js';
import { RULES } from '../rules/index.js';

/**
 * PART 5 — the new pipeline.
 *
 *   Parse → Collect Observations → Annotate Suppression → Derive Findings
 *
 * No score. No level. No recommendation-for-the-whole-scan. This function's
 * only job is: turn one URL into every fact this engine can extract about
 * it, structured for a Correlation Engine and Risk Engine sitting downstream
 * to consume. Any single rule throwing is caught and logged — one broken
 * rule must never take down a scan.
 *
 * @param {string} rawUrl
 * @returns {import('./analyzerOutput.d.ts').LexicalAnalysisResult}
 */
export function analyze(rawUrl) {
  const parsed = parseUrl(rawUrl);

  if (parsed.error) {
    return {
      ok: false,
      error: parsed.error,
      raw: parsed.raw,
    };
  }

  // --- Collect: every rule contributes zero or more raw observations ---
  const allObservations = [];
  for (const rule of RULES) {
    let results = [];
    try {
      results = rule.observe(parsed) ?? [];
    } catch (err) {
      console.error(`[url-lexical-engine] rule "${rule.id}" threw during observe():`, err);
    }
    for (const obs of results) allObservations.push(obs);
  }

  // --- Annotate: suppression as metadata, nothing removed ---
  const observations = annotateSuppression(allObservations);

  // --- Derive: human-readable findings, purely for display/compatibility ---
  const findings = observations
    .map((obs) => {
      const text = describe(obs);
      if (!text) return null;
      return {
        observationId: obs.observationId,
        title: text.title,
        description: text.description,
        recommendation: text.recommendation,
        // Deliberately named suggestedSeverity, not severity — this is a
        // per-observation starting point for a "dumb" presentation layer,
        // NOT an authoritative platform severity. The Risk Engine computes
        // the real one, informed by this plus every other intelligence
        // source, and is free to ignore this value entirely.
        suggestedSeverity: text.baseSeverity,
        references: text.references ?? [],
        confidence: obs.confidence,
        evidence: obs.evidence,
        suppressed: Boolean(obs.suppressedBy),
        suppressedBy: obs.suppressedBy ?? null,
      };
    })
    .filter(Boolean);

  return {
    ok: true,
    engine: 'url-lexical-intelligence',
    engineVersion: '2.0.0',
    timestamp: new Date().toISOString(),
    sourceUrl: parsed.raw,
    correlationKey: parsed.correlationKey,
    urlMetadata: {
      protocol: parsed.protocol,
      hostname: parsed.hostname,
      registeredDomain: parsed.registeredDomain,
      subdomain: parsed.subdomain,
      tld: parsed.tld,
      port: parsed.port,
      explicitPort: parsed.explicitPort,
      isIpHost: parsed.isIpHost,
      pathname: parsed.pathname,
      urlLength: parsed.fullLength,
      normalizedInput: parsed.normalizedInput,
    },
    observations,
    findings,
  };
}
