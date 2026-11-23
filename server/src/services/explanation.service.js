/**
 * Explanation Engine — the "dumb frontend" contract. Takes everything the
 * pipeline produced (raw findings + correlations + risk) and turns it into
 * exactly what a UI needs to render, with zero further interpretation
 * required on the frontend side.
 */

import { isDynamicDnsHosted } from './backend-integration/data/dynamicDnsProviders.js';

const RISK_HEADLINES = {
  CRITICAL: 'This URL shows strong, corroborated signs of being malicious.',
  HIGH: 'This URL shows multiple concerning signals worth serious caution.',
  MEDIUM: 'This URL has some indicators worth a closer look before trusting it.',
  LOW: 'This URL shows minor indicators, likely low risk.',
  SAFE: 'No significant phishing or malicious indicators were found.',
};

const RISK_ACTIONS = {
  CRITICAL: 'Do not enter any credentials or personal information. Do not proceed.',
  HIGH: 'Avoid entering credentials or payment details until verified through an official channel.',
  MEDIUM: 'Proceed with caution — verify the source before entering sensitive information.',
  LOW: 'Generally low risk, but standard browsing caution still applies.',
  SAFE: 'No action needed based on current findings — normal browsing caution still applies.',
};

/**
 * @param {object} masterFindings - dns/whois/html/virustotal/urlLexical
 * @param {Array<object>} correlatedFindings - output of processCorrelations()
 * @param {object} riskResult - output of computeRisk()
 * @param {string} targetUrl
 * @returns {object} explanation-ready result for direct frontend rendering
 */
export function buildExplanation(masterFindings, correlatedFindings, riskResult, targetUrl) {
  const { dns = {}, whois = {}, html = {}, virustotal = {}, urlLexical = {}, lexical = {} } = masterFindings;
  const lexicalPayload = urlLexical?.fullFindings ? urlLexical : lexical;

  // One flat, prioritized reason list — correlations first (highest
  // confidence, cross-source), then raw single-source findings — each
  // shaped identically so the frontend can render one component for all of it.
  const reasons = [
    ...correlatedFindings.map((cf) => ({
      source: 'correlation',
      severity: cf.severity,
      confidence: cf.confidence,
      title: cf.title,
      evidence: cf.evidence,
    })),
    ...(lexicalPayload.fullFindings || [])
      .filter((f) => !f.suppressed)
      .map((f) => ({
        source: 'url_lexical',
        severity: f.suggestedSeverity.toUpperCase(),
        confidence: f.confidence >= 0.85 ? 'HIGH' : f.confidence >= 0.6 ? 'MEDIUM' : 'LOW',
        title: f.title,
        evidence: [f.description],
        references: f.references,
      })),
    ...(html.findings || []).map((f) => ({
      source: 'html_analysis',
      severity: html.threatFound ? 'HIGH' : 'MEDIUM',
      confidence: 'MEDIUM',
      title: f,
      evidence: [],
    })),
    ...(virustotal.positives > 0
      ? [
        {
          source: 'virustotal',
          severity: virustotal.threatFound ? 'CRITICAL' : 'MEDIUM',
          confidence: 'HIGH',
          title: `${virustotal.positives} of ${virustotal.totalScanners} security vendors flagged this URL`,
          evidence: [virustotal.findings],
        },
      ]
      : []),
  ];

  const severityRank = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3 };
  reasons.sort((a, b) => (severityRank[a.severity] ?? 4) - (severityRank[b.severity] ?? 4));

  // Inside services/explanation.service.js -> buildExplanation()
  return {
    url: targetUrl,
    verdict: {
      score: riskResult.score,
      riskLevel: riskResult.risk,
      headline: RISK_HEADLINES[riskResult.risk] ?? RISK_HEADLINES.MEDIUM,
      recommendedAction: RISK_ACTIONS[riskResult.risk] ?? RISK_ACTIONS.MEDIUM,

      // 🔥 NEW: Push the transparency profile directly to your frontend UI response
      confidence: riskResult.transparency.verdictConfidence,
      justification: riskResult.transparency.justification,
      totalIndicators: riskResult.transparency.totalSignalsProcessed
    },
    reasons,
    sourceSummary: {
      dns: { checked: true, ipAddress: dns.ipv4?.[0] ?? null },
      whois: {
        checked: true,
        registrar: whois.registerName ?? 'Unknown',
        domainAgeDays: whois.daysSinceRegistration ?? null,
        // Explicit flag so the frontend can show "age data may not reflect
        // this specific subdomain" instead of presenting a misleading
        // "11.7 years old, looks safe" number without context.
        ageDataReliable: !isDynamicDnsHosted(lexicalPayload.urlMetadata?.registeredDomain),
      },
      html: { checked: true, riskScore: html.riskScore ?? null, threatFound: html.threatFound ?? false },
      virustotal: {
        checked: true,
        positives: virustotal.positives ?? 0,
        totalScanners: virustotal.totalScanners ?? 0,
      },
      urlLexical: {
        checked: true,
        observationCount: (lexicalPayload.observations || []).length,
        registeredDomain: lexicalPayload.urlMetadata?.registeredDomain ?? null,
      },
    },
    generatedAt: new Date().toISOString(),
  };
}
