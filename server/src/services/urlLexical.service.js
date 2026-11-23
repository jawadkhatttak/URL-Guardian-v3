import { analyze } from './backend-integration/url-lexical-engine/src/core/analyzer.js';

/**
 * Wraps the URL lexical engine (built separately — see url-lexical-engine/)
 * to match the output convention your dns/whois/html/virustotal services
 * already use: a `success` flag and a human-readable `findings` array for
 * display, PLUS the raw `observations` array underneath for the
 * correlation/risk engines to actually reason over structurally.
 *
 * Unlike your other four services, this one has no network I/O — it's pure
 * synchronous string parsing — but is kept `async` so it drops into the
 * same `await getXInfo(...)` call pattern your orchestrator already uses
 * for dns/whois/html/virustotal without special-casing it.
 *
 * @param {string} url
 * @returns {Promise<object>}
 */
export async function getUrlLexicalInfo(url) {
  const result = analyze(url);

  if (!result.ok) {
    return {
      success: false,
      error: result.error,
      findings: [],
      observations: [],
    };
  }

  return {
    url: url,
    success: true,
    correlationKey: result.correlationKey,
    urlMetadata: result.urlMetadata,
    // Human-readable strings, same shape as html.findings — lets you drop
    // this straight into any display code already written for the other
    // services without writing new rendering logic.
    findings: result.findings.map((f) => `${f.title}: ${f.description}`),
    // Raw structured data — THIS is what correlation.service.js and
    // risk.service.js should actually key off, not the strings above.
    observations: result.observations,
    fullFindings: result.findings, // includes severity/confidence/evidence/references per finding
  };
}
