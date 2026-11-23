import { SUSPICIOUS_HOSTNAME_KEYWORDS } from '../data/suspiciousKeywords.js';

export const id = 'SUSPICIOUS_KEYWORDS';
export const ruleVersion = '2.0.0';

/**
 * v1 computed a "weightedCount" purely to pick one of three severities.
 * That weighting logic is a Risk Engine decision now — this rule just
 * reports which keywords matched and how (exact token vs substring), and
 * lets the consumer decide how much each match type should count for.
 */
export function observe(ctx) {
  if (!ctx.hostname || ctx.isIpHost) return [];

  const hostLower = ctx.hostname.toLowerCase();
  const tokens = hostLower.split(/[^a-z0-9]+/).filter(Boolean);

  const exactMatches = SUSPICIOUS_HOSTNAME_KEYWORDS.filter((kw) => tokens.includes(kw));
  const substringMatches = SUSPICIOUS_HOSTNAME_KEYWORDS.filter(
    (kw) => !exactMatches.includes(kw) && hostLower.includes(kw)
  );

  if (exactMatches.length === 0 && substringMatches.length === 0) return [];

  return [
    {
      observationId: id,
      category: 'HOST_STRUCTURE',
      data: {
        exactTokenMatches: exactMatches,
        substringMatches: substringMatches,
      },
      evidence: [...exactMatches, ...substringMatches],
      // Exact-token matches are a stronger signal than substring matches
      // (substring matching alone can false-positive against real words —
      // "service" inside "servicenow"), reflected in confidence rather than
      // in a pre-computed severity bucket.
      confidence: exactMatches.length > 0 ? 0.75 : 0.5,
      meta: { sourceRule: id, ruleVersion },
    },
  ];
}
