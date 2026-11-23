/**
 * PART 7 — Suppression is advisory-only now, computed over observationId
 * (not ruleId, since some rules emit multiple distinct observationIds —
 * e.g. SUBDOMAIN_ABUSE produces SUBDOMAIN_LABEL_MIMICRY and/or
 * SUBDOMAIN_DEPTH as separate ids).
 *
 * Every observation this module receives is returned. Nothing is deleted.
 * Suppressed observations get one extra field — `suppressedBy` — set to the
 * observationId of the more specific fact that explains the same
 * underlying phenomenon. Downstream consumers choose what to do with that:
 *
 *   - A "v1-compatible" presentation layer can filter suppressedBy != null
 *     to reproduce the old de-duplicated finding list.
 *   - The Correlation Engine and Risk Engine see everything, always, and
 *     decide for themselves whether the suppression relationship still
 *     matters once WHOIS/DNS/VirusTotal data is in the picture.
 */

const SUPPRESSION_RULES = [
  // NOTE: v1 had an "IP_ADDRESS_HOST suppresses SUBDOMAIN_ABUSE/BRAND_*/etc."
  // entry here. Auditing it during this migration found it was dead code —
  // every one of those rules already has an `isIpHost` short-circuit guard
  // (see subdomainAbuse.js, brandImpersonation.js, suspiciousKeywords.js,
  // entropy.js, levenshteinBrand.js), so none of them can ever produce an
  // observation on an IP-hosted URL to begin with. There was never
  // anything for that suppression rule to suppress. Removed rather than
  // carried forward silently.
  {
    trigger: 'HOMOGRAPH',
    suppresses: ['UNICODE_HOSTNAME', 'PUNYCODE'],
    reason: 'HOMOGRAPH is the more specific explanation for why this hostname uses non-ASCII/punycode encoding.',
  },
  {
    trigger: 'BRAND_IMPERSONATION',
    suppresses: ['BRAND_TYPOSQUAT'],
    reason: 'An exact brand keyword in the hostname is more specific than a fuzzy near-miss against the same brand.',
  },
  {
    trigger: 'DANGEROUS_PROTOCOL',
    suppresses: ['INSECURE_PROTOCOL', 'NON_STANDARD_PORT'],
    reason: 'javascript:/data: URLs have no meaningful transport security or port to evaluate.',
  },
];

/**
 * @param {import('./observation.d.ts').Observation[]} observations
 * @returns {import('./observation.d.ts').Observation[]} the SAME observations,
 *          each optionally annotated with { suppressedBy, suppressedReason }.
 *          Length in === length out, always.
 */
export function annotateSuppression(observations) {
  const presentIds = new Set(observations.map((o) => o.observationId));
  const suppressionMap = new Map(); // observationId -> { by, reason }

  for (const rule of SUPPRESSION_RULES) {
    if (!presentIds.has(rule.trigger)) continue;
    for (const suppressedId of rule.suppresses) {
      if (presentIds.has(suppressedId) && !suppressionMap.has(suppressedId)) {
        suppressionMap.set(suppressedId, { by: rule.trigger, reason: rule.reason });
      }
    }
  }

  return observations.map((obs) => {
    const suppression = suppressionMap.get(obs.observationId);
    if (!suppression) return obs;
    return {
      ...obs,
      suppressedBy: suppression.by,
      suppressedReason: suppression.reason,
    };
  });
}
