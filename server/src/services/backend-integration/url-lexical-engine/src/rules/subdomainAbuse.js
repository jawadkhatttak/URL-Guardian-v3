export const id = 'SUBDOMAIN_ABUSE';
export const ruleVersion = '2.0.0';

/**
 * v1 used if/else across three severities here, which silently dropped a
 * true co-occurring fact whenever two applied at once — e.g. a hostname
 * that BOTH has a deceptive hyphenated label AND stacks 4+ subdomain
 * levels would only ever report the label-mimicry branch, never the depth
 * fact, purely because of branch ordering. These are two independently
 * true structural facts about the same hostname, not one fact with three
 * severities, so this version can emit both.
 */
export function observe(ctx) {
  if (ctx.isIpHost || ctx.subdomainLabels.length === 0) return [];

  const observations = [];
  const labels = ctx.subdomainLabels;
  const longestLabel = labels.reduce((a, b) => (b.length > a.length ? b : a), '');
  const hyphenCount = (longestLabel.match(/-/g) || []).length;

  if (longestLabel.length >= 18 && hyphenCount >= 2) {
    observations.push({
      observationId: 'SUBDOMAIN_LABEL_MIMICRY',
      category: 'HOST_STRUCTURE',
      data: {
        label: longestLabel,
        labelLength: longestLabel.length,
        hyphenCount,
        registeredDomain: ctx.registeredDomain,
      },
      evidence: [longestLabel],
      confidence: 0.85, // heuristic threshold-based pattern match, not a syntactic certainty
      meta: { sourceRule: id, ruleVersion },
    });
  }

  if (labels.length >= 3) {
    observations.push({
      observationId: 'SUBDOMAIN_DEPTH',
      category: 'HOST_STRUCTURE',
      data: {
        subdomainLabelCount: labels.length,
        registeredDomain: ctx.registeredDomain,
      },
      evidence: [ctx.subdomain],
      confidence: 1.0, // a label count is an exact fact, no ambiguity
      meta: { sourceRule: id, ruleVersion },
    });
  }

  return observations;
}
