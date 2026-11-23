const REDIRECT_PARAM_NAMES = [
  'redirect', 'url', 'next', 'return', 'return_url', 'returnurl', 'redirect_uri',
  'redirecturi', 'continue', 'dest', 'destination', 'goto', 'target', 'redirect_to',
  'rurl', 'r',
];

export const id = 'REDIRECT_PATTERN';
export const ruleVersion = '2.0.0';

/**
 * v1 returned early on the @ trick, meaning a URL with BOTH an @ userinfo
 * trick AND a suspicious redirect query parameter would never have the
 * second fact reported. Same co-occurrence issue as subdomainAbuse.js —
 * fixed here by checking both and returning every observation found.
 */
export function observe(ctx) {
  const observations = [];

  if (ctx.rawUserinfo) {
    observations.push({
      observationId: 'AT_USERINFO_TRICK',
      category: 'PATH_QUERY',
      data: {
        userinfoText: ctx.rawUserinfo,
        actualHost: ctx.hostname,
      },
      evidence: [ctx.rawUserinfo, ctx.hostname],
      confidence: 1.0, // syntactic fact — the @ delimiter's behavior is unambiguous
      meta: { sourceRule: id, ruleVersion },
    });
  }

  if (ctx.search) {
    let params;
    try {
      params = new URLSearchParams(ctx.search);
    } catch {
      params = null;
    }

    if (params) {
      for (const [key, value] of params.entries()) {
        if (!REDIRECT_PARAM_NAMES.includes(key.toLowerCase())) continue;
        const looksLikeUrl = /^https?:\/\//i.test(value) || /%2f%2f/i.test(value) || value.includes('://');
        if (looksLikeUrl) {
          observations.push({
            observationId: 'OPEN_REDIRECT_PARAM',
            category: 'PATH_QUERY',
            data: {
              paramName: key,
              paramValue: value,
            },
            evidence: [`${key}=${value}`],
            confidence: 0.8, // the param NAME + URL-shaped value is a strong heuristic, not absolute proof of abuse
            meta: { sourceRule: id, ruleVersion },
          });
          break; // one example is sufficient evidence; keep the observation set from ballooning on many matching params
        }
      }
    }
  }

  return observations;
}
