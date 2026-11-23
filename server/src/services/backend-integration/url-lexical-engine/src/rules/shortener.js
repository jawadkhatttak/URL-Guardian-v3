import { URL_SHORTENERS } from '../data/shorteners.js';

export const id = 'URL_SHORTENER';
export const ruleVersion = '2.0.0';

export function observe(ctx) {
  if (!ctx.hostname) return [];
  const isShortener = URL_SHORTENERS.includes(ctx.hostname.toLowerCase());
  if (!isShortener) return [];

  return [
    {
      observationId: id,
      category: 'REPUTATION_HINT',
      data: {
        shortenerHostname: ctx.hostname,
      },
      evidence: [ctx.hostname],
      confidence: 1.0, // exact list membership — deterministic
      meta: { sourceRule: id, ruleVersion },
    },
  ];
}
