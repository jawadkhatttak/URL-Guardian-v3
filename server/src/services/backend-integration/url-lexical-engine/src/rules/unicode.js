import { hasNonAscii } from '../data/confusables.js';

export const id = 'UNICODE_HOSTNAME';
export const ruleVersion = '2.0.0';

export function observe(ctx) {
  if (!ctx.rawHostname || ctx.isIpHost) return [];
  if (!hasNonAscii(ctx.rawHostname)) return [];

  return [
    {
      observationId: id,
      category: 'HOST_ENCODING',
      data: {
        rawHostname: ctx.rawHostname,
      },
      evidence: [ctx.rawHostname],
      confidence: 1.0,
      meta: { sourceRule: id, ruleVersion },
    },
  ];
}
