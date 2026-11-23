export const id = 'DANGEROUS_PROTOCOL';
export const ruleVersion = '2.0.0';

const DANGEROUS_PROTOCOLS = ['javascript:', 'data:', 'vbscript:'];

export function observe(ctx) {
  if (!DANGEROUS_PROTOCOLS.includes(ctx.protocol)) return [];

  return [
    {
      observationId: id,
      category: 'TRANSPORT',
      data: {
        protocol: ctx.protocol,
      },
      evidence: [ctx.protocol],
      confidence: 1.0,
      meta: { sourceRule: id, ruleVersion },
    },
  ];
}
