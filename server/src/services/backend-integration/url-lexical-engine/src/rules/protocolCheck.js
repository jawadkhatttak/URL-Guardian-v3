export const id = 'INSECURE_PROTOCOL';
export const ruleVersion = '2.0.0';

export function observe(ctx) {
  if (ctx.protocol !== 'http:') return [];

  return [
    {
      observationId: id,
      category: 'TRANSPORT',
      data: {
        protocol: ctx.protocol,
        isEncrypted: false,
      },
      evidence: [ctx.protocol],
      confidence: 1.0,
      meta: { sourceRule: id, ruleVersion },
    },
  ];
}
