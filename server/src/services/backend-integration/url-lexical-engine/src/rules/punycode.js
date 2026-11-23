export const id = 'PUNYCODE';
export const ruleVersion = '2.0.0';

export function observe(ctx) {
  if (!ctx.hostname || ctx.isIpHost) return [];

  const punycodeLabels = ctx.labels.filter((label) => label.toLowerCase().startsWith('xn--'));
  if (punycodeLabels.length === 0) return [];

  return [
    {
      observationId: id,
      category: 'HOST_ENCODING',
      data: {
        punycodeLabels,
      },
      evidence: punycodeLabels,
      confidence: 1.0, // syntactic prefix match — deterministic
      meta: { sourceRule: id, ruleVersion },
    },
  ];
}
