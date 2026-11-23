export const id = 'NON_STANDARD_PORT';
export const ruleVersion = '2.0.0';

const STANDARD_PORTS = { 'http:': '80', 'https:': '443', 'ftp:': '21' };
const COMMONLY_ABUSED_PORTS = new Set(['22', '23', '25', '135', '139', '445', '1433', '3306', '3389', '5900']);

export function observe(ctx) {
  if (!ctx.explicitPort) return [];

  const standard = STANDARD_PORTS[ctx.protocol];
  if (ctx.explicitPort === standard) return [];

  return [
    {
      observationId: id,
      category: 'TRANSPORT',
      data: {
        port: ctx.explicitPort,
        protocol: ctx.protocol,
        // Membership in the commonly-abused list is a categorical fact from
        // a static reference list — descriptive, not this rule's opinion
        // about how dangerous it is.
        isKnownCommonlyAbusedPort: COMMONLY_ABUSED_PORTS.has(ctx.explicitPort),
      },
      evidence: [ctx.explicitPort],
      confidence: 1.0,
      meta: { sourceRule: id, ruleVersion },
    },
  ];
}
