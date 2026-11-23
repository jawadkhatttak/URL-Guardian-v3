/**
 * Example implementation of the Observation contract (see observation.d.ts)
 * for the IP-address rule. This is the pattern all 16 rules in src/rules/
 * follow — see that directory for the full set.
 */

export const id = 'IP_ADDRESS_HOST';
export const ruleVersion = '2.0.0'; // bumped from v1's implicit "1.0" any time this logic changes meaningfully

/**
 * @param {import('../core/parser.js').ParsedUrlContext} ctx
 * @returns {import('../core/observation.d.ts').Observation[]}
 */
export function observe(ctx) {
  if (!ctx.isIpHost) return [];

  return [
    {
      observationId: id,
      category: 'HOST_IDENTITY',
      data: {
        isIpHost: true,
        ipVersion: ctx.ipVersion,
        hostValue: ctx.hostname,
      },
      evidence: [ctx.hostname],
      confidence: 1.0,
      meta: { sourceRule: id, ruleVersion },
    },
  ];
}
