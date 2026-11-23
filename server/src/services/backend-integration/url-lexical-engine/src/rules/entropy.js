import { shannonEntropy } from '../utils/entropyMath.js';

export const id = 'HIGH_ENTROPY';
export const ruleVersion = '2.0.0';

const MIN_LABEL_LENGTH = 10;
const MIN_REPORT_ENTROPY = 3.5; // below this, not worth reporting at all — not a severity line

export function observe(ctx) {
  if (!ctx.hostname || ctx.isIpHost) return [];

  const label = ctx.registeredDomain.split('.')[0] || '';
  if (label.length < MIN_LABEL_LENGTH) return [];

  const entropy = shannonEntropy(label.toLowerCase());
  if (entropy < MIN_REPORT_ENTROPY) return [];

  return [
    {
      observationId: id,
      category: 'HOST_STRUCTURE',
      data: {
        label,
        entropyBitsPerChar: Math.round(entropy * 100) / 100,
      },
      evidence: [label],
      // Entropy-based randomness detection has a real false-positive rate
      // against legitimate but unusual-looking brand names — reflected
      // honestly as sub-1.0 confidence even at high measured entropy.
      confidence: entropy >= 4.0 ? 0.7 : 0.5,
      meta: { sourceRule: id, ruleVersion },
    },
  ];
}
