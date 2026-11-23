export const id = 'LONG_URL';
export const ruleVersion = '2.0.0';

// Below this, a URL's length isn't a meaningful signal either way — not a
// severity threshold, just a floor for "not worth reporting at all."
const MIN_REPORT_THRESHOLD = 90;

/**
 * v1 had two severity tiers (>=150 "medium", >=90 "low") on what is
 * genuinely ONE continuous fact: the URL's character length. Collapsing
 * that into a single observation carrying the raw number, rather than two
 * mutually-exclusive severity branches, means the Risk Engine can define
 * (and later re-tune) its own thresholds on this number without this rule
 * needing a code change every time the threshold should move.
 */
export function observe(ctx) {
  const len = ctx.fullLength;
  if (len < MIN_REPORT_THRESHOLD) return [];

  return [
    {
      observationId: id,
      category: 'HOST_STRUCTURE',
      data: {
        urlLength: len,
      },
      evidence: [`${len} characters`],
      confidence: 1.0, // it's just a length count — no ambiguity in the measurement itself
      meta: { sourceRule: id, ruleVersion },
    },
  ];
}
