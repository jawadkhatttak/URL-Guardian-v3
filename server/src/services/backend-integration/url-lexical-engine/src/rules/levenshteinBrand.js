import { KNOWN_BRANDS } from '../data/brands.js';
import { levenshtein } from '../utils/levenshtein.js';

export const id = 'BRAND_TYPOSQUAT';
export const ruleVersion = '2.1.0';

const MIN_BRAND_LENGTH = 4;
const MAX_DISTANCE = 2;
// Tokens inside a hyphenated label are matched more strictly (distance 1),
// because short dictionary words appear in hyphenated domains far more often.
const MAX_TOKEN_DISTANCE = 1;
const MIN_TOKEN_LENGTH = 6; // avoids short-word collisions like "apply" ≈ "apple"

// Common character substitutions used in typosquats (paypa1 → paypal, g00gle → google)
const LEET_MAP = { 0: 'o', 1: 'l', 3: 'e', 4: 'a', 5: 's', 7: 't', $: 's', '@': 'a' };
const normalizeLeet = (s) => s.replace(/[013457$@]/g, (ch) => LEET_MAP[ch]);

export function observe(ctx) {
  if (!ctx.hostname || ctx.isIpHost) return [];

  const regLabel = ctx.registeredDomain.split('.')[0]?.toLowerCase() ?? '';
  if (!regLabel) return [];

  // Individual parts of a hyphenated label, e.g. "paypa1-login-verify" → ["paypa1", "login", "verify"]
  const tokens = regLabel.includes('-') ? regLabel.split('-').filter(Boolean) : [];

  let closest = null;
  const consider = (candidate, brand, distance) => {
    if (!closest || distance < closest.distance) closest = { brand, distance, candidate };
  };

  for (const brand of KNOWN_BRANDS) {
    if (brand.name.length < MIN_BRAND_LENGTH) continue;
    if (ctx.registeredDomain.toLowerCase() === brand.domain) continue;

    // 1. Whole registered label vs brand
    const distance = levenshtein(regLabel, brand.name);
    const lengthDiffOk = Math.abs(regLabel.length - brand.name.length) <= MAX_DISTANCE;
    if (distance > 0 && distance <= MAX_DISTANCE && lengthDiffOk) {
      consider(regLabel, brand, distance);
    } else if (regLabel !== brand.name && normalizeLeet(regLabel) === brand.name) {
      consider(regLabel, brand, 1);
    }

    // 2. Each hyphen-separated token vs brand (exact brand tokens are handled by BRAND_IMPERSONATION)
    for (const token of tokens) {
      if (token === brand.name) continue;
      if (normalizeLeet(token) === brand.name) {
        consider(token, brand, 1);
        continue;
      }
      if (token.length < MIN_TOKEN_LENGTH || brand.name.length < MIN_TOKEN_LENGTH) continue;
      const tokenDistance = levenshtein(token, brand.name);
      if (tokenDistance > 0 && tokenDistance <= MAX_TOKEN_DISTANCE) {
        consider(token, brand, tokenDistance);
      }
    }
  }

  if (!closest) return [];

  return [
    {
      observationId: id,
      category: 'BRAND_SIGNAL',
      data: {
        candidateLabel: closest.candidate,
        matchedBrand: closest.brand.name,
        legitimateBrandDomain: closest.brand.domain,
        editDistance: closest.distance,
      },
      evidence: [regLabel, closest.brand.name],
      // Edit distance 1 is far more likely deliberate than distance 2 —
      // reflected as confidence, not a severity tier baked into the rule.
      confidence: closest.distance === 1 ? 0.9 : 0.7,
      meta: { sourceRule: id, ruleVersion },
    },
  ];
}
