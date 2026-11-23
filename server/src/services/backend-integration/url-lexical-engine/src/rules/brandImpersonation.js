import { KNOWN_BRANDS } from '../data/brands.js';

export const id = 'BRAND_IMPERSONATION';
export const ruleVersion = '2.0.0';

function hasBrandToken(hostLower, brandName) {
  const escaped = brandName.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  const re = new RegExp(`(?:^|[^a-z0-9])${escaped}(?:[^a-z0-9]|$)`, 'i');
  return re.test(hostLower);
}

export function observe(ctx) {
  if (!ctx.hostname || ctx.isIpHost) return [];

  const hostLower = ctx.hostname.toLowerCase();
  const registeredDomainLower = ctx.registeredDomain.toLowerCase();

  for (const brand of KNOWN_BRANDS) {
    if (registeredDomainLower === brand.domain) continue;
    if (brand.alsoOwns?.includes(ctx.tld.toLowerCase())) continue;

    if (hasBrandToken(hostLower, brand.name)) {
      return [
        {
          observationId: id,
          category: 'BRAND_SIGNAL',
          data: {
            matchedBrand: brand.name,
            legitimateBrandDomain: brand.domain,
            actualRegisteredDomain: ctx.registeredDomain,
          },
          evidence: [brand.name, ctx.registeredDomain],
          confidence: 0.9, // token-boundary matched, but a brand name COULD legitimately appear elsewhere in rare cases
          meta: { sourceRule: id, ruleVersion },
        },
      ];
    }
  }

  return [];
}
