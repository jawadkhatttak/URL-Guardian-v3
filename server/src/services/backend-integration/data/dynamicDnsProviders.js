/**
 * Dynamic-DNS / free-subdomain-hosting providers that are commonly abused
 * for phishing infrastructure specifically BECAUSE they defeat naive
 * WHOIS-age checks: the provider's own registrable domain (e.g. dynv6.net)
 * can be a decade old while the attacker-controlled subdomain
 * (netflix-suporte.dynv6.net) was created an hour ago — and there is no
 * public WHOIS record for that subdomain creation, because dynamic-DNS
 * subdomains aren't registered through ICANN at all.
 *
 * Every entry below was checked against the REAL Public Suffix List
 * (js/data/publicSuffixList.js) before being included — this isn't a
 * guessed list, it's confirmed against the actual PSL's PRIVATE DOMAINS
 * section.
 *
 * WHY THIS MATTERS: whois.daysSinceRegistration is only meaningful when
 * the URL's registered domain (per PSL) is the actual entity someone
 * registered. When it's a dynamic-DNS suffix, that field describes the
 * PROVIDER's infrastructure age, not the attacker's. Any correlation rule
 * using domain age MUST check this list first and treat the WHOIS age
 * signal as not-applicable when the domain sits on one of these suffixes.
 */
export const DYNAMIC_DNS_PROVIDERS = new Set([
  'dynv6.net',
  'duckdns.org',
  'no-ip.org',
  'no-ip.biz',
  'ddns.net',
  'hopto.org',
  'zapto.org',
  'sytes.net',
  'servequake.com',
  'ngrok.io',
  'ngrok-free.app',
  'serveo.net',
  'localtunnel.me',
  'trycloudflare.com',
  'pagekite.me',
]);

/**
 * @param {string} registeredDomain - from the URL lexical engine's parsed output
 * @returns {boolean}
 */
export function isDynamicDnsHosted(registeredDomain) {
  if (!registeredDomain) return false;
  // registeredDomain is already "label.suffix" (e.g. "netflix-suporte.dynv6.net") —
  // the suffix itself is what we're checking against the provider list.
  const parts = registeredDomain.toLowerCase().split('.');
  for (let i = 1; i < parts.length; i++) {
    const candidateSuffix = parts.slice(i).join('.');
    if (DYNAMIC_DNS_PROVIDERS.has(candidateSuffix)) return true;
  }
  return false;
}
