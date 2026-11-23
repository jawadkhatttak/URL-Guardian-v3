import { EXACT_SUFFIXES, WILDCARD_SUFFIXES, EXCEPTION_SUFFIXES } from '../data/publicSuffixList.js';

const SCHEME_PREFIX_RE = /^[a-zA-Z][a-zA-Z0-9+.-]*:/;
// Captures: 1=scheme, 2=userinfo (the "@" trick target), 3=host, 4=port
// Host alternation tries a bracketed IPv6 literal first ([2001:db8::1]) since
// plain [^:]+ would otherwise stop at the first colon inside the brackets.
const RAW_AUTHORITY_RE = /^([a-zA-Z][a-zA-Z0-9+.-]*:)\/\/(?:([^/?#@]*)@)?(\[[0-9a-fA-F:]+\]|[^/?#@:]+)(?::(\d+))?/;

const IPV4_RE = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/;
// Deliberately permissive (not a strict RFC4291 validator) — good enough to
// flag "this is an IPv6 literal" for the host-type rules.
const IPV6_LOOSE_RE = /^\[?[0-9a-fA-F:]+\]?$/;

function isIPv4(host) {
  const match = host.match(IPV4_RE);
  if (!match) return false;
  return match.slice(1).every((octet) => Number(octet) <= 255);
}

function isIPv6(host) {
  const stripped = host.replace(/^\[/, '').replace(/\]$/, '');
  return stripped.includes(':') && IPV6_LOOSE_RE.test(host);
}

/**
 * Implements the real Public Suffix List matching algorithm
 * (https://publicsuffix.org/list/ — "Algorithm" section):
 *   1. Find the longest matching rule across exact + wildcard rules.
 *   2. If an exception rule matches at that same length, the real public
 *      suffix is one label SHORTER than what the wildcard would imply.
 *   3. If nothing matches at all, the implicit "*" rule applies: the public
 *      suffix is just the last label.
 *
 * Runs against js/data/publicSuffixList.js, a static snapshot generated
 * from the real Mozilla Public Suffix List (see that file's header).
 */
function findSuffixLabelCount(labels) {
  let best = 0;

  for (let n = 1; n <= labels.length; n++) {
    const candidate = labels.slice(-n).join('.');
    if (EXACT_SUFFIXES.has(candidate)) best = Math.max(best, n);
  }

  // Wildcard rules need at least one label in front of the fixed part
  // ("*.ck" requires something.ck — "ck" alone doesn't count), so n starts at 2.
  for (let n = 2; n <= labels.length; n++) {
    const fixedPart = labels.slice(-(n - 1)).join('.');
    if (WILDCARD_SUFFIXES.has(fixedPart)) best = Math.max(best, n);
  }

  // No rule matched at all — the implicit default rule "*" applies: treat
  // the last label alone as the public suffix (correct for ordinary,
  // unlisted TLDs and malformed/fake ones alike).
  if (best === 0) best = 1;

  // An exception rule at the SAME length overrides the wildcard match it
  // corresponds to, carving one label back out (e.g. "*.ck" would treat
  // "www.ck" as a 2-label suffix, but "!www.ck" says it's really just "ck").
  const candidateAtBest = labels.slice(-best).join('.');
  if (EXCEPTION_SUFFIXES.has(candidateAtBest)) best -= 1;

  return Math.min(best, labels.length);
}

/**
 * Splits a hostname into { subdomain, registeredDomain, tld } using the
 * real Public Suffix List matching algorithm above.
 */
function splitDomain(hostname) {
  const labels = hostname.split('.').filter(Boolean);
  if (labels.length <= 1) {
    return { subdomain: '', registeredDomain: hostname, tld: '' };
  }

  const suffixLabelCount = findSuffixLabelCount(labels);
  const tld = labels.slice(-suffixLabelCount).join('.');

  if (labels.length <= suffixLabelCount) {
    // The whole hostname IS the public suffix (e.g. someone typed "co.uk"
    // directly) — there's no registrable label left in front of it.
    return { subdomain: '', registeredDomain: hostname, tld };
  }

  const remaining = labels.slice(0, labels.length - suffixLabelCount);
  const registeredLabel = remaining[remaining.length - 1];
  const subdomainLabels = remaining.slice(0, -1);

  return {
    subdomain: subdomainLabels.join('.'),
    registeredDomain: `${registeredLabel}.${tld}`,
    tld,
    tld,
  };
}

/**
 * Parses a raw, possibly messy, user-supplied URL string.
 *
 * Returns either:
 *   { error: string, raw: string }                       — unparseable input
 *   { ...full parsed context object... }                 — success
 */
export function parseUrl(rawInputUntrimmed) {
  const raw = (rawInputUntrimmed || '').trim();
  if (!raw) {
    return { error: 'Please enter a URL to analyze.', raw };
  }

  // Only prepend a scheme if none exists at all — never mask an existing
  // (possibly dangerous) scheme like javascript: or data: by rewriting it.
  const normalizedInput = SCHEME_PREFIX_RE.test(raw) ? raw : `http://${raw}`;

  // Grab the host BEFORE the URL constructor gets a chance to punycode-encode
  // it. This is the only place in the app that still sees literal Unicode
  // characters the way an attacker typed/pasted them.
  const rawMatch = normalizedInput.match(RAW_AUTHORITY_RE);
  const rawUserinfo = rawMatch ? rawMatch[2] || '' : '';
  const rawHostBracketed = rawMatch ? rawMatch[3] || '' : '';
  const rawHost = rawHostBracketed.replace(/^\[/, '').replace(/\]$/, '');

  let urlObj;
  try {
    urlObj = new URL(normalizedInput);
  } catch (err) {
    return { error: 'That doesn\'t parse as a valid URL.', raw };
  }

  const protocol = urlObj.protocol; // includes trailing ':'
  let hostname = urlObj.hostname; // ASCII/punycode form, may be '' for javascript:/data:
  const isBracketedV6 = hostname.startsWith('[') && hostname.endsWith(']');
  const hostnameNoBrackets = isBracketedV6 ? hostname.slice(1, -1) : hostname;

  const ipv4 = isIPv4(hostnameNoBrackets);
  const ipv6 = isBracketedV6 || isIPv6(hostnameNoBrackets);
  const isIpHost = ipv4 || ipv6;

  let subdomain = '';
  let registeredDomain = hostnameNoBrackets;
  let tld = '';
  if (hostname && !isIpHost) {
    const split = splitDomain(hostnameNoBrackets);
    registeredDomain = split.registeredDomain;
    tld = split.tld;

    const rawSubLabels = split.subdomain ? split.subdomain.split('.').filter(Boolean) : [];
    // "www" is a near-universal, benign convention rather than a meaningfully
    // distinct subdomain — strip exactly one leading "www" so it doesn't get
    // treated identically to a real subdomain in the UI or the abuse rule.
    // Only an exact match is stripped; "www2", "www-login", etc. are left
    // alone since those ARE meaningful signal.
    const displaySubLabels =
      rawSubLabels.length > 0 && rawSubLabels[0].toLowerCase() === 'www'
        ? rawSubLabels.slice(1)
        : rawSubLabels;
    subdomain = displaySubLabels.join('.');
  }

  const port = urlObj.port || (protocol === 'https:' ? '443' : protocol === 'http:' ? '80' : '');
  const explicitPort = urlObj.port; // '' means "not explicitly specified in the URL"

  // Explicit, stable join key for cross-engine correlation (WHOIS, DNS,
  // VirusTotal, the Correlation Engine). Deliberately NOT just
  // "registeredDomain" reused implicitly — an IP-hosted URL has no
  // registrable domain at all, and every consumer needs one unambiguous
  // answer for "what do I key this against" rather than re-deriving their
  // own fallback logic and risking two services disagreeing.
  const correlationKey = isIpHost ? hostnameNoBrackets : registeredDomain || hostnameNoBrackets;

  return {
    error: null,
    raw,
    normalizedInput,
    href: urlObj.href,
    protocol,
    hostname: hostnameNoBrackets,
    rawHostname: rawHost, // pre-punycode, literal characters as typed
    rawUserinfo, // text before '@' in the authority, if any
    isIpHost,
    ipVersion: ipv6 ? 'v6' : ipv4 ? 'v4' : null,
    subdomain,
    subdomainLabels: subdomain ? subdomain.split('.').filter(Boolean) : [],
    registeredDomain,
    tld,
    port,
    explicitPort,
    pathname: urlObj.pathname,
    search: urlObj.search,
    hash: urlObj.hash,
    fullLength: raw.length,
    labels: hostnameNoBrackets ? hostnameNoBrackets.split('.').filter(Boolean) : [],
    correlationKey,
  };
}
