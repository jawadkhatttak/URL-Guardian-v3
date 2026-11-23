/**
 * PART 3/9 continuation — the describe() layer.
 *
 * This is where v1's title/description/recommendation/severity text lives
 * now — NOT inside the rules. A rule observes; this function interprets.
 * That separation is what lets severity wording change (or eventually be
 * computed by an ML-informed Risk Engine) without ever touching detection
 * logic in src/rules/.
 *
 * Keyed by observationId so it stays a flat, auditable lookup rather than
 * scattered logic — adding a 17th rule means adding one entry here too.
 */

const DESCRIPTORS = {
  IP_ADDRESS_HOST: (obs) => ({
    title: 'IP Address Used as Host',
    description: `The link points directly to an IP address (${obs.data.ipVersion === 'v6' ? 'IPv6' : 'IPv4'}: ${obs.data.hostValue}) instead of a domain name. This bypasses DNS-based reputation and blocklist checks entirely.`,
    recommendation: 'Treat raw-IP links with strong suspicion, especially in emails or messages.',
    baseSeverity: 'high',
    references: [],
  }),

  URL_SHORTENER: (obs) => ({
    title: 'URL Shortener Detected',
    description: `"${obs.data.shortenerHostname}" is a known link-shortening service. The visible link hides the actual destination domain until you click through.`,
    recommendation: 'Resolve the shortened link first before trusting or clicking it.',
    baseSeverity: 'medium',
    references: [],
  }),

  INSECURE_PROTOCOL: () => ({
    title: 'Insecure HTTP Connection',
    description: 'This URL uses unencrypted HTTP rather than HTTPS. Any data submitted on the page can be intercepted or modified in transit.',
    recommendation: 'Avoid entering credentials or personal data on HTTP pages.',
    baseSeverity: 'medium',
    references: [],
  }),

  LONG_URL: (obs) => ({
    title: obs.data.urlLength >= 150 ? 'Unusually Long URL' : 'Long URL',
    description: `This URL is ${obs.data.urlLength} characters long, longer than typical for a simple link.`,
    recommendation: 'Inspect the hostname carefully rather than judging the link by its path or query string.',
    baseSeverity: obs.data.urlLength >= 150 ? 'medium' : 'low',
    references: [],
  }),

  SUBDOMAIN_LABEL_MIMICRY: (obs) => ({
    title: 'Deceptive Subdomain Label',
    description: `The subdomain "${obs.data.label}" is long and hyphen-heavy, a pattern commonly used to make a subdomain visually resemble a full, trustworthy domain name.`,
    recommendation: `Compare the actual registered domain ("${obs.data.registeredDomain}") to what you'd expect.`,
    baseSeverity: 'high',
    references: [],
  }),

  SUBDOMAIN_DEPTH: (obs) => ({
    title: obs.data.subdomainLabelCount >= 4 ? 'Excessive Subdomain Depth' : 'Multiple Subdomain Levels',
    description: `This hostname stacks ${obs.data.subdomainLabelCount} subdomain labels in front of "${obs.data.registeredDomain}".`,
    recommendation: 'Read the hostname from right to left — the registered domain is what actually controls this site.',
    baseSeverity: obs.data.subdomainLabelCount >= 4 ? 'medium' : 'low',
    references: [],
  }),

  SUSPICIOUS_KEYWORDS: (obs) => ({
    title: 'Suspicious Keyword in Hostname',
    description: `The hostname contains term(s) commonly used to manufacture urgency or false trust: ${[...obs.data.exactTokenMatches, ...obs.data.substringMatches].join(', ')}.`,
    recommendation: 'Treat this as supporting evidence, not a verdict on its own.',
    baseSeverity: obs.data.exactTokenMatches.length >= 2 ? 'high' : obs.data.exactTokenMatches.length === 1 ? 'medium' : 'low',
    references: [],
  }),

  BRAND_IMPERSONATION: (obs) => ({
    title: 'Brand Name Impersonation',
    description: `The hostname references "${obs.data.matchedBrand}" but the actual registered domain is "${obs.data.actualRegisteredDomain}", not ${obs.data.legitimateBrandDomain}.`,
    recommendation: `If you expect this to be ${obs.data.matchedBrand}, type ${obs.data.legitimateBrandDomain} directly into your browser instead.`,
    baseSeverity: 'critical',
    references: [],
  }),

  PUNYCODE: (obs) => ({
    title: 'Punycode-Encoded Domain',
    description: `One or more labels in this hostname are punycode-encoded (${obs.data.punycodeLabels.join(', ')}), meaning the real domain contains internationalized characters.`,
    recommendation: "Check what the decoded characters actually render as before trusting this domain.",
    baseSeverity: 'high',
    references: [{ title: 'RFC 3492: Punycode', url: 'https://www.rfc-editor.org/rfc/rfc3492' }],
  }),

  UNICODE_HOSTNAME: (obs) => ({
    title: 'Non-ASCII Characters in Hostname',
    description: `The hostname, as typed, contains non-ASCII characters ("${obs.data.rawHostname}").`,
    recommendation: 'Verify the exact characters with an IDN-homograph checker before trusting this domain by sight.',
    baseSeverity: 'medium',
    references: [],
  }),

  HOMOGRAPH: (obs) => ({
    title: obs.data.confusableCharacters.length > 0 ? 'Homograph / Confusable Character Attack' : 'Mixed-Script Hostname',
    description:
      obs.data.confusableCharacters.length > 0
        ? `This hostname mixes ordinary Latin letters with visually identical characters from another script: ${obs.data.confusableCharacters.map((c) => `"${c.char}"→"${c.mimics}"`).join(', ')}.`
        : `This hostname mixes characters from multiple writing systems (${obs.data.scriptsPresent.join(', ')}).`,
    recommendation: 'Never trust this domain by sight alone — verify the exact characters with an IDN-homograph checker.',
    baseSeverity: obs.data.confusableCharacters.length > 0 ? 'critical' : 'high',
    references: [
      { title: 'Unicode Technical Standard #39: Unicode Security Mechanisms', url: 'https://unicode.org/reports/tr39/' },
    ],
  }),

  BRAND_TYPOSQUAT: (obs) => ({
    title: 'Likely Brand Typosquat',
    description: `"${obs.data.candidateLabel}" is only ${obs.data.editDistance} character(s) away from the brand name "${obs.data.matchedBrand}" (real domain: ${obs.data.legitimateBrandDomain}).`,
    recommendation: `Compare this domain character-by-character against ${obs.data.legitimateBrandDomain}.`,
    baseSeverity: obs.data.editDistance === 1 ? 'critical' : 'high',
    references: [],
  }),

  HIGH_ENTROPY: (obs) => ({
    title: obs.data.entropyBitsPerChar >= 4.0 ? 'High-Entropy Domain Label' : 'Elevated Domain Randomness',
    description: `The domain label "${obs.data.label}" has unusually high character randomness (entropy ≈ ${obs.data.entropyBitsPerChar} bits/char).`,
    recommendation: 'Not conclusive by itself — weigh it against the other findings.',
    baseSeverity: obs.data.entropyBitsPerChar >= 4.0 ? 'medium' : 'low',
    references: [],
  }),

  AT_USERINFO_TRICK: (obs) => ({
    title: '"@" Userinfo Redirect Trick',
    description: `The URL contains an "@" before the real host. Browsers treat everything before "@" ("${obs.data.userinfoText}") as login text, not the destination — the real destination is "${obs.data.actualHost}".`,
    recommendation: `Ignore the text before "@" entirely — the actual destination is "${obs.data.actualHost}".`,
    baseSeverity: 'critical',
    references: [],
  }),

  OPEN_REDIRECT_PARAM: (obs) => ({
    title: 'Open-Redirect Query Parameter',
    description: `The query parameter "${obs.data.paramName}" contains what looks like another URL ("${obs.data.paramValue}").`,
    recommendation: 'Check where this parameter actually leads — the visible hostname may not be where you end up.',
    baseSeverity: 'high',
    references: [],
  }),

  NON_STANDARD_PORT: (obs) => ({
    title: 'Non-Standard Port',
    description: `This URL explicitly specifies port ${obs.data.port} instead of the default for ${obs.data.protocol.replace(':', '')}.`,
    recommendation: 'Not malicious by itself, but raises overall risk combined with other findings.',
    baseSeverity: obs.data.isKnownCommonlyAbusedPort ? 'high' : 'medium',
    references: [],
  }),

  RISKY_FILE_EXTENSION: (obs) => ({
    title: 'Risky File Extension in URL',
    description: `This URL points directly at a ".${obs.data.extension}" file (risk tier: ${obs.data.extensionRiskTier}).`,
    recommendation: 'Do not download or open this file unless you fully trust the source.',
    baseSeverity: obs.data.extensionRiskTier,
    references: [],
  }),

  DANGEROUS_PROTOCOL: (obs) => ({
    title: `Dangerous "${obs.data.protocol}" Protocol`,
    description: `This is not a normal web link — it uses the "${obs.data.protocol}" scheme, which executes code or renders arbitrary content directly.`,
    recommendation: 'Never click or paste links using this scheme from an untrusted source.',
    baseSeverity: 'critical',
    references: [],
  }),
};

/**
 * Turns one Observation into human-readable finding text + a suggested
 * base severity. Pure function — no side effects, no access to other
 * observations (that's the Correlation Engine's job, see Part 10).
 *
 * @param {import('./observation.d.ts').Observation} observation
 * @returns {{ title: string, description: string, recommendation: string, baseSeverity: string } | null}
 */
export function describe(observation) {
  const fn = DESCRIPTORS[observation.observationId];
  if (!fn) {
    console.warn(`[describe] no descriptor registered for observationId "${observation.observationId}"`);
    return null;
  }
  return fn(observation);
}
