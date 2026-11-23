/**
 * Central scoring weights for the unified feature pipeline.
 *
 * Every signal — no matter which intelligence layer produced it — is reduced to
 * a feature object carrying a numeric `weight` (its contribution to the 0–100
 * risk score). These tables define how each source's weight is derived. Keeping
 * them in one module is what makes the pipeline "unified": the risk engine no
 * longer re-implements scoring per source.
 */

/** Correlation (cross-service) base weights, keyed by correlation id. */
export const CORRELATION_WEIGHTS = {
  CORR_ACTIVE_MALICIOUS_CAMPAIGN: 45,
  CORR_HIGH_RISK_PHISHING_CANDIDATE: 40,
  CORR_EVASIVE_PHISHING_INFRASTRUCTURE: 45,
  CORR_TARGETED_SOCIAL_ENGINEERING: 30,
  CORR_BRAND_IMPERSONATION: 35,
  CORR_HOMOGRAPH_BRAND_TARGETING: 35,
  CORR_URL_TRICK_WITH_EXTERNAL_HARVEST: 35,
  CORR_CREDENTIAL_HARVESTING: 25,
  CORR_EVASIVE_MALWARE_CLOAKING: 25,
  CORR_DYNAMIC_DNS_HOSTING: 12,
  CORR_AGGRESSIVE_REDIRECT_LOOP: 15,
  DEFAULT: 15,
};

/** Base logical threat weights for lexical observation ids. */
export const LEXICAL_BASE_WEIGHTS = {
  // Critical / High targets
  BRAND_IMPERSONATION: 30,
  BRAND_TYPOSQUAT: 30,
  HOMOGRAPH: 30,
  AT_USERINFO_TRICK: 30,
  DANGEROUS_PROTOCOL: 30,
  IP_ADDRESS_HOST: 25,
  PUNYCODE: 20,
  SUBDOMAIN_LABEL_MIMICRY: 20,
  OPEN_REDIRECT_PARAM: 20,

  // Medium / general deceptions
  SUSPICIOUS_KEYWORDS: 15,
  UNICODE_HOSTNAME: 15,
  URL_SHORTENER: 15,
  NON_STANDARD_PORT: 15,
  RISKY_FILE_EXTENSION: 15,
  INSECURE_PROTOCOL: 10,

  // Low / supporting evidence
  SUBDOMAIN_DEPTH: 8,
  LONG_URL: 8,
  HIGH_ENTROPY: 8,
};

/** Runtime severity multipliers emitted by the lexical describe() layer. */
export const RUNTIME_SEVERITY_MULTIPLIERS = {
  critical: 1.4, // e.g. extremely long URL or a 1-distance typosquat gets boosted
  high: 1.1,
  medium: 0.8,
  low: 0.5, // e.g. shorter long URLs or low entropy get scaled down
};

/** Correlation severity / confidence multipliers. */
export const SEVERITY_MULTIPLIER = { CRITICAL: 1.3, HIGH: 1.1, MEDIUM: 0.9, LOW: 0.6 };
export const CONFIDENCE_MULTIPLIER = { CRITICAL: 1.2, HIGH: 1.0, MEDIUM: 0.8, LOW: 0.5 };

/** Hosting platforms where some signals are expected and should be softened. */
export const DEVELOPER_PLATFORMS = [
  'github.io', 'vercel.app', 'netlify.app', 'pages.dev', 'workers.dev',
  'firebaseapp.com', 'web.app', 'blogspot.com', 'githubusercontent.com',
];

/** Round to one decimal place, matching the engine's historical precision. */
export const round1 = (value) => Math.round(value * 10) / 10;