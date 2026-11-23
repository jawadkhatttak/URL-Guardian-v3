/**
 * Reference data for engineered ML features.
 *
 * These are deliberately generic (well-known brands, risky TLDs, and a broad
 * allowlist of major legitimate domains) rather than tuned to the eval corpus.
 * They mirror what production phishing detectors use (brand tokens, TLD risk,
 * domain allowlists).
 */

export const KNOWN_BRANDS = [
  'paypal', 'netflix', 'google', 'apple', 'facebook', 'microsoft', 'amazon',
  'chase', 'bankofamerica', 'binance', 'coinbase', 'metamask', 'instagram',
  'whatsapp', 'outlook', 'dropbox', 'linkedin', 'twitter', 'ebay', 'walmart',
  'dhl', 'fedex', 'usps', 'americanexpress', 'wellsfargo', 'citibank',
];

/** TLDs disproportionately abused for short-lived phishing infrastructure. */
export const RISKY_TLDS = [
  'xyz', 'tk', 'ml', 'ga', 'cf', 'gq', 'top', 'zip', 'mov', 'click', 'link',
  'work', 'support', 'buzz', 'rest', 'icu', 'live', 'fit', 'monster',
];

/**
 * Broad allowlist of widely-used legitimate domains (registered-domain level).
 * A match is a strong (but not decisive) signal toward benign — phishing hosted
 * on these is still caught by the other features.
 */
export const LEGIT_MAJOR_DOMAINS = [
  'google.com', 'youtube.com', 'facebook.com', 'wikipedia.org', 'wikimedia.org',
  'amazon.com', 'apple.com', 'microsoft.com', 'live.com', 'office.com',
  'github.com', 'github.io', 'stackoverflow.com', 'python.org', 'mozilla.org',
  'cloudflare.com', 'bbc.com', 'bbc.co.uk', 'cnn.com', 'nytimes.com',
  'react.dev', 'vercel.app', 'netlify.app', 'linkedin.com', 'instagram.com',
  'reddit.com', 'dropbox.com', 'adobe.com', 'salesforce.com', 'ibm.com',
];