import { htmlPatterns } from './htmlPatterns.js';

/**
 * Labeled evaluation corpus.
 *
 * Each scenario pairs a URL with a ground-truth label ('benign' | 'phishing')
 * and the environment signals a real scan would observe:
 *   - whois:  { days, registrar }         domain age + registrar
 *   - vt:     { positives, total }        VirusTotal detections
 *   - dns:    { ipv4: [...] }             resolved addresses
 *   - html:   analyzer-shaped result      (findings + structured signals)
 *
 * The lexical layer is NOT mocked — buildDataset runs the real lexical engine
 * against each URL, so those observations are authentic. WHOIS/VT/DNS cannot be
 * queried offline, so they are recorded as realistic values captured from the
 * kinds of infrastructure each scenario represents.
 *
 * Labels are the analyst's ground truth (intent of the URL), independent of what
 * the engine predicts — that is what makes the evaluation meaningful.
 */

const benign = (id, url, days, registrar, ipv4, html = htmlPatterns.benignHome()) => ({
  id,
  url,
  label: 'benign',
  whois: { days, registrar },
  vt: { positives: 0, total: 90 },
  dns: { ipv4 },
  html,
});

const phish = (id, url, days, registrar, positives, ipv4, html) => ({
  id,
  url,
  label: 'phishing',
  whois: { days, registrar },
  vt: { positives, total: 90 },
  dns: { ipv4 },
  html,
});

export const scenarios = [
  // ── Benign ────────────────────────────────────────────────────────────────
  benign('benign-github', 'https://github.com', 6500, 'MarkMonitor', ['140.82.113.3']),
  benign('benign-wikipedia', 'https://en.wikipedia.org', 8000, 'MarkMonitor', ['208.80.154.224']),
  benign('benign-python', 'https://www.python.org', 7000, 'Namecheap', ['151.101.0.223']),
  benign('benign-mozilla', 'https://developer.mozilla.org', 6000, 'MarkMonitor', ['34.120.54.55']),
  benign('benign-cloudflare', 'https://www.cloudflare.com', 9000, 'Cloudflare, Inc.', ['104.16.132.229']),
  benign('benign-bbc', 'https://www.bbc.com', 9000, 'BBC', ['151.101.0.81']),
  benign('benign-stackoverflow', 'https://stackoverflow.com', 8000, 'Cloudflare, Inc.', ['151.101.1.69']),
  benign('benign-react', 'https://react.dev', 1500, 'Cloudflare, Inc.', ['76.76.21.21']),
  benign('benign-apple', 'https://www.apple.com', 9000, 'CSC Corporate Domains', ['17.253.144.10']),
  benign('benign-microsoft', 'https://www.microsoft.com', 9000, 'MarkMonitor', ['20.112.250.133']),
  // Young registrations on developer cloud hosts — expected to be mitigated.
  benign('benign-vercel', 'https://myportfolio.vercel.app', 5, 'Vercel Inc', ['76.76.21.21']),
  benign('benign-githubpages', 'https://someone.github.io', 5, 'MarkMonitor', ['185.199.108.153']),
  // A legitimate URL shortener link — keeps has_shortener from being a one-class fluke.
  benign('benign-shortener', 'https://bit.ly/spring-docs', 4000, 'Digital Ocean', ['104.20.1.1'], htmlPatterns.benignHome()),

  // ── Phishing ──────────────────────────────────────────────────────────────
  // Typosquat + credential harvesting
  phish('phish-paypa1', 'https://paypa1-login-verify.xyz', 3, 'Namecheap', 12, ['185.199.108.153'], htmlPatterns.phishCredential('paypal')),
  phish('phish-netflix-billing', 'https://netflix-billing-update.com', 2, 'Namecheap', 20, ['172.67.1.1'], htmlPatterns.phishCredential('netflix')),
  phish('phish-apple-id', 'https://secure-apple-id-login.com', 5, 'GoDaddy', 8, ['104.21.1.1'], htmlPatterns.phishCredential('apple')),
  phish('phish-microsoft365', 'https://secure-login-microsoft365.com', 1, 'Unknown', 18, ['104.21.3.3'], htmlPatterns.phishCredential('microsoft')),
  phish('phish-amazon-otp', 'https://amazon-order-otp.xyz', 2, 'Namecheap', 15, ['172.67.2.2'], htmlPatterns.phishCredential('amazon')),
  phish('phish-chase-alert', 'https://chase-bank-alert.com', 7, 'Privacy Private', 6, ['104.21.4.4'], htmlPatterns.phishCredential('chase')),
  phish('phish-binance-connect', 'https://binance-wallet-connect.app', 5, 'Namecheap', 9, ['172.67.5.5'], htmlPatterns.phishCredential('binance')),
  phish('phish-google-security', 'https://account-google-security.tk', 6, 'Privacy Private', 3, ['185.220.101.4'], htmlPatterns.phishCredential('google')),
  phish('phish-free-netflix', 'https://free-netflix-account.xyz', 3, 'Namecheap', 10, ['172.67.3.3'], htmlPatterns.phishCredential('netflix')),

  // Homograph / punycode
  phish('phish-homograph', 'https://mïcrosoft-verify.com', 4, 'Hostinger', 5, ['91.240.118.12'], htmlPatterns.phishCredential('microsoft')),

  // Dynamic-DNS abuse
  phish('phish-duckdns', 'https://paypal-verify.duckdns.org', 1, 'DuckDNS', 0, ['8.8.8.8'], htmlPatterns.phishCredential('paypal')),

  // IP-address host
  phish('phish-ip-host', 'http://185.220.101.4/login', 10, 'Hostinger', 30, ['185.220.101.4'], htmlPatterns.phishCredential('microsoft')),

  // Obfuscation / cloaking, no VT hits, fresh domain
  phish('phish-cloaked', 'https://update-my-security-settings.xyz', 4, 'Hostinger', 0, ['91.240.118.12'], htmlPatterns.phishObfuscated()),

  // Hard cases: brand + new domain with a benign-looking page (no HTML signals)
  phish('phish-brand-only', 'https://apple-support-login.com', 2, 'Namecheap', 0, ['104.21.6.6'], htmlPatterns.benignHome()),

  // Hard case: URL shortener hiding the destination (needs expansion, future work)
  phish('phish-shortener', 'https://bit.ly/3xYzAbc', 4000, 'Digital Ocean', 0, ['104.20.1.1'], htmlPatterns.benignHome()),
];

export const datasetStats = () => {
  const positives = scenarios.filter((s) => s.label === 'phishing').length;
  const negatives = scenarios.filter((s) => s.label === 'benign').length;
  return { total: scenarios.length, positives, negatives };
};