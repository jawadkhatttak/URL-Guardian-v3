/**
 * HTML signal patterns for the evaluation corpus.
 *
 * Each pattern returns an object in exactly the shape the HTML analyzer emits
 * (`findings` strings + structured `signals`), with messages copied verbatim
 * from htmlAnalyzer.service.js. That keeps the correlation layer's string-based
 * regexes behaving exactly as they do on live scans, while letting the dataset
 * stay compact and offline (no scraping needed).
 */

const signal = (id, weight, severity, message) => ({ id, weight, severity, message });

const SINGLE_FORM = signal(
  'HTML_SINGLE_FORM',
  15,
  'low',
  'Suspicious structural layout: Page contains exactly one isolated form component.'
);

const PASSWORD_FIELD = signal(
  'HTML_PASSWORD_FIELD',
  25,
  'high',
  'Credential Harvest Signal: Target form contains active password fields.'
);

const EXTERNAL_FORM = signal(
  'HTML_EXTERNAL_FORM',
  40,
  'high',
  'Deceptive Form: Form targets data transmission to an external network domain.'
);

const SOCIAL_ENGINEERING = signal(
  'HTML_SOCIAL_ENGINEERING',
  25,
  'medium',
  'Social Engineering Warning: High presence of urgency/panic-inducing text phrases (3 patterns found).'
);

const HEX_OBFUSCATION = signal(
  'HTML_HEX_OBFUSCATION',
  30,
  'high',
  'High Density Script Obfuscation: Detected 80 lexical hex strings indicating runtime code packing.'
);

const SUSPICIOUS_EVAL = signal(
  'HTML_SUSPICIOUS_EVAL',
  35,
  'critical',
  'Malicious JavaScript Heuristic: Deceptive eval syntax unescaping routine detected.'
);

const META_REFRESH = signal(
  'HTML_META_REFRESH',
  30,
  'medium',
  'Stealth Redirection Element: Client-side meta-refresh routing element deployed.'
);

const brandMismatch = (brand) =>
  signal(
    'HTML_BRAND_MISMATCH',
    40,
    'critical',
    `Critical Brand Mismatch: Brand token identity [${brand.toUpperCase()}] is referenced, but host platform domain is unrelated.`
  );

/**
 * Assemble an HTML result from a list of signal definitions. riskScore is the
 * sum of signal weights, capped at 100, matching the analyzer's accumulation.
 */
function makeHtml(signals) {
  const riskScore = Math.min(
    100,
    signals.reduce((sum, s) => sum + s.weight, 0)
  );
  return {
    success: true,
    threatFound: riskScore >= 60,
    riskScore,
    findings: signals.map((s) => s.message),
    signals: signals.map((s) => ({ id: s.id, weight: s.weight, severity: s.severity, message: s.message })),
  };
}

export const htmlPatterns = {
  /** A plain informational page with no forms or suspicious assets. */
  benignHome: () => makeHtml([]),

  /** A legitimate login page: one same-origin form with a password field. */
  benignLogin: () => makeHtml([SINGLE_FORM, PASSWORD_FIELD]),

  /** A credential-harvesting page impersonating a brand. */
  phishCredential: (brand) =>
    makeHtml([SINGLE_FORM, PASSWORD_FIELD, EXTERNAL_FORM, brandMismatch(brand), SOCIAL_ENGINEERING]),

  /** A cloaked page that hides its intent behind obfuscation and redirects. */
  phishObfuscated: () => makeHtml([HEX_OBFUSCATION, SUSPICIOUS_EVAL, META_REFRESH]),

  /** A branded page with an external form but no obfuscation. */
  phishBrandForm: (brand) => makeHtml([PASSWORD_FIELD, EXTERNAL_FORM, brandMismatch(brand)]),
};