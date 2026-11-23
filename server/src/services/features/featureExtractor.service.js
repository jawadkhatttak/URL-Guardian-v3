import {
  CORRELATION_WEIGHTS,
  LEXICAL_BASE_WEIGHTS,
  RUNTIME_SEVERITY_MULTIPLIERS,
  SEVERITY_MULTIPLIER,
  CONFIDENCE_MULTIPLIER,
  round1,
} from './featureWeights.js';
import { KNOWN_BRANDS, RISKY_TLDS, LEGIT_MAJOR_DOMAINS } from './brandData.js';

/**
 * Unified Feature Extractor
 * -------------------------
 * Single source of truth that turns the raw output of every intelligence layer
 * (DNS / WHOIS / HTML / VirusTotal / lexical) plus the cross-service
 * correlations into ONE flat list of feature objects.
 *
 * Each feature is shaped identically so the risk engine can score, mitigate and
 * explain them with a single code path instead of re-implementing scoring per
 * source:
 *
 *   {
 *     id,          // stable identifier, e.g. 'WHOIS_NEW_REGISTRATION'
 *     source,      // 'correlation' | 'whois' | 'virustotal' | 'lexical' | 'html'
 *     title,       // human-readable summary
 *     description, // longer explanation (optional)
 *     evidence,    // string[] supporting evidence (optional)
 *     severity,    // 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW'
 *     confidence,  // 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | number
 *     weight       // numeric contribution to the 0–100 score (pre-mitigation)
 *   }
 *
 * The weight for each source is derived with the formulas that previously lived
 * inside the risk engine, so behaviour is preserved while the structure is now
 * uniform and consumable by the ML/dataset work.
 */

const SEVERITY_NORMALISE = { critical: 'CRITICAL', high: 'HIGH', medium: 'MEDIUM', low: 'LOW' };

function normaliseSeverity(value) {
  if (!value) return 'MEDIUM';
  return SEVERITY_NORMALISE[String(value).toLowerCase()] ?? 'MEDIUM';
}

function correlationFeatures(correlatedFindings) {
  return correlatedFindings.map((cf) => {
    const base = CORRELATION_WEIGHTS[cf.id] ?? CORRELATION_WEIGHTS.DEFAULT;
    const sevMult = SEVERITY_MULTIPLIER[cf.severity] ?? 1.0;
    const confMult = CONFIDENCE_MULTIPLIER[cf.confidence] ?? 1.0;
    return {
      source: 'correlation',
      id: cf.id,
      title: cf.title,
      severity: normaliseSeverity(cf.severity),
      confidence: cf.confidence ?? 'MEDIUM',
      evidence: Array.isArray(cf.evidence) ? cf.evidence : [],
      weight: round1(base * sevMult * confMult),
    };
  });
}

function whoisFeatures(masterFindings) {
  const { whois = {} } = masterFindings;
  const features = [];

  if (whois && typeof whois.daysSinceRegistration === 'number') {
    const age = whois.daysSinceRegistration;
    if (age <= 30 && age >= 0) {
      features.push({
        source: 'whois',
        id: 'WHOIS_NEW_REGISTRATION',
        title: `Newly Registered Domain (Age: ${age} days)`,
        severity: 'HIGH',
        confidence: 'HIGH',
        evidence: [`Domain was registered ${age} day(s) ago.`],
        weight: 25,
      });
    } else if (age <= 90 && age > 30) {
      features.push({
        source: 'whois',
        id: 'WHOIS_RECENT_REGISTRATION',
        title: `Recently Registered Domain (Age: ${age} days)`,
        severity: 'MEDIUM',
        confidence: 'MEDIUM',
        evidence: [`Domain was registered ${age} day(s) ago.`],
        weight: 12,
      });
    }
  }

  return features;
}

function virusTotalFeatures(masterFindings) {
  const { virustotal = {} } = masterFindings;
  if (virustotal.success && virustotal.totalScanners > 0) {
    const ratio = virustotal.positives / virustotal.totalScanners;
    if (ratio > 0) {
      return [{
        source: 'virustotal',
        id: 'VT_POSITIVE_RATIO',
        title: `${virustotal.positives}/${virustotal.totalScanners} security vendors flagged this domain`,
        severity: ratio >= 0.5 ? 'CRITICAL' : ratio >= 0.2 ? 'HIGH' : 'MEDIUM',
        confidence: 'HIGH',
        evidence: [`${virustotal.positives} of ${virustotal.totalScanners} engines returned a positive verdict.`],
        weight: round1(Math.min(40, ratio * 100)),
      }];
    }
  }
  return [];
}

function lexicalFeatures(masterFindings) {
  const { urlLexical = {}, lexical = {} } = masterFindings;
  const lexicalPayload = urlLexical?.fullFindings ? urlLexical : (lexical?.fullFindings ? lexical : null);
  const features = [];

  if (lexicalPayload && Array.isArray(lexicalPayload.fullFindings)) {
    for (const finding of lexicalPayload.fullFindings) {
      if (finding.suppressed) continue;

      const obsId = finding.observationId;
      const baseWeight = LEXICAL_BASE_WEIGHTS[obsId];
      if (baseWeight === undefined) continue;

      const runtimeSeverity = finding.suggestedSeverity || finding.baseSeverity || 'medium';
      const severityMultiplier = RUNTIME_SEVERITY_MULTIPLIERS[runtimeSeverity.toLowerCase()] ?? 1.0;
      const confidence = finding.confidence ?? 1.0;

      features.push({
        source: 'lexical',
        id: obsId,
        title: finding.title || finding.description,
        description: finding.description,
        severity: normaliseSeverity(runtimeSeverity),
        confidence,
        evidence: Array.isArray(finding.references) ? finding.references : [],
        weight: round1(baseWeight * severityMultiplier * confidence),
      });
    }
  }

  return features;
}

/**
 * HTML signals come from the structured `signals` array emitted by the HTML
 * analyzer. Each signal already carries the points it contributes, so HTML is
 * scored without re-deriving anything here. When the analyzer output predates
 * structured signals (e.g. older stored scans or lightweight mock data), no
 * HTML feature is produced — which keeps behaviour stable for such inputs.
 */
function htmlFeatures(masterFindings) {
  const { html = {} } = masterFindings;
  const signals = Array.isArray(html.signals) ? html.signals : [];

  return signals
    .filter((signal) => signal && Number(signal.weight) > 0)
    .map((signal, index) => ({
      source: 'html',
      id: signal.id || `HTML_SIGNAL_${index}`,
      title: signal.message || signal.title || 'HTML structural signal',
      severity: normaliseSeverity(signal.severity),
      confidence: 'HIGH',
      evidence: [],
      weight: round1(Number(signal.weight)),
    }));
}

/**
 * Extract the unified feature list from a completed analysis.
 * @param {object} masterFindings - dns / whois / html / virustotal / urlLexical (or lexical)
 * @param {Array<object>} correlatedFindings - output of processCorrelations()
 * @returns {{ features: Array<object> }}
 */
export function extractFeatures(masterFindings, correlatedFindings = []) {
  const features = [
    ...correlationFeatures(correlatedFindings),
    ...whoisFeatures(masterFindings),
    ...virusTotalFeatures(masterFindings),
    ...lexicalFeatures(masterFindings),
    ...htmlFeatures(masterFindings),
  ];

  return { features };
}

/**
 * Build a fixed-schema numeric feature vector — the row format the dataset /
 * ML work (#3, #4) will train on. Every key is always present so vectors are
 * comparable across samples. `targetUrl` unlocks a few host-level engineered
 * features (brand-in-host, allowlist, risky TLD, scheme).
 */
export function buildFeatureVector(masterFindings, correlatedFindings = [], targetUrl = '') {
  const { whois = {}, html = {}, virustotal = {}, urlLexical = {}, lexical = {} } = masterFindings;
  const lexicalPayload = urlLexical?.fullFindings ? urlLexical : (lexical?.fullFindings ? lexical : null);

  const observations = (lexicalPayload?.fullFindings || []).filter((f) => !f.suppressed);
  const obsIds = new Set(observations.map((o) => o.observationId));

  const htmlSignals = Array.isArray(html.signals) ? html.signals : [];
  const htmlIds = new Set(htmlSignals.map((s) => s.id));

  const age = typeof whois.daysSinceRegistration === 'number' ? whois.daysSinceRegistration : -1;
  const vtTotal = typeof virustotal.totalScanners === 'number' ? virustotal.totalScanners : 0;
  const vtPositives = typeof virustotal.positives === 'number' ? virustotal.positives : 0;

  const hasWhois = Boolean(
    whois && !whois.error && (whois.creationDate || whois.registerName || typeof whois.daysSinceRegistration === 'number')
  );

  // Host-level engineered features.
  const metadata = lexicalPayload?.urlMetadata || {};
  const hostname = metadata.hostname || (targetUrl ? new URL(targetUrl).hostname : '');
  const registeredDomain = metadata.registeredDomain || hostname;
  const tld = (metadata.tld || (hostname ? hostname.split('.').pop() : '')).toLowerCase();

  return {
    // Registration
    domain_age_days: age,
    has_whois: hasWhois ? 1 : 0,
    domain_age_is_new: age >= 0 && age <= 30 ? 1 : 0,

    // VirusTotal
    vt_total_scanners: vtTotal,
    vt_positives: vtPositives,
    vt_positive_ratio: vtTotal > 0 ? Math.round((vtPositives / vtTotal) * 10000) / 10000 : 0,

    // Lexical
    lexical_finding_count: observations.length,
    has_brand_impersonation: obsIds.has('BRAND_IMPERSONATION') ? 1 : 0,
    has_typosquat: obsIds.has('BRAND_TYPOSQUAT') ? 1 : 0,
    has_homograph: obsIds.has('HOMOGRAPH') ? 1 : 0,
    has_punycode: obsIds.has('PUNYCODE') ? 1 : 0,
    has_ip_host: obsIds.has('IP_ADDRESS_HOST') ? 1 : 0,
    has_shortener: obsIds.has('URL_SHORTENER') ? 1 : 0,
    has_suspicious_keyword: obsIds.has('SUSPICIOUS_KEYWORDS') ? 1 : 0,
    has_at_userinfo: obsIds.has('AT_USERINFO_TRICK') ? 1 : 0,
    has_dangerous_protocol: obsIds.has('DANGEROUS_PROTOCOL') ? 1 : 0,

    // URL shape
    url_length: typeof metadata.urlLength === 'number' ? metadata.urlLength : 0,
    brand_in_host: KNOWN_BRANDS.some((brand) => hostname.includes(brand)) ? 1 : 0,
    is_legit_major_domain: LEGIT_MAJOR_DOMAINS.includes(registeredDomain) ? 1 : 0,
    has_https: targetUrl.toLowerCase().startsWith('https') ? 1 : 0,
    tld_risk: RISKY_TLDS.includes(tld) ? 1 : 0,

    // HTML
    html_risk_score: typeof html.riskScore === 'number' ? html.riskScore : 0,
    html_signal_count: htmlSignals.length,
    html_has_password_field: htmlIds.has('HTML_PASSWORD_FIELD') ? 1 : 0,
    html_has_external_form: htmlIds.has('HTML_EXTERNAL_FORM') ? 1 : 0,
    html_has_brand_mismatch: htmlIds.has('HTML_BRAND_MISMATCH') ? 1 : 0,
    html_has_obfuscation: htmlIds.has('HTML_OBFUSCATION') || htmlIds.has('HTML_SUSPICIOUS_EVAL') ? 1 : 0,

    // Correlations
    correlation_count: correlatedFindings.length,
    has_dynamic_dns: correlatedFindings.some((c) => c.id === 'CORR_DYNAMIC_DNS_HOSTING') ? 1 : 0,
  };
}

/** Convenience: features + feature vector in one call. */
export function extractAll(masterFindings, correlatedFindings = [], targetUrl) {
  const { features } = extractFeatures(masterFindings, correlatedFindings);
  return {
    features,
    featureVector: buildFeatureVector(masterFindings, correlatedFindings, targetUrl),
  };
}