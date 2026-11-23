import { isDynamicDnsHosted } from './backend-integration/data/dynamicDnsProviders.js';

/**
 * Numeric confidence (0-1, from the lexical engine's Observation contract)
 * bucketed into the word-scale your other correlations already use, so
 * everything coming out of this file is consistent.
 */
function confidenceToWord(numericConfidence) {
  if (numericConfidence >= 0.85) return 'HIGH';
  if (numericConfidence >= 0.6) return 'MEDIUM';
  return 'LOW';
}

/**
 * Cross-Service Intelligence: Correlates independent service findings into
 * unified threat profiles.
 *
 * @param {Object} masterFindings - dns / whois / html / virustotal /
 *   urlLexical, as your orchestrator already assembles them. urlLexical is
 *   the NEW addition — see services/urlLexical.service.js.
 * @param {string} targetUrl
 * @returns {Array<Object>}
 */
export function processCorrelations(masterFindings, targetUrl) {
  const correlatedFindings = [];
  const urlObj = new URL(targetUrl.toLowerCase());
  const domain = urlObj.hostname;

  const { dns = {}, whois = {}, html = {}, virustotal = {}, urlLexical = {} } = masterFindings;
  const htmlFindings = html.findings || [];
  const lexicalObservations = urlLexical.observations || [];

  const findLexical = (observationId) => lexicalObservations.find((o) => o.observationId === observationId);

  // ----------------------------------------------------
  // HTML feature extraction — unchanged from your original
  // ----------------------------------------------------
  const hasPassword = htmlFindings.some((f) => /password|Credential Harvest/i.test(f));
  const hasIsolatedForm = htmlFindings.some((f) => /isolated form|one isolated form/i.test(f));
  const hasExternalForm = htmlFindings.some((f) => /external form action|submits to external/i.test(f));
  const hasObfuscation = htmlFindings.some((f) => /obfuscated|eval\(|unescape|zero-width/i.test(f));
  const hasInvisibleElements = htmlFindings.some((f) => /invisible element|hidden input overlay|opacity/i.test(f));
  const hasMetaRefresh = htmlFindings.some((f) => /meta refresh|redirect behavior/i.test(f));
  const hasJsRedirect = htmlFindings.some((f) => /javascript redirect|window\.location/i.test(f));
  const hasBrandSpoofSignal = htmlFindings.some((f) => /brand mention|impersonation keywords/i.test(f));

  // ----------------------------------------------------
  // Network & registration signals
  // ----------------------------------------------------
  const isVtMalicious = virustotal.threatFound === true || virustotal.positives >= 2;

  // *** THE FIX ***
  // whois.daysSinceRegistration only describes the entity WHOIS actually
  // has a record for. When the registered domain sits on a known
  // dynamic-DNS/free-subdomain provider (dynv6.net, duckdns.org, etc.),
  // that record describes the PROVIDER's infrastructure, not the
  // attacker-controlled subdomain — there is no public WHOIS record for
  // when "netflix-suporte" was created under dynv6.net, because that
  // registration never went through ICANN. Verified against your real
  // sample: netflix-suporte.dynv6.net read as "4281 days old" purely
  // because dynv6.net (Hetzner's infrastructure) is 11.7 years old.

  const registeredDomain = urlLexical.urlMetadata?.registeredDomain || domain;
  const isOnDynamicDns = isDynamicDnsHosted(registeredDomain);
  // Must be a real number: `null < 30` is true in JS, which would treat
  // "WHOIS returned no creation date" as "registered today".
  const rawIsFresh = typeof whois.daysSinceRegistration === 'number'
    && whois.daysSinceRegistration >= 0
    && whois.daysSinceRegistration < 30;
  // Domain-age freshness is only a meaningful signal when WHOIS actually
  // describes the entity in question.
  const isFreshDomain = !isOnDynamicDns && rawIsFresh;

  const isSuspiciousRegistrar = whois.registerName && /free|privacy|protected|unknown/i.test(whois.registerName);

  // ==========================================
  // RULE 0 (NEW): Dynamic-DNS / Free-Subdomain Hosting
  // ==========================================
  // This is its own positive signal, independent of WHOIS age, precisely
  // BECAUSE hosting on these providers is a well-known way to defeat
  // WHOIS-age-based detection. Absence of a fresh-domain signal on one of
  // these hosts is not reassuring — it's expected, and worth flagging on
  // its own.
  if (isOnDynamicDns) {
    correlatedFindings.push({
      id: 'CORR_DYNAMIC_DNS_HOSTING',
      title: 'Hosted on Dynamic-DNS / Free-Subdomain Provider',
      severity: 'MEDIUM',
      confidence: 'HIGH',
      evidence: [
        `The registered domain ("${registeredDomain}") is a subdomain under a known dynamic-DNS or free-subdomain hosting provider.`,
        `WHOIS registration-age data reflects the PROVIDER's infrastructure (registered ${whois.daysSinceRegistration ?? 'unknown'} days ago), not this specific subdomain — there is no public record of when this subdomain was actually created.`,
      ],
    });
  }

  // ==========================================
  // RULE 1: Complex Credential Harvesting Detection — unchanged
  // ==========================================
  if (hasPassword && (hasIsolatedForm || hasExternalForm)) {
    correlatedFindings.push({
      id: 'CORR_CREDENTIAL_HARVESTING',
      title: 'Suspicious Credential Capture Point',
      severity: 'HIGH',
      confidence: hasExternalForm ? 'HIGH' : 'MEDIUM',
      evidence: [
        'Page structure isolates user authentication inputs.',
        hasExternalForm
          ? 'Form data points directly to a third-party non-matching domain handler.'
          : 'Isolated structural elements mimic login behavior layout.',
      ],
    });
  }

  // ==========================================
  // RULE 2: Brand Impersonation — now also fed by the lexical engine's
  // BRAND_IMPERSONATION / BRAND_TYPOSQUAT observations, not just a raw
  // substring check against targetUrl
  // ==========================================
  const lexicalBrandImpersonation = findLexical('BRAND_IMPERSONATION');
  const lexicalBrandTyposquat = findLexical('BRAND_TYPOSQUAT');
  const lexicalBrandMatch = lexicalBrandImpersonation?.data.matchedBrand || lexicalBrandTyposquat?.data.matchedBrand;

  const knownBrands = ['netflix', 'paypal', 'google', 'facebook', 'microsoft', 'apple', 'amazon', 'binance', 'chase', 'bankofamerica'];
  const substringBrandMatch = knownBrands.find((brand) => targetUrl.toLowerCase().includes(brand));
  const matchedUrlBrand = lexicalBrandMatch || substringBrandMatch;

  if (matchedUrlBrand || hasBrandSpoofSignal) {
    const brandName = matchedUrlBrand || 'Targeted Identity';
    const officialRegistrarRegex = new RegExp(brandName, 'i');
    const officialBrandDomains = {
      netflix: 'netflix.com',
      paypal: 'paypal.com',
      google: 'google.com',
      facebook: 'facebook.com',
      microsoft: 'microsoft.com',
      apple: 'apple.com',
      amazon: 'amazon.com',
      binance: 'binance.com',
      chase: 'chase.com',
      bankofamerica: 'bankofamerica.com',
    };


    const normalizeHost = (host) => (host || '').toLowerCase().replace(/^www\./, '');
    const expectedBrandDomain = officialBrandDomains[brandName];
    const isOfficialBrandDomain = expectedBrandDomain && normalizeHost(registeredDomain) === expectedBrandDomain;
    if (!isOfficialBrandDomain) {
      correlatedFindings.push({
        id: 'CORR_BRAND_IMPERSONATION',
        title: `Deceptive Brand Impersonation (${brandName.toUpperCase()})`,
        severity: 'CRITICAL',
        confidence: matchedUrlBrand ? 'HIGH' : 'MEDIUM',
        evidence: [
          lexicalBrandImpersonation
            ? `Lexical analysis confirms "${lexicalBrandImpersonation.data.matchedBrand}" appears directly in the hostname, which does not match its legitimate domain (${lexicalBrandImpersonation.data.legitimateBrandDomain}).`
            : lexicalBrandTyposquat
              ? `Lexical analysis found the registered domain is ${lexicalBrandTyposquat.data.editDistance} character(s) from "${lexicalBrandTyposquat.data.matchedBrand}" — a likely typosquat.`
              : 'Visual or textual context implies identity representation of brand asset groups.',
          `Outbound domain parameters point back to independent host framework: '${whois.registerName || 'Unknown Registrar'}'.`,
        ],
      });
    }
  }

  // ==========================================
  // RULE 3: Active Malicious Campaign — fixed to use the corrected
  // isFreshDomain, and to treat dynamic-DNS + VT-malicious as an
  // alternate strong path (since fresh-domain data isn't available at all
  // on these hosts, but that doesn't make an active VT-flagged campaign
  // on dynamic DNS any less real)
  // ==========================================
  if ((isFreshDomain && isVtMalicious) || (isOnDynamicDns && isVtMalicious)) {
    correlatedFindings.push({
      id: 'CORR_ACTIVE_MALICIOUS_CAMPAIGN',
      title: 'Active Malicious Campaign Infrastructure',
      severity: 'CRITICAL',
      confidence: 'CRITICAL',
      evidence: [
        isFreshDomain
          ? `Operational infrastructure was established under 30 days ago (${whois.daysSinceRegistration} days).`
          : `Hosted on dynamic-DNS infrastructure, where true subdomain creation date is not publicly visible via WHOIS.`,
        `Global threat engines confirmed positive blacklistings matching this direct endpoint routing (${virustotal.positives}/${virustotal.totalScanners}).`,
      ],
    });
  }

  // ==========================================
  // RULE 4: High-Risk Phishing Candidate — same dynamic-DNS-aware fix
  // ==========================================
  if (hasPassword && (isFreshDomain || isOnDynamicDns) && (hasExternalForm || isSuspiciousRegistrar || isOnDynamicDns)) {
    correlatedFindings.push({
      id: 'CORR_HIGH_RISK_PHISHING_CANDIDATE',
      title: 'High-Risk Zero-Day Phishing Target',
      severity: 'CRITICAL',
      confidence: 'HIGH',
      evidence: [
        'Login credential targets identified on infrastructure with no verifiable, trustworthy registration history.',
        'Ancillary signals verify external data extraction paths, hidden placeholder registrars, or dynamic-DNS hosting.',
      ],
    });
  }

  // ==========================================
  // RULE 5: Evasive Obfuscation & Cloaking — unchanged
  // ==========================================
  if (hasObfuscation && (hasInvisibleElements || isVtMalicious)) {
    correlatedFindings.push({
      id: 'CORR_EVASIVE_MALWARE_CLOAKING',
      title: 'Evasive Script Obfuscation & Cloaking',
      severity: 'HIGH',
      confidence: 'HIGH',
      evidence: [
        'Source code contains compressed text strings designed to bypass defensive security scanners.',
        hasInvisibleElements
          ? 'Detected invisible structural layouts stacked over clickable viewport components.'
          : 'Global security vendors flag this endpoint as hosting malicious artifacts.',
      ],
    });
  }

  // ==========================================
  // RULE 6: Multi-Stage Redirection — unchanged
  // ==========================================
  if (hasMetaRefresh && hasJsRedirect) {
    correlatedFindings.push({
      id: 'CORR_AGGRESSIVE_REDIRECT_LOOP',
      title: 'Aggressive Multi-Stage Browser Redirection',
      severity: 'MEDIUM',
      confidence: 'HIGH',
      evidence: [
        'Concurrent client-side execution vectors triggered immediately to force alternate host navigation.',
        'Typical indicator used by threat campaigns to strip referrer paths and drop users onto final exploits.',
      ],
    });
  }

  // ==========================================
  // RULE 7 (NEW): Lexical Homograph/Encoding Attack + Brand Targeting
  // ==========================================
  const homographObs = findLexical('HOMOGRAPH');
  if (homographObs && matchedUrlBrand) {
    correlatedFindings.push({
      id: 'CORR_HOMOGRAPH_BRAND_TARGETING',
      title: 'Character-Spoofing Attack Targeting a Known Brand',
      severity: 'CRITICAL',
      confidence: confidenceToWord(homographObs.confidence),
      evidence: [
        `Hostname uses characters designed to visually impersonate "${matchedUrlBrand}".`,
        `Confusable/mixed-script characters detected: ${(homographObs.data.confusableCharacters || []).map((c) => c.char).join(', ') || homographObs.data.scriptsPresent?.join(', ')}.`,
      ],
    });
  }

  // ==========================================
  // RULE 8 (NEW): Lexical redirect trick + HTML external form
  // ==========================================
  const atTrickObs = findLexical('AT_USERINFO_TRICK');
  if (atTrickObs && hasExternalForm) {
    correlatedFindings.push({
      id: 'CORR_URL_TRICK_WITH_EXTERNAL_HARVEST',
      title: 'URL Obfuscation Combined With External Credential Submission',
      severity: 'CRITICAL',
      confidence: 'HIGH',
      evidence: [
        `URL uses the "@" userinfo trick to display "${atTrickObs.data.userinfoText}" while actually navigating to "${atTrickObs.data.actualHost}".`,
        'Page additionally submits form data to a third-party, non-matching domain.',
      ],
    });
  }

  return correlatedFindings;
}
