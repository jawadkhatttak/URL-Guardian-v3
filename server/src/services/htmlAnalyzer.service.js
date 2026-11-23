import * as cheerio from 'cheerio';

/**
 * Rules Engine Layer: Deep structural and lexical inspection of raw HTML contents.
 *
 * In addition to the human-readable `findings` strings and the accumulated
 * `riskScore` (both consumed by the UI), each rule now emits a structured
 * `signals` entry: { id, severity, weight, message }. The unified feature
 * pipeline (services/features) consumes `signals` so HTML indicators actually
 * contribute to the overall risk score instead of being display-only.
 *
 * @param {string} html - Raw HTML input string.
 * @param {string} targetUrl - The original URL under analysis for cross-domain validation.
 * @returns {Object} Threat evaluation profile.
 */
export function analyzeHtmlContent(html, targetUrl) {
  const $ = cheerio.load(html);

  const report = {
    success: true,
    threatFound: false,
    riskScore: 0, // Accumulator scale: 0 to 100
    findings: [],
    signals: [], // Structured signals consumed by the feature pipeline
  };

  // Single mutation point so findings/riskScore/signals never drift apart.
  const addFinding = (points, id, severity, message) => {
    report.riskScore += points;
    report.findings.push(message);
    report.signals.push({ id, severity, weight: points, message });
  };

  try {
    const parsedUrl = new URL(targetUrl);
    const baseHostname = parsedUrl.hostname;

    // --- GLOBAL SCAN PARAMETERS ---
    const protectedBrands = ['microsoft', 'google', 'apple', 'facebook', 'paypal', 'amazon', 'chase', 'netflix', 'metamask'];
    const deceptiveKeywords = ['secure payment', 'login', 'verify', 'verification', 'account validation', 'security alert', 'bank verification'];

    // High-Value Urgency & Social Engineering Keywords
    const socialEngineeringKeywords = [
      'action required', 'account suspended', 'verify within', 'unusual activity',
      'immediate attention', 'unauthorized login', 'confirm identity', 'restricted access'
    ];

    // =========================================================================
    // INDICATOR 1: DOM EXTRACTS & FORMS
    // =========================================================================
    const forms = $('form');

    if (forms.length === 1) {
      addFinding(15, 'HTML_SINGLE_FORM', 'low', 'Suspicious structural layout: Page contains exactly one isolated form component.');
    }

    forms.each((_, element) => {
      const action = $(element).attr('action');
      if (!action) return;
      const cleanedAction = action.trim();

      if (cleanedAction.startsWith('http://') || cleanedAction.startsWith('https://')) {
        try {
          const actionUrl = new URL(cleanedAction);
          if (actionUrl.hostname !== baseHostname) {
            addFinding(40, 'HTML_EXTERNAL_FORM', 'high', 'Deceptive Form: Form targets data transmission to an external network domain.');
          }
        } catch (_) {}
      }

      const hasPasswordField = $(element).find('input[type="password"]').length > 0;
      if (hasPasswordField) {
        addFinding(25, 'HTML_PASSWORD_FIELD', 'high', 'Credential Harvest Signal: Target form contains active password fields.');
      }
    });

    // =========================================================================
    // INDICATOR 2: BRAND CONTEXT, LOGOS, & IDENTITY MATCHING
    // =========================================================================
    const pageTitle = $('title').text() || '';
    const metaDescription = $('meta[name="description"]').attr('content') || '';
    const ogTitle = $('meta[property="og:title"]').attr('content') || '';

    const contextText = `${pageTitle} ${metaDescription} ${ogTitle}`.toLowerCase();

    // Catch basic deceptive keywords
    deceptiveKeywords.forEach(keyword => {
      if (contextText.includes(keyword)) {
        addFinding(15, 'HTML_DECEPTIVE_KEYWORD', 'medium', `Deceptive pattern detected: "${keyword.toUpperCase()}" target keyword found in metadata elements.`);
      }
    });

    // Cross-reference target brand names with genuine domain profiles
    protectedBrands.forEach(brand => {
      if (contextText.includes(brand) && !baseHostname.includes(brand)) {
        addFinding(40, 'HTML_BRAND_MISMATCH', 'critical', `Critical Brand Mismatch: Brand token identity [${brand.toUpperCase()}] is referenced, but host platform domain is unrelated.`);
      }
    });

    // Favicon Hijack extraction logic
    const faviconHref = $('link[rel*="icon"]').attr('href');
    if (faviconHref && (faviconHref.startsWith('http://') || faviconHref.startsWith('https://'))) {
      try {
        const favUrl = new URL(faviconHref);
        protectedBrands.forEach(brand => {
          if (favUrl.hostname.includes(brand) && !baseHostname.includes(brand)) {
            addFinding(30, 'HTML_FAVICON_HIJACK', 'high', `Favicon Hijack: Branding icon resource assets are pulled directly from authentic external ${brand.toUpperCase()} CDN infrastructure.`);
          }
        });
      } catch (_) {}
    }

    // =========================================================================
    // INDICATOR 3: SOCIAL ENGINEERING & URGENCY DETECTION
    // =========================================================================
    const bodyText = $('body').text().toLowerCase();
    let urgencyMatchCount = 0;

    socialEngineeringKeywords.forEach(phrase => {
      if (bodyText.includes(phrase)) {
        urgencyMatchCount++;
      }
    });

    if (urgencyMatchCount >= 2) {
      addFinding(25, 'HTML_SOCIAL_ENGINEERING', 'medium', `Social Engineering Warning: High presence of urgency/panic-inducing text phrases (${urgencyMatchCount} patterns found).`);
    }

    // =========================================================================
    // INDICATOR 4: MALICIOUS JAVASCRIPT & OBFUSCATION HEURISTICS
    // =========================================================================
    const jsRegexPatterns = {
      HEX_OBFUSCATION: /\\x[0-9a-fA-F]{2}/g,
      SUSPICIOUS_EVAL: /eval\s*\(\s*(?:unescape|atob|decodeURIComponent)\s*\(/i,
      KEYLOGGER_KEYWORDS: /(?:addEventListener|attachEvent)\s*\(\s*['"](?:keypress|keydown|keyup)['"]/i,

      // Defensive Evasion & Anti-Analysis Heuristics
      ANTI_DEBUGGING: /debugger|setInterval\s*\(\s*function\s*\(\s*\)\s*\{\s*debugger/i,
      DISABLE_RIGHT_CLICK: /oncontextmenu\s*=\s*['"]return\s+false['"]|preventDefault\(\s*\)\s*;\s*\}\s*,\s*false\s*\);/i,
      DISABLE_DEVTOOLS: /keydown.*F12|ctrlShiftI|webkitDeprecate/i
    };

    // 1. High-Density Hex Obfuscation
    const hexMatches = html.match(jsRegexPatterns.HEX_OBFUSCATION);
    if (hexMatches && hexMatches.length > 45) {
      addFinding(30, 'HTML_HEX_OBFUSCATION', 'high', `High Density Script Obfuscation: Detected ${hexMatches.length} lexical hex strings indicating runtime code packing.`);
    }

    // 2. Dynamic execution traps
    if (jsRegexPatterns.SUSPICIOUS_EVAL.test(html)) {
      addFinding(35, 'HTML_SUSPICIOUS_EVAL', 'critical', 'Malicious JavaScript Heuristic: Deceptive eval syntax unescaping routine detected.');
    }

    // 3. Scripted input listener traps
    if (jsRegexPatterns.KEYLOGGER_KEYWORDS.test(html)) {
      addFinding(25, 'HTML_KEYLOGGER', 'high', 'Malicious JavaScript Heuristic: Global keypress interception hooks detected via raw script scanning.');
    }

    // 4. Client routing adjustments
    const refreshTag = $('meta[http-equiv="refresh" i]');
    if (refreshTag.length > 0) {
      addFinding(30, 'HTML_META_REFRESH', 'medium', 'Stealth Redirection Element: Client-side meta-refresh routing element deployed.');
    }

    const inlineJsRedirectPattern = /window\.location(\.href)?\s*=/i;
    if (inlineJsRedirectPattern.test(html)) {
      addFinding(25, 'HTML_JS_REDIRECT', 'medium', 'Dynamic Redirection Signal: Inline scripts set browser window location configurations directly.');
    }

    // 5. Right-click & Context Menu Disabling Indicators
    const bodyOnContextMenu = $('body').attr('oncontextmenu');
    if (bodyOnContextMenu || jsRegexPatterns.DISABLE_RIGHT_CLICK.test(html)) {
      addFinding(20, 'HTML_DISABLE_CONTEXT_MENU', 'low', 'Evasion Check: Script attempts to disable native right-click/context menu interactions.');
    }

    // 6. Anti-Debugging / Sandbox Evasion Detection
    if (jsRegexPatterns.ANTI_DEBUGGING.test(html) || jsRegexPatterns.DISABLE_DEVTOOLS.test(html)) {
      addFinding(30, 'HTML_ANTI_DEBUGGING', 'high', 'Anti-Analysis Evasion: Found defensive loops attempting to block browser devtools or debug environments.');
    }

    // =========================================================================
    // STRUCTURAL & PIPELINE AUDITS
    // =========================================================================
    let totalAssets = 0;
    let externalAssets = 0;

    $('script[src], link[rel="stylesheet"][href], img[src]').each((_, el) => {
      const src = $(el).attr('src') || $(el).attr('href');
      if (!src) return;

      totalAssets++;
      if (src.startsWith('http://') || src.startsWith('https://')) {
        try {
          const assetUrl = new URL(src);
          if (assetUrl.hostname !== baseHostname) {
            externalAssets++;
          }
        } catch (_) {}
      }
    });

    if (totalAssets > 0 && (externalAssets / totalAssets) > 0.80) {
      addFinding(20, 'HTML_EXTERNAL_ASSETS', 'low', `Anomalous Resource Sourcing: ${(externalAssets / totalAssets * 100).toFixed(0)}% of primary page assets load from external domains.`);
    }

    const structuralHiddenElements = $('form [style*="display:none"], form [style*="visibility:hidden"], input[type="hidden"]');
    if (structuralHiddenElements.length > 5) {
      addFinding(15, 'HTML_HIDDEN_ELEMENTS', 'low', `Layout Obfuscation: Detected ${structuralHiddenElements.length} hidden structural field input properties inside forms.`);
    }

    // --- FINALIZE MASTER REPORT THREAT STATE ---
    // Cap score at 100 max
    report.riskScore = Math.min(report.riskScore, 100);

    if (report.riskScore >= 60) {
      report.threatFound = true;
    }

    if (report.findings.length === 0) {
      report.findings.push('No malicious layout structural signals found.');
    }

    return report;

  } catch (error) {
    console.error(`[Rules Engine Fault] Content structural exception: ${error.message}`);
    return {
      success: false,
      error: 'HTML processing layer suffered an execution failure during syntax tree compilation.',
      findings: [],
      signals: [],
    };
  }
}