import test from 'node:test';
import assert from 'node:assert/strict';

import { computeRisk } from '../src/services/risk.service.js';
import { buildExplanation } from '../src/services/explanation.service.js';
import { getUrlLexicalInfo } from '../src/services/urlLexical.service.js';

const typosquatFindings = () => ({
    virustotal: {
        success: true,
        totalScanners: 10,
        positives: 8,
        threatFound: true,
    },
    lexical: {
        fullFindings: [
            {
                suggestedSeverity: 'critical',
                confidence: 0.95,
                suppressed: false,
                observationId: 'BRAND_TYPOSQUAT',
                title: 'Brand typo',
                description: 'desc',
                references: [],
            },
        ],
        observations: [],
        urlMetadata: { registeredDomain: 'example.com' },
    },
});

test('computeRisk combines VirusTotal and lexical signals into a CRITICAL score', () => {
    const result = computeRisk(typosquatFindings(), [], 'https://example-typosquat.com');

    // VirusTotal: 8/10 → 80%, capped at 40 points
    // Typosquat:  30 (base) × 1.4 (critical) × 0.95 (confidence) = 39.9 points
    assert.equal(result.score, 80);
    assert.equal(result.risk, 'CRITICAL');
    assert.equal(result.contributions.length, 2);
});

test('computeRisk returns SAFE with a score of 0 when no signals are present', () => {
    const result = computeRisk({}, [], 'https://example.com');

    assert.equal(result.score, 0);
    assert.equal(result.risk, 'SAFE');
});

test('computeRisk scores newly registered domains from WHOIS', () => {
    const result = computeRisk({ whois: { daysSinceRegistration: 3 } }, [], 'https://example.com');

    assert.equal(result.score, 25);
    assert.equal(result.risk, 'MEDIUM');
});

test('computeRisk mitigates new-domain weight on developer cloud platforms', () => {
    const result = computeRisk({ whois: { daysSinceRegistration: 3 } }, [], 'https://someone.github.io');

    // 25 points × 0.5 platform mitigation = 12.5 → rounded to 13
    assert.equal(result.score, 13);
    assert.ok(result.contributions[0].mitigated);
});

test('buildExplanation reads lexical findings from the same payload shape used by analysis', () => {
    const findings = typosquatFindings();
    const riskResult = computeRisk(findings, [], 'https://example.com');
    const explanation = buildExplanation(findings, [], riskResult, 'https://example.com');

    assert.ok(explanation.reasons.some((reason) => reason.title === 'Brand typo'));
    assert.equal(explanation.verdict.riskLevel, riskResult.risk);
});

test('lexical engine detects a leet-speak brand inside a hyphenated domain', async () => {
    const lexical = await getUrlLexicalInfo('http://paypa1-login-verify.xyz/account/update');
    const typosquat = lexical.fullFindings.find((f) => f.observationId === 'BRAND_TYPOSQUAT');

    assert.ok(typosquat, 'expected a BRAND_TYPOSQUAT finding for "paypa1"');
});

test('lexical engine does not flag ordinary words that are one letter from a brand', async () => {
    for (const url of ['https://apply-now-jobs.com', 'https://goggles-shop.com']) {
        const lexical = await getUrlLexicalInfo(url);
        const typosquat = lexical.fullFindings.find((f) => f.observationId === 'BRAND_TYPOSQUAT');
        assert.equal(typosquat, undefined, `false positive typosquat on ${url}`);
    }
});

test('correlation engine does not treat a missing WHOIS age as a new domain', async () => {
    const { processCorrelations } = await import('../src/services/correlation.service.js');
    const url = 'https://unknown-age-example.xyz';
    const findings = {
        whois: { daysSinceRegistration: null },
        virustotal: { success: true, positives: 2, totalScanners: 90, threatFound: true },
        lexical: await getUrlLexicalInfo(url),
    };

    const correlations = processCorrelations(findings, url);
    const mentionsNullAge = correlations.some((c) =>
        JSON.stringify(c).includes('null days'));
    assert.equal(mentionsNullAge, false);
});
