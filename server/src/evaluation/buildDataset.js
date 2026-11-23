import { getUrlLexicalInfo } from '../services/urlLexical.service.js';
import { processCorrelations } from '../services/correlation.service.js';
import { computeRisk } from '../services/risk.service.js';
import { buildFeatureVector } from '../services/features/featureExtractor.service.js';
import { scenarios } from '../dataset/scenarios.js';

/**
 * Materialises the labeled corpus into fully-scored samples by running the REAL
 * pipeline: the lexical engine analyses each URL (offline, synchronous), then
 * the correlations and risk/feature engines run exactly as they do on a live
 * scan. WHOIS / VT / DNS are supplied from the scenario's recorded values.
 */

function materialiseWhois(scenario) {
  const days = scenario.whois.days;
  const creationDate = new Date(Date.now() - days * 24 * 60 * 60 * 1000);
  return {
    domain: new URL(scenario.url).hostname,
    creationDate: creationDate.toISOString(),
    expireDate: null,
    registerName: scenario.whois.registrar ?? null,
    nameServers: null,
    status: null,
    domainAge: days / 365,
    daysSinceRegistration: days,
  };
}

function materialiseVirusTotal(scenario) {
  return {
    success: true,
    positives: scenario.vt.positives,
    totalScanners: scenario.vt.total,
    threatFound: scenario.vt.positives >= 2,
    reputation: 0,
    status: 'COMPLETED',
    findings: null,
  };
}

async function buildSample(scenario) {
  const hostname = new URL(scenario.url).hostname;
  const urlLexical = await getUrlLexicalInfo(scenario.url);

  const masterFindings = {
    dns: { domain: hostname, ipv4: scenario.dns.ipv4, ipv6: null, nameServers: null },
    whois: materialiseWhois(scenario),
    html: scenario.html,
    virustotal: materialiseVirusTotal(scenario),
    urlLexical,
  };

  const correlations = processCorrelations(masterFindings, scenario.url);
  const risk = computeRisk(masterFindings, correlations, scenario.url);
  const featureVector = buildFeatureVector(masterFindings, correlations, scenario.url);

  return {
    id: scenario.id,
    url: scenario.url,
    label: scenario.label,
    score: risk.score,
    risk: risk.risk,
    featureVector,
    features: risk.features.map((f) => ({ id: f.id, source: f.source, contribution: f.contribution })),
    correlations: correlations.map((c) => c.id),
  };
}

/**
 * Build every sample in the corpus.
 * @returns {Promise<Array<object>>}
 */
export async function buildDataset() {
  const samples = [];
  for (const scenario of scenarios) {
    samples.push(await buildSample(scenario));
  }
  return samples;
}