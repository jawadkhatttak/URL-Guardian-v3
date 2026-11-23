/**
 * 🎯 Phishing Detection Pipeline - Validation & Accuracy Suite
 * Evaluates core engine performance and outputs industry-standard validation metrics.
 */

import { processCorrelations } from '../services/correlation.service.js';
import { computeRisk } from '../services/risk.service.js';

// =========================================================================
// 🧪 THE CORPUS: Define distinct mock scenarios representing your 5 profiles
// =========================================================================
const testCorpus = [
  // 1. Legitimate Sites (Expected Outcome: SAFE/LOW)
  {
    url: "https://github.com",
    expectedRisk: "SAFE",
    data: {
      dns: { ipv4: ["140.82.113.3"] },
      whois: { daysSinceRegistration: 6500, registerName: "MarkMonitor" },
      html: { riskScore: 0, threatFound: false, findings: [] },
      virustotal: { success: true, positives: 0, totalScanners: 90 },
      urlLexical: { fullFindings: [], observations: [], urlMetadata: { registeredDomain: "github.com" } }
    }
  },
  {
    url: "https://myportfolio.vercel.app",
    expectedRisk: "SAFE", // Cloud provider testing
    data: {
      dns: { ipv4: ["76.76.21.21"] },
      whois: { daysSinceRegistration: 5, registerName: "Vercel Inc" }, // Young, but dynamic cloud host
      html: { riskScore: 0, threatFound: false, findings: [] },
      virustotal: { success: true, positives: 0, totalScanners: 90 },
      urlLexical: { fullFindings: [], observations: [], urlMetadata: { registeredDomain: "vercel.app" } }
    }
  },

  // 2. Typosquatting / Homograph Domains (Expected Outcome: HIGH/CRITICAL)
  {
    url: "https://mïcrosoft.com",
    expectedRisk: "CRITICAL",
    data: {
      dns: { ipv4: ["192.168.1.1"] },
      whois: { daysSinceRegistration: 14, registerName: "Cheap Registrar Ltd" },
      html: { riskScore: 10, threatFound: false, findings: [] },
      virustotal: { success: true, positives: 1, totalScanners: 90 },
      lexical: { // Now matching the analyzer output structure
        fullFindings: [
          { observationId: "PUNYCODE", title: "Punycode-Encoded Domain", confidence: 1, suppressed: false },
          { observationId: "UNICODE_HOSTNAME", title: "Non-ASCII Characters in Hostname", confidence: 1, suppressed: false },
          { observationId: "HIGH_ENTROPY", title: "Elevated Domain Randomness", confidence: 0.5, suppressed: false }
        ]
      }
    }
  },

  // 3. Known Phishing (Expected Outcome: CRITICAL)
  {
    url: "https://secure-netflix-login-update.com",
    expectedRisk: "CRITICAL",
    data: {
      dns: { ipv4: ["185.220.101.4"] },
      whois: { daysSinceRegistration: 2, registerName: "Namecheap" },
      html: { 
        riskScore: 70, 
        threatFound: true, 
        findings: [
          "Credential Harvest Signal: Target form contains active password fields.",
          "Critical Brand Mismatch: Brand token identity [NETFLIX] is referenced, but host platform domain is unrelated."
        ] 
      },
      virustotal: { success: true, positives: 15, totalScanners: 90 },
      urlLexical: { fullFindings: [], urlMetadata: { registeredDomain: "secure-netflix-login-update.com" } }
    }
  },

  // 4. Dynamic DNS Abuse (Expected Outcome: HIGH/CRITICAL)
  {
    url: "https://paypal-verify.duckdns.org",
    expectedRisk: "CRITICAL",
    data: {
      dns: { ipv4: ["8.8.8.8"] },
      whois: { daysSinceRegistration: 1, registerName: "DuckDNS" },
      html: {
        riskScore: 65,
        threatFound: true,
        findings: [
          "Credential Harvest Signal: Target form contains active password fields.",
          "Critical Brand Mismatch: Brand token identity [PAYPAL] is referenced, but host platform domain is unrelated."
        ]
      },
      virustotal: { success: true, positives: 0, totalScanners: 90 },
      urlLexical: { fullFindings: [], urlMetadata: { registeredDomain: "duckdns.org" } }
    }
  },

  // 5. Evasive Cloaking Deployment (Expected Outcome: HIGH/CRITICAL)
  {
    url: "https://update-my-security-settings.xyz",
    expectedRisk: "HIGH",
    data: {
      dns: { ipv4: ["91.240.118.12"] },
      whois: { daysSinceRegistration: 4, registerName: "Hostinger" },
      html: { riskScore: 0, threatFound: false, findings: [] },
      virustotal: { success: true, positives: 0, totalScanners: 90 },
      lexical: { // Now matching the analyzer output structure
        fullFindings: [
          { observationId: "SUSPICIOUS_KEYWORDS", title: "Suspicious Keyword in Hostname", confidence: 0.75, suppressed: false },
          { observationId: "HIGH_ENTROPY", title: "Elevated Domain Randomness", confidence: 0.5, suppressed: false }
        ]
      }
    }
  }
];

// =========================================================================
// 🚀 RUN ENGINE VALIDATION
// =========================================================================
function executeSuite() {
  console.log("==================================================");
  console.log("🛠️  STARTING PHISHING ENGINE ACCURACY VERIFICATION");
  console.log("==================================================\n");

  let truePositives = 0;  // Correctly flagged bad sites
  let trueNegatives = 0;  // Correctly passed clean sites
  let falsePositives = 0; // Clean sites flagged as bad
  let falseNegatives = 0; // Bad sites missed
  let exactLevelMatches = 0; // Engine produced exactly the expected risk level

  testCorpus.forEach((scenario, index) => {
    const { url, expectedRisk, data } = scenario;

    // 1. Process via your updated services
    const correlations = processCorrelations(data, url);
    const result = computeRisk(data, correlations, url);

    const isExpectedSafe = expectedRisk === "SAFE" || expectedRisk === "LOW";
    const isEngineSafe = result.risk === "SAFE" || result.risk === "LOW";
    const isExactMatch = result.risk === expectedRisk;
    if (isExactMatch) exactLevelMatches++;

    // Binary classification (safe vs. threat) drives precision/recall.
    // A correct classification with the wrong severity is reported separately.
    let status = isExactMatch ? "PASS" : "⚠️  PASS (classification correct, risk level differs)";
    if (isExpectedSafe && isEngineSafe) {
      trueNegatives++;
    } else if (!isExpectedSafe && !isEngineSafe) {
      truePositives++;
    } else if (isExpectedSafe && !isEngineSafe) {
      falsePositives++;
      status = "❌ FALSE POSITIVE";
    } else if (!isExpectedSafe && isEngineSafe) {
      falseNegatives++;
      status = "❌ FALSE NEGATIVE";
    }

    console.log(`[Scenario ${index + 1}] Target: ${url}`);
    console.log(` └─ Expected: ${expectedRisk} | Got: ${result.risk} [Score: ${result.score}]`);
    console.log(` └─ Verdict Justification: "${result.transparency.justification}"`);
    console.log(` └─ Evaluation Result: ${status}\n`);
  });

  // Calculate Industry Metrics
  const totalScenarios = testCorpus.length;
  const accuracy = ((truePositives + trueNegatives) / totalScenarios) * 100;
  const precision = truePositives / (truePositives + falsePositives || 1) * 100;
  const recall = truePositives / (truePositives + falseNegatives || 1) * 100;

  console.log("==================================================");
  console.log("📊 ENGINE ACCURACY PROFILE METRICS");
  console.log("==================================================");
  const levelAccuracy = (exactLevelMatches / totalScenarios) * 100;

  console.log(`Overall Accuracy:  ${accuracy.toFixed(1)}% (safe vs. threat classification)`);
  console.log(`Exact Risk Level:  ${levelAccuracy.toFixed(1)}% (${exactLevelMatches}/${totalScenarios} scenarios)`);
  console.log(`Precision Rate:    ${precision.toFixed(1)}% (Ability to avoid false alarms)`);
  console.log(`Recall / Detection: ${recall.toFixed(1)}% (Ability to catch bad URLs)`);
  console.log(`False Positives:    ${falsePositives}`);
  console.log(`False Negatives:    ${falseNegatives}`);
  console.log("==================================================\n");

  // Non-zero exit on misclassification so the suite can gate CI
  if (falsePositives > 0 || falseNegatives > 0) process.exitCode = 1;
}

executeSuite();