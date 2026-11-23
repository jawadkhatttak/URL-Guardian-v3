import { lookupDns } from "./dns.service.js";
import { lookupWhois } from "./whois.service.js";
import { fetchHtmlContent } from "./htmlFetcher.service.js";
import { analyzeHtmlContent } from "./htmlAnalyzer.service.js";
import { lookupVirusTotal } from "./virusTotal.service.js";
import { processCorrelations } from "./correlation.service.js";
import { getUrlLexicalInfo } from "./urlLexical.service.js";
import { computeRisk } from "./risk.service.js";
import { buildExplanation } from "./explanation.service.js";
import { resolveScoring } from "../ml/scoring.js";
import { log } from "../utils/log.js";


export async function analyzeUrl(url) {
    log.debug("[Master Orchestration Tier] Launching full security scan for:", url);
    const parsedUrl = new URL(url);

    const fetchAndAnalyzeHtml = async () => {
        try {
            const rawHtml = await fetchHtmlContent(parsedUrl.href);
            return analyzeHtmlContent(rawHtml, parsedUrl.href);
        } catch (error) {
            return {
                success: false,
                threatFound: false,
                error: error.message || "HTML Engine tier timed out or failed."
            };
        }
    };

    // Parallel processing array remains completely clean
    const servicePromises = [
        lookupDns(parsedUrl.hostname),
        lookupWhois(parsedUrl.hostname),
        fetchAndAnalyzeHtml(),
        lookupVirusTotal(parsedUrl.href),
        getUrlLexicalInfo(parsedUrl.href)
    ];

    const results = await Promise.allSettled(servicePromises);

    const [dnsResult, whoisResult, htmlResult, vtResult, lexicalResult] = results.map(result =>
        result.status === 'fulfilled' ? result.value : { error: "Downstream microservice engine unavailable." }
    );

    // Collect all raw responses into your master object layout
    const rawFindings = {
        dns: dnsResult,
        whois: whoisResult,
        html: htmlResult,
        virustotal: vtResult,
        lexical: lexicalResult
    };

    // 🔥 2. GENERATE ADVANCED CROSS-SERVICE CORRELATIONS
    const correlatedThreats = processCorrelations(rawFindings, parsedUrl.href);



    const riskResult = computeRisk(rawFindings, correlatedThreats, parsedUrl.href);

    // Combine the heuristic score with the trained ML model (mode from
    // SCORING_MODE: heuristic | ml | hybrid). Falls back to heuristic when no
    // model is loaded.
    const scoring = resolveScoring(riskResult.featureVector, riskResult.score);
    const scoringRiskResult = (scoring.score === riskResult.score && scoring.risk === riskResult.risk)
        ? riskResult
        : { ...riskResult, score: scoring.score, risk: scoring.risk };

    const explanation = buildExplanation(rawFindings, correlatedThreats, scoringRiskResult, parsedUrl.href);

    log.debug(`[Risk Engine] Computed risk level: ${riskResult.risk} with score: ${riskResult.score} (final: ${scoring.score} via ${scoring.mode})`);

    return {
        url: parsedUrl.href,
        findings: rawFindings,
        correlations: correlatedThreats, // 🔥 3. EXPOSE DYNAMIC CORRELATIONS IN THE FINAL OUTPUT
        features: riskResult.features,          // Unified, scored feature list (single source of truth)
        featureVector: riskResult.featureVector, // Fixed-schema numeric vector for ML / datasets
        scoring,                                // { mode, heuristicScore, mlScore, mlProbability, ... }
        score: scoring.score,
        risk: scoring.risk,
        explanation: explanation
    };
}
