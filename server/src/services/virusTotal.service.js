import { log } from "../utils/log.js";


/**
 * Helper to generate the VirusTotal URL-safe Base64 identifier.
 */
function generateVirusTotalId(url) {
  const cleanedUrl = url.replace(/\/$/, ""); // Strip trailing slash
  const base64 = Buffer.from(cleanedUrl).toString("base64");
  return base64.replace(/=/g, ""); // Remove padding
}

/**
 * Parses the raw analysis attributes statistics object into a standardized payload.
 */
function parseVirusTotalStats(stats, reputation = 0) {
  const totalPositives = (stats.malicious || 0) + (stats.suspicious || 0);
  const totalScanners = Object.values(stats).reduce((acc, curr) => acc + curr, 0);
  const threatDetected = totalPositives >= 2;

  return {
    success: true,
    threatFound: threatDetected,
    positives: totalPositives,
    totalScanners: totalScanners,
    reputation: reputation,
    findings: threatDetected 
      ? `Global Threat Alert: Flagged malicious by ${totalPositives} engine vendors out of ${totalScanners} audits.`
      : `Clean History: Checked across ${totalScanners} engines with zero global malicious records.`
  };
}

/**
 * Asynchronous Background Polling Engine: Fires off a brand-new scan request 
 * and handles smart resource looping using exponential backoff scaling rules.
 */
async function initiateBackgroundScanAndPoll(targetUrl, apiKey) {
  try {
    log.debug(`[Polling Engine - Async Triggered] Submitting URL for remote analysis indexing: ${targetUrl}`);
    
    // 1. Submit the URL to VirusTotal Scan Pipeline
    const submissionResponse = await fetch('https://www.virustotal.com/api/v3/urls', {
      method: 'POST',
      headers: {
        'x-apikey': apiKey,
        'Content-Type': 'application/x-www-form-urlencoded'
      },
      body: new URLSearchParams({ url: targetUrl })
    });

    if (!submissionResponse.ok) {
      throw new Error(`Failed to submit scan job layout request. Status: ${submissionResponse.status}`);
    }

    const submissionData = await submissionResponse.json();
    const analysisId = submissionData.data?.id; 

    if (!analysisId) {
      throw new Error("VirusTotal failed to generate a valid target Analysis Identifier.");
    }

    // 2. Resource-Efficient Smart Polling Loop with Exponential Backoff
    const maxRetries = 5;
    let delay = 4000; // Start with a safe 4-second initial delay to protect 429 ceilings

    for (let attempt = 1; attempt <= maxRetries; attempt++) {
      log.debug(`[Polling Engine] Awaiting processing window... (Attempt ${attempt}/${maxRetries} with ${delay}ms backoff delay)`);
      
      await new Promise(resolve => setTimeout(resolve, delay));

      const checkResponse = await fetch(`https://www.virustotal.com/api/v3/analyses/${analysisId}`, {
        method: 'GET',
        headers: { 'x-apikey': apiKey }
      });

      if (!checkResponse.ok) {
        log.error(`[Polling Engine Warning] Check failed with status ${checkResponse.status}. Skipping iteration.`);
        continue;
      }

      const analysisData = await checkResponse.json();
      const status = analysisData.data?.attributes?.status;

      if (status === 'completed') {
        const stats = analysisData.data?.attributes?.stats;
        log.debug(`[Polling Engine] Scan loop resolved completely for target.`);
        
        // At this point, you can optionally store the final result in a local DB cache if needed
        return parseVirusTotalStats(stats);
      }

      // Exponential backoff modification formula to avoid triggering 429 rate bounds
      delay *= 1.8; 
    }

    log.warn(`[Polling Engine Timeout] Scan loop exceeded maximum safe resource ceilings for: ${targetUrl}`);
  } catch (error) {
    log.error(`[Background Polling Processing Error] Structural execution failed: ${error.message}`);
  }
}

/**
 * Microservice Tier: Queries the VirusTotal v3 API for existing domain/URL threat intelligence.
 */
export async function lookupVirusTotal(targetUrl) {
  const apiKey = process.env.VIRUSTOTAL_API_KEY;
  
  if (!apiKey) {
    throw new Error("Missing VIRUSTOTAL_API_KEY inside environment configuration.");
  }

  try {
    const resourceId = generateVirusTotalId(targetUrl);
    const vtEndpoint = `https://www.virustotal.com/api/v3/urls/${resourceId}`;

    log.debug(`[VirusTotal Operational] Querying global threat cache for: ${targetUrl}`);

    const response = await fetch(vtEndpoint, {
      method: 'GET',
      headers: {
        'x-apikey': apiKey,
        'Accept': 'application/json'
      }
    });

    // === SECURITY FIX: OPTIMIZATION AND SEARCH IMPLEMENTATION ===
    if (response.status === 404) {
      log.debug(`[VirusTotal Cache Miss] Record absent. Handing off submission execution asynchronously to background loop.`);
      
      // Fire-and-Forget: Trigger background scanning without using 'await' 
      // This ensures the application does NOT hang or block the master response window.
      initiateBackgroundScanAndPoll(targetUrl, apiKey);

      return {
        success: true,
        threatFound: false,
        status: "SCAN_QUEUED",
        positives: 0,
        totalScanners: 0,
        findings: "URL analysis records not found in database. Scan request successfully pushed to background processing queue."
      };
    }

    if (!response.ok) {
      throw new Error(`VirusTotal API returned HTTP Error Status: ${response.status}`);
    }

    const payload = await response.json();
    const stats = payload.data?.attributes?.last_analysis_stats;
    const reputation = payload.data?.attributes?.reputation || 0;

    if (!stats) {
      return { success: false, error: "Malformed response syntax from remote threat intelligence tier." };
    }

    return parseVirusTotalStats(stats, reputation);

  } catch (error) {
    log.error(`[VirusTotal Fault] Engine failure: ${error.message}`);
    return {
      success: false,
      threatFound: false,
      error: "Global database analysis tier temporarily unavailable or rate-limited."
    };
  }
}

// FIXED: Pass the raw text URL string directly into the lookup function
// const rawUrl = "https://linkscribe.io/";
