import { log } from "../utils/log.js";

export async function lookupWhois(domain) {
    log.debug("Fetching WHOIS Info of ", domain);

    // Read at call time so it never depends on module import order vs. dotenv
    const WHOIS_API_KEY = process.env.WHOIS_API_KEY;
    if (!WHOIS_API_KEY) {
        return { error: "Missing WHOIS_API_KEY inside environment configuration." };
    }

    const WHOIS_TIMEOUT = 8000; // 8 seconds for WHOIS API (longer than DNS since it's an external API)
    
    try {
        // Create an AbortController for timeout handling
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), WHOIS_TIMEOUT);
        
        const res = await fetch(`https://whoisjson.com/api/v1/whois?domain=${encodeURIComponent(domain)}`, {
            headers: { Authorization: "TOKEN=" + WHOIS_API_KEY },
            signal: controller.signal
        });
        const data = await res.json();
        // Safe extraction with null coalescing and optional chaining
        const creationDateStr = data.created ?? null;
        const expireDateStr = data.expires ?? null;
        const registerName = data.registrar?.name ?? null;  // Safe navigation for nested property
        const nameServers = Array.isArray(data.nameserver) ? data.nameserver : null;  // Ensure it's an array
        const status = data.status ?? null;






        const creationDate = creationDateStr ? new Date(creationDateStr) : null;
        const expireDate = expireDateStr ? new Date(expireDateStr) : null;

        // Domain age
        const domainAge = creationDate ? (new Date() - creationDate) / (1000 * 60 * 60 * 24 * 365) : null;

        // calculate Days since registration 
        const daysSinceRegistration = creationDate ? Math.floor((new Date() - creationDate) / (1000 * 60 * 60 * 24)) : null;


        clearTimeout(timeoutId);
        
        return {
            domain: domain,
            creationDate: creationDate,
            expireDate: expireDate,
            registerName: registerName,
            nameServers: nameServers,
            status: status,
            domainAge: domainAge,
            daysSinceRegistration: daysSinceRegistration
        };


    } catch (error) {
        if (error.name === 'AbortError') {
            log.error("WHOIS API Error: Request timeout");
            return { error: "WHOIS lookup timed out" };
        }
        log.error("WHOIS API Error:", error.message);
        // Fallback gracefully so your whole app doesn't crash if the API limit hits
        return { error: "WHOIS lookup service unavailable" };
    }
}
