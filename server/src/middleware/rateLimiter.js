import { rateLimit } from "express-rate-limit";

const windowMinutes = Number(process.env.RATE_LIMIT_WINDOW_MINUTES) || 15;
const maxRequests = Number(process.env.RATE_LIMIT_MAX) || 20;

/**
 * Limits scans per IP. Every scan calls paid third-party APIs
 * (VirusTotal, WhoisJSON, ScrapingBee), so this protects the API quotas.
 */
export const scanRateLimiter = rateLimit({
    windowMs: windowMinutes * 60 * 1000,
    limit: maxRequests,
    standardHeaders: "draft-7",
    legacyHeaders: false,
    message: {
        success: false,
        message: `Too many scans from this IP. Try again in ${windowMinutes} minutes.`,
    },
});
