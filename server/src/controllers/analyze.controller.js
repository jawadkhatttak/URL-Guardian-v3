import { analyzeUrl } from "../services/analysis.service.js";
import { createScan } from "../db/scanRepository.js";
import { log } from "../utils/log.js";

export async function analyzeController(req, res, next) {
    try {
        const targetUrl = req.parsedUrl.href;
        const result = await analyzeUrl(targetUrl);

        // Persist the completed scan. A storage failure must not fail the scan
        // itself — the analysis result is still returned to the caller.
        try {
            const hostname = new URL(targetUrl).hostname;
            const saved = createScan({
                url: result.url,
                hostname,
                score: result.score,
                risk: result.risk,
                result,
            });
            result.id = saved.id;
            result.isFavorite = saved.isFavorite;
            result.timestamp = saved.timestamp;
        } catch (dbError) {
            log.error("Failed to persist scan result:", dbError.message);
        }

        res.status(200).json(result);
    } catch (error) {
        next(error);
    }
}