import { log } from "../utils/log.js";

export function notFoundHandler(req, res) {
    res.status(404).json({
        success: false,
        message: `Route ${req.method} ${req.originalUrl} not found.`,
    });
}

// Express recognises error handlers by their 4-argument signature
// eslint-disable-next-line no-unused-vars
export function errorHandler(err, req, res, next) {
    // Malformed JSON body or body over the size limit (thrown by express.json)
    if (err.type === "entity.parse.failed") {
        return res.status(400).json({ success: false, message: "Request body must be valid JSON." });
    }
    if (err.type === "entity.too.large") {
        return res.status(413).json({ success: false, message: "Request body is too large." });
    }

    log.error("Unhandled error:", err);

    // Never leak internal error details to the client
    res.status(err.status || 500).json({
        success: false,
        message: "An internal error occurred while analyzing the URL.",
    });
}
