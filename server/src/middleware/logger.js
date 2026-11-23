import { log } from "../utils/log.js";

// Logs method, path, status and duration. Request bodies (scanned URLs) are not logged.
export function logger(req, res, next) {
    const start = Date.now();
    res.on("finish", () => {
        log.info(`${req.method} ${req.originalUrl} ${res.statusCode} ${Date.now() - start}ms`);
    });
    next();
}
