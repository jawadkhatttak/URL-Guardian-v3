/**
 * Minimal leveled logger.
 * Set LOG_LEVEL=debug in .env to see per-service tracing (includes scanned URLs).
 * Default level is "info", which keeps scanned URLs out of the logs.
 */
const LEVELS = { error: 0, warn: 1, info: 2, debug: 3 };

const currentLevel = () => LEVELS[process.env.LOG_LEVEL?.toLowerCase()] ?? LEVELS.info;

const write = (level, method) => (...args) => {
    if (LEVELS[level] <= currentLevel()) {
        method(`[${new Date().toISOString()}] ${level.toUpperCase()}`, ...args);
    }
};

export const log = {
    error: write("error", console.error),
    warn: write("warn", console.warn),
    info: write("info", console.log),
    debug: write("debug", console.log),
};
