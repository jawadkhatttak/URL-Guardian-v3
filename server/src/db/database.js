import { DatabaseSync } from "node:sqlite";
import { fileURLToPath } from "node:url";
import path from "node:path";
import fs from "node:fs";
import { log } from "../utils/log.js";

/**
 * SQLite persistence layer (Node 26 built-in `node:sqlite`).
 *
 * Zero external dependencies and no native compilation. The database file is
 * created on first use. Override the location with DATABASE_PATH; otherwise it
 * lives in server/data/guardian.db (gitignored).
 */

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const DEFAULT_DB_PATH = path.resolve(__dirname, "../../data/guardian.db");

let dbInstance = null;

const SCHEMA = `
    CREATE TABLE IF NOT EXISTS scans (
        id           TEXT PRIMARY KEY,
        url          TEXT NOT NULL,
        hostname     TEXT,
        score        INTEGER NOT NULL,
        risk         TEXT NOT NULL,
        is_favorite  INTEGER NOT NULL DEFAULT 0,
        created_at   TEXT NOT NULL,
        result_json  TEXT NOT NULL
    );

    CREATE INDEX IF NOT EXISTS idx_scans_created_at ON scans (created_at DESC);
    CREATE INDEX IF NOT EXISTS idx_scans_url ON scans (url);
`;

function applySchema(database) {
    database.exec(SCHEMA);
}

/**
 * Returns the shared database connection, opening it and applying the schema on
 * first call.
 * @returns {import('node:sqlite').DatabaseSync}
 */
export function getDb() {
    if (dbInstance) return dbInstance;

    const dbPath = process.env.DATABASE_PATH
        ? path.resolve(process.env.DATABASE_PATH)
        : DEFAULT_DB_PATH;

    fs.mkdirSync(path.dirname(dbPath), { recursive: true });

    dbInstance = new DatabaseSync(dbPath);
    dbInstance.exec("PRAGMA journal_mode = WAL;");
    dbInstance.exec("PRAGMA foreign_keys = ON;");
    applySchema(dbInstance);

    log.info(`SQLite database ready at ${dbPath}`);
    return dbInstance;
}

/**
 * Closes the shared connection if open. Used by tests.
 */
export function closeDb() {
    if (dbInstance) {
        dbInstance.close();
        dbInstance = null;
    }
}