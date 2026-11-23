import { randomUUID } from "node:crypto";
import { getDb } from "./database.js";

/**
 * Scan repository — the single data-access layer over the `scans` table.
 *
 * The full analysis result is stored as JSON in `result_json`. List queries
 * return the stored result alongside the summary columns so the frontend can
 * render history rows and reopen reports without a second round-trip.
 */

function rowToRecord(row) {
    return {
        id: row.id,
        url: row.url,
        hostname: row.hostname,
        score: row.score,
        risk: row.risk,
        isFavorite: row.is_favorite === 1,
        timestamp: row.created_at,
        result: JSON.parse(row.result_json),
    };
}

/**
 * Persist a completed analysis.
 * @param {object} scan - { url, hostname, score, risk, result }
 * @returns {{ id: string, url: string, hostname: string|null, score: number, risk: string, isFavorite: boolean, timestamp: string }}
 */
export function createScan({ url, hostname = null, score = 0, risk = "UNKNOWN", result }) {
    const db = getDb();
    const id = randomUUID();
    const createdAt = new Date().toISOString();

    db.prepare(
        `INSERT INTO scans (id, url, hostname, score, risk, is_favorite, created_at, result_json)
         VALUES (?, ?, ?, ?, ?, 0, ?, ?)`
    ).run(id, url, hostname, score, risk, createdAt, JSON.stringify(result ?? {}));

    return { id, url, hostname, score, risk, isFavorite: false, timestamp: createdAt };
}

/**
 * Returns every scan, newest first, including the stored result payload.
 */
export function listScans() {
    const db = getDb();
    const rows = db.prepare("SELECT * FROM scans ORDER BY created_at DESC").all();
    return rows.map(rowToRecord);
}

/**
 * Returns a single scan by id, or null when it does not exist.
 */
export function getScanById(id) {
    const db = getDb();
    const row = db.prepare("SELECT * FROM scans WHERE id = ?").get(id);
    return row ? rowToRecord(row) : null;
}

/**
 * Flips the favorite flag for a scan.
 * @returns {{ id: string, isFavorite: boolean } | null} null when the id is unknown.
 */
export function toggleFavorite(id) {
    const db = getDb();
    const row = db.prepare("SELECT is_favorite FROM scans WHERE id = ?").get(id);
    if (!row) return null;

    const nextValue = row.is_favorite === 1 ? 0 : 1;
    db.prepare("UPDATE scans SET is_favorite = ? WHERE id = ?").run(nextValue, id);
    return { id, isFavorite: nextValue === 1 };
}

/**
 * Deletes a single scan.
 * @returns {boolean} true when a row was removed.
 */
export function deleteScan(id) {
    const db = getDb();
    const result = db.prepare("DELETE FROM scans WHERE id = ?").run(id);
    return result.changes > 0;
}

/**
 * Removes every scan.
 * @returns {{ deleted: number }}
 */
export function clearScans() {
    const db = getDb();
    const result = db.prepare("DELETE FROM scans").run();
    return { deleted: result.changes };
}

/**
 * Total number of stored scans.
 */
export function countScans() {
    const db = getDb();
    const row = db.prepare("SELECT COUNT(*) AS count FROM scans").get();
    return row.count;
}