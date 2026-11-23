import { Router } from "express";
import {
    listScans,
    getScanById,
    toggleFavorite,
    deleteScan,
    clearScans,
} from "../db/scanRepository.js";

const router = Router();

/**
 * Scan history API. Every endpoint returns JSON and never leaks internals.
 * A malformed id simply yields 404 / 400 rather than a stack trace.
 */

// GET /api/v1/scans — full scan history, newest first.
router.get("/scans", (req, res) => {
    res.status(200).json({ success: true, scans: listScans() });
});

// GET /api/v1/scans/:id — a single stored scan.
router.get("/scans/:id", (req, res) => {
    const scan = getScanById(req.params.id);
    if (!scan) {
        return res.status(404).json({ success: false, message: "Scan not found." });
    }
    res.status(200).json({ success: true, scan });
});

// PATCH /api/v1/scans/:id/favorite — flip the favorite flag.
router.patch("/scans/:id/favorite", (req, res) => {
    const updated = toggleFavorite(req.params.id);
    if (!updated) {
        return res.status(404).json({ success: false, message: "Scan not found." });
    }
    res.status(200).json({ success: true, ...updated });
});

// DELETE /api/v1/scans/:id — remove a single scan.
router.delete("/scans/:id", (req, res) => {
    const removed = deleteScan(req.params.id);
    if (!removed) {
        return res.status(404).json({ success: false, message: "Scan not found." });
    }
    res.status(200).json({ success: true });
});

// DELETE /api/v1/scans — clear the entire history.
router.delete("/scans", (req, res) => {
    const { deleted } = clearScans();
    res.status(200).json({ success: true, deleted });
});

export default router;