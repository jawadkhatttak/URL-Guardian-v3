import { Router } from "express";
import { analyzeController } from "../controllers/analyze.controller.js";
import { validateUrl } from "../middleware/validate.js";
import { scanRateLimiter } from "../middleware/rateLimiter.js";

const router = Router();

// Health check
router.get("/analyze", (req, res) => {
  res.status(200).json({ status: "ok", message: "URL Guardian API v1 is running." });
});

// Order matters: rate-limit first, then validate, then analyze
router.post("/analyze", scanRateLimiter, validateUrl, analyzeController);

export default router;
