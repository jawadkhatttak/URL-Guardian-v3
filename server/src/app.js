import express from "express";
import cors from "cors";
import helmet from "helmet";
import analyzeRoutes from "./routes/analyze.routes.js";
import scanRoutes from "./routes/scan.routes.js";
import { logger } from "./middleware/logger.js";
import { notFoundHandler, errorHandler } from "./middleware/errorHandler.js";

const app = express();

// Comma-separated list of allowed frontend origins, e.g. "https://myapp.com,http://localhost:5173"
const allowedOrigins = (process.env.CORS_ORIGIN || "http://localhost:5173")
    .split(",")
    .map((origin) => origin.trim())
    .filter(Boolean);

app.use(helmet());
app.use(cors({
    origin(origin, callback) {
        // Allow non-browser clients (curl, Postman) that send no Origin header
        if (!origin || allowedOrigins.includes(origin)) return callback(null, true);
        return callback(null, false);
    },
    methods: ["GET", "POST"],
}));
app.use(express.json({ limit: "10kb" }));
app.use(logger);

app.use("/api/v1", analyzeRoutes);
app.use("/api/v1", scanRoutes);

app.use(notFoundHandler);
app.use(errorHandler);

export default app;
