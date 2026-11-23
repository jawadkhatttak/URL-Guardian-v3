// Must be the first import: loads .env before any service module reads process.env
import "dotenv/config";
import app from "./app.js";
import { log } from "./utils/log.js";

const PORT = process.env.PORT || 5000;

app.listen(PORT, () => {
    log.info(`URL Guardian API running on port ${PORT}`);
});
