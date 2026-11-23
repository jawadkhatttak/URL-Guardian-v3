const MAX_URL_LENGTH = 2048;

export function validateUrl(req, res, next) {
    // req.body is undefined in Express 5 when no JSON body is sent
    const { url } = req.body ?? {};

    if (typeof url !== "string" || url.trim() === "") {
        return res.status(400).json({
            success: false,
            message: "URL must be a non-empty string."
        });
    }

    if (url.length > MAX_URL_LENGTH) {
        return res.status(400).json({
            success: false,
            message: `URL must be at most ${MAX_URL_LENGTH} characters.`
        });
    }

    let parsedUrl;
    try {
        parsedUrl = new URL(url.trim());
    } catch {
        return res.status(400).json({
            success: false,
            message: "Invalid URL."
        });
    }

    // Parse with the URL API and check the protocol property. A substring check
    // like url.includes("http://") can be bypassed (e.g. "javascript:alert('http://')").
    if (parsedUrl.protocol !== "http:" && parsedUrl.protocol !== "https:") {
        return res.status(400).json({
            success: false,
            message: "Only HTTP and HTTPS URLs are allowed."
        });
    }

    req.parsedUrl = parsedUrl;
    next();
}
