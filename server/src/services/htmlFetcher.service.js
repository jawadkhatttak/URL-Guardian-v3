import { ScrapingBeeClient } from "scrapingbee";
import { log } from "../utils/log.js";


/**
 * Network Layer: Hardened fetch routine that filters content types and payload sizes
 * to prevent OOM memory bomb attacks and binary corruption inside the rules engine.
 * * @param {string} targetUrl - The endpoint URL to scrape.
 * @returns {Promise<string>} Raw HTML source text string.
 */

export async function fetchHtmlContent(targetUrl) {
  const apiKey = process.env.SCRAPINGBEE_API_KEY;
  if (!apiKey) {
    throw new Error("Missing SCRAPINGBEE_API_KEY inside environment configuration.");
  }

  const client = new ScrapingBeeClient(apiKey);
  log.debug(`[I/O Operational - Hardened] Initiating Guarded Cloud Scraping for: ${targetUrl}`);

  // Configured Limits
  const MAX_CONTENT_LENGTH = 10 * 1024 * 1024; // Strict 10MB Threshold Limit
  const ALLOWED_CONTENT_TYPES = ['text/html', 'text/xhtml', 'application/xhtml+xml'];

  const response = await client.get({
    url: targetUrl,
    params: { block_ads: 'true' },
    timeout: 30000, // RULE 1: Hard 30-second network infrastructure timeout
  });

  if (!response) {
    throw new Error("Target destination returned an empty or missing response payload.");
  }

  // === GUARD CLAUSE: ISSUE 2 (Content-Type Validation) ===
  const contentType = response.headers?.['content-type'] || '';
  const isHtml = ALLOWED_CONTENT_TYPES.some(type => contentType.toLowerCase().includes(type));
  
  if (!isHtml) {
    throw new Error(`Security Exception: Rejected unsupported content type [${contentType}]. Expected text/html.`);
  }

  // === GUARD CLAUSE: ISSUE 1 (Content-Length Validation) ===
  // 1. Check structural header length sent by remote server
  const contentLengthHeader = parseInt(response.headers?.['content-length'], 10);
  if (!isNaN(contentLengthHeader) && contentLengthHeader > MAX_CONTENT_LENGTH) {
    throw new Error(`Security Exception: Payload structural length exceeds maximal safe limits (${contentLengthHeader} bytes).`);
  }

  // 2. Fallback: Check the explicit in-memory data buffer size directly
  if (response.data) {
    const dataSize = response.data.byteLength || Buffer.byteLength(response.data);
    if (dataSize > MAX_CONTENT_LENGTH) {
      throw new Error(`Security Exception: Evaluated in-memory size violates buffer ceilings (${dataSize} bytes).`);
    }
  } else {
    throw new Error("No data structure returned from scraping pipeline proxy endpoints.");
  }

  // Handle cross-runtime buffer string conversion safely
  if (typeof response.data.toString === 'function') {
    return response.data.toString('utf-8');
  } else {
    const decoder = new TextDecoder();
    return decoder.decode(response.data);
  }
}

// debugging
