/**
 * NOTE on what's deliberately NOT here vs the v1 frontend version:
 *
 * - formatTimestamp() used Date.toLocaleString(), which resolves against the
 *   SERVER's locale/timezone. In a stateless backend engine serving unknown
 *   global clients, that's a real bug, not a style choice — timestamps must
 *   leave this engine as ISO 8601 (new Date().toISOString()), locale-agnostic.
 *   Human-readable formatting belongs in the Explanation Engine, scoped to
 *   the actual requesting client's locale.
 *
 * - truncate() was a presentation concern (how much of a string to show in a
 *   UI list). That decision belongs to whatever renders the final output,
 *   not to the intelligence engine producing the raw data.
 *
 * escapeHTML stays: whichever layer eventually renders `title`/`description`
 * text into HTML still needs it, since that text can contain attacker-
 * controlled URL fragments. Keeping it here as shared, available tooling
 * rather than re-implementing it downstream.
 */

/** Escape text before injecting into HTML — defense-in-depth against the
 *  final rendering layer becoming an XSS vector via attacker-controlled URLs. */
export function escapeHTML(str) {
  if (str === null || str === undefined) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

export function capitalize(str) {
  if (!str) return '';
  return str.charAt(0).toUpperCase() + str.slice(1);
}
