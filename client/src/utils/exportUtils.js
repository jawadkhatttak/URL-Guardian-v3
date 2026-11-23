/**
 * Export utility functions for scan data.
 * Centralised here to avoid duplicating blob/anchor logic across components.
 */

/**
 * Download a scan result as a formatted JSON file.
 * @param {object} data - The full scan result object to export.
 * @param {string} hostname - Used to compose the filename. Falls back to 'url_guardian'.
 * @param {string|number} timestamp - ISO string or epoch used in the filename.
 */
export const downloadJson = (data, hostname, timestamp) => {
  const safeName = (hostname || 'url_guardian').replace(/[^a-z0-9_-]/gi, '_');
  const epoch = timestamp ? new Date(timestamp).getTime() : Date.now();
  const filename = `${safeName}_scan_${epoch}.json`;

  const jsonStr = JSON.stringify(data, null, 2);
  const blob = new Blob([jsonStr], { type: 'application/json' });
  const url = URL.createObjectURL(blob);

  const link = document.createElement('a');
  link.href = url;
  link.download = filename;
  document.body.appendChild(link);
  link.click();
  document.body.removeChild(link);
  URL.revokeObjectURL(url);
};
