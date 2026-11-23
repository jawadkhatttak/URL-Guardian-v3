/**
 * Formatting and visual mapping helper functions
 */

/**
 * Format ISO Timestamp into readable date-time string
 */
export const formatDate = (isoString) => {
  if (!isoString) return 'N/A';
  try {
    const date = new Date(isoString);
    return date.toLocaleString(undefined, {
      year: 'numeric',
      month: 'short',
      day: 'numeric',
      hour: '2-digit',
      minute: '2-digit',
      second: '2-digit'
    });
  } catch {
    return isoString;
  }
};

/**
 * Get CSS badge class based on risk string
 */
export const getRiskBadgeClass = (risk) => {
  const norm = (risk || '').toUpperCase();
  switch (norm) {
    case 'CRITICAL': return 'badge-critical';
    case 'HIGH': return 'badge-high';
    case 'MEDIUM': return 'badge-medium';
    case 'LOW': return 'badge-low';
    case 'CLEAN':
    case 'INFO':
    case 'SAFE':
      return 'badge-clean';
    default:
      return 'badge-low';
  }
};

/**
 * Get CSS severity class for rule findings
 */
export const getSeverityClass = (severity) => {
  const norm = (severity || '').toLowerCase();
  switch (norm) {
    case 'critical':
      return 'severity-critical';
    case 'high':
      return 'severity-high';
    case 'medium':
      return 'severity-medium';
    case 'low':
      return 'severity-low';
    case 'clean':
    case 'safe':
    case 'info':
      return 'severity-clean';
    default:
      return '';
  }
};

/**
 * Get color representation for risk levels (useful for SVGs/gauges)
 */
export const getRiskColor = (risk) => {
  const norm = (risk || '').toUpperCase();
  switch (norm) {
    case 'CRITICAL': return '#ef4444'; // Red
    case 'HIGH': return '#f97316'; // Orange
    case 'MEDIUM': return '#eab308'; // Yellow
    case 'LOW': return '#3b82f6'; // Blue
    case 'CLEAN':
    case 'INFO':
    case 'SAFE':
      return '#10b981'; // Green
    default:
      return '#6b7280'; // Slate Muted
  }
};

/**
 * Format domain age into readable text (years and months)
 */
export const formatDomainAge = (ageInYears) => {
  if (ageInYears === null || ageInYears === undefined) return 'N/A';
  
  const years = Math.floor(ageInYears);
  const months = Math.round((ageInYears - years) * 12);
  
  if (years === 0) {
    return `${months} month${months !== 1 ? 's' : ''}`;
  }
  
  if (months === 0) {
    return `${years} year${years !== 1 ? 's' : ''}`;
  }
  
  return `${years} year${years !== 1 ? 's' : ''}, ${months} month${months !== 1 ? 's' : ''}`;
};
