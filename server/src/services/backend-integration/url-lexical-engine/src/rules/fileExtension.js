import { RISKY_EXTENSIONS } from '../data/riskyExtensions.js';

export const id = 'RISKY_FILE_EXTENSION';
export const ruleVersion = '2.0.0';

function getExtension(pathname) {
  const lastSegment = pathname.split('/').filter(Boolean).pop() || '';
  const dotIndex = lastSegment.lastIndexOf('.');
  if (dotIndex === -1 || dotIndex === lastSegment.length - 1) return '';
  return lastSegment.slice(dotIndex + 1).toLowerCase();
}

export function observe(ctx) {
  const ext = getExtension(ctx.pathname || '');
  if (!ext) return [];

  for (const [tier, list] of Object.entries(RISKY_EXTENSIONS)) {
    if (list.includes(ext)) {
      return [
        {
          observationId: id,
          category: 'PATH_QUERY',
          data: {
            extension: ext,
            // This tier label comes from data/riskyExtensions.js's own
            // taxonomy of file-type danger (does it execute immediately,
            // carry macros, etc.) — a descriptive fact about the
            // EXTENSION's inherent nature, not this rule's severity
            // judgment about THIS particular URL.
            extensionRiskTier: tier,
          },
          evidence: [`.${ext}`],
          confidence: 1.0, // exact extension match against a static list
          meta: { sourceRule: id, ruleVersion },
        },
      ];
    }
  }

  return [];
}
