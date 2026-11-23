import { CONFUSABLES_MAP, detectScripts } from '../data/confusables.js';

export const id = 'HOMOGRAPH';
export const ruleVersion = '2.0.0';

/**
 * v1 had two branches: "mixed script + known confusable chars" (critical)
 * vs "mixed script alone" (high). Unlike subdomainAbuse's two genuinely
 * independent facts, these aren't independent — confusable-character
 * presence is a REFINEMENT of the mixed-script fact, not a separate
 * phenomenon that can occur without it. So this collapses into ONE
 * observation carrying both facts, rather than two possible observations.
 */
export function observe(ctx) {
  if (!ctx.rawHostname || ctx.isIpHost) return [];

  const raw = ctx.rawHostname;
  const confusableChars = [...new Set([...raw].filter((ch) => CONFUSABLES_MAP[ch]))];
  const scripts = detectScripts(raw);
  const hasMixedScript = scripts.has('latin') && scripts.size > 1;

  if (!hasMixedScript) return [];

  return [
    {
      observationId: id,
      category: 'HOST_ENCODING',
      data: {
        scriptsPresent: [...scripts],
        confusableCharacters: confusableChars.map((ch) => ({ char: ch, mimics: CONFUSABLES_MAP[ch] })),
      },
      evidence: confusableChars.length > 0 ? confusableChars : [...scripts],
      // Higher confidence when a KNOWN confusable substitution was found
      // (a documented lookalike, not just "two scripts happen to be
      // present," which occasionally has legitimate cases).
      confidence: confusableChars.length > 0 ? 0.95 : 0.7,
      meta: { sourceRule: id, ruleVersion },
    },
  ];
}
