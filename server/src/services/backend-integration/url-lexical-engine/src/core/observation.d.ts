/**
 * PART 4 — The standardized Observation contract.
 *
 * Every rule in src/rules/ exports observe(ctx), which ALWAYS returns
 * Observation[] — possibly empty, never null, never a single bare object.
 *
 * This is stricter than v1's `finding | null` on purpose. Auditing the v1
 * rules during this migration surfaced a real bug: several rules (the
 * clearest example is subdomain-abuse detection) used if/else branching
 * across severities to decide which ONE finding to return, which silently
 * dropped a second, independently-true fact whenever both applied at once
 * (e.g. a hostname that is BOTH a deceptive hyphenated label AND has
 * excessive subdomain depth — v1 only ever reported one, never both).
 * Returning an array removes that false choice: a rule can report every
 * independent fact it actually observed, and it's the Risk Engine's job —
 * not the rule's — to decide how co-occurring facts should be weighed
 * together.
 */

export type ObservationCategory =
  | 'HOST_IDENTITY'       // what kind of thing the host is (IP, domain, etc.)
  | 'HOST_STRUCTURE'      // subdomain depth, length, structural shape
  | 'HOST_ENCODING'       // punycode, unicode, homograph — encoding-level facts
  | 'BRAND_SIGNAL'        // brand name presence or similarity
  | 'PATH_QUERY'          // findings in the path/query string, not the host
  | 'TRANSPORT'           // protocol, port
  | 'REPUTATION_HINT';    // shorteners, known-abused patterns

export interface Observation {
  /**
   * Stable, unique identifier for WHAT WAS OBSERVED — not a severity, not a
   * verdict. Matches the originating rule's id 1:1 for traceability.
   * Example: "IP_ADDRESS_HOST", "BRAND_TOKEN_MISMATCH", "HIGH_ENTROPY_LABEL"
   */
  observationId: string;

  /** Which of the fixed categories above this observation belongs to —
   *  lets the Correlation/Risk Engines group and reason about related
   *  signals without string-matching on observationId. */
  category: ObservationCategory;

  /**
   * The raw, structured, machine-readable facts this observation is built
   * from. This is intentionally free-form per observation type (a
   * TypeScript union or generics could type this per-rule if desired) —
   * what matters is that it contains NUMBERS, STRINGS, BOOLEANS describing
   * reality, never an adjective describing how bad it is.
   */
  data: Record<string, unknown>;

  /**
   * The literal substring(s)/value(s) from the URL that a human (or the
   * Explanation Engine) would need to see to verify this observation
   * themselves. Always derived from ctx, never invented.
   */
  evidence: string[];

  /**
   * How certain the engine is that this observation is CORRECTLY
   * IDENTIFIED — not how dangerous it is. 1.0 for a deterministic syntactic
   * fact (e.g. "this literally is an IP address" — undeniable). Lower for
   * heuristic/fuzzy observations (e.g. entropy-based randomness detection,
   * where the underlying math has a real false-positive rate).
   * Range: 0.0–1.0.
   */
  confidence: number;

  /**
   * Which rule module produced this, and when the observation logic itself
   * was last meaningfully changed — NOT a scan timestamp (analyzer.js owns
   * that). Lets the Risk Engine's future ML layer track which rule
   * version produced which training examples.
   */
  meta: {
    sourceRule: string; // matches rules/index.js's registered id
    ruleVersion: string; // semver of the rule's logic, bumped on any behavior change
  };
}

/**
 * Every rule module in src/rules/ must export a function matching this
 * signature. Always returns an array — empty if nothing was observed,
 * never null, never a single bare object.
 */
export type ObserveFn = (ctx: import('./parser.js').ParsedUrlContext) => Observation[];
