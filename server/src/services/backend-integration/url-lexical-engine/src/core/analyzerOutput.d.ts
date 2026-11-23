/**
 * Output contract of analyze() in analyzer.js.
 *
 * analyze() never throws on bad input: an unparseable URL produces a
 * LexicalAnalysisFailure, and everything else produces a LexicalAnalysisSuccess.
 */

import type { Observation } from './observation.d.ts';

export type SuggestedSeverity = 'low' | 'medium' | 'high' | 'critical';

/** An Observation annotated with suppression metadata by annotateSuppression(). */
export interface AnnotatedObservation extends Observation {
  /** observationId of the observation that makes this one redundant, if any. */
  suppressedBy?: string | null;
}

/** Human-readable rendering of one observation, produced by describe(). */
export interface LexicalFinding {
  observationId: string;
  title: string;
  description: string;
  recommendation: string;
  /** Starting point for display only. The Risk Engine computes the authoritative severity. */
  suggestedSeverity: SuggestedSeverity;
  references: string[];
  confidence: number;
  evidence: string[];
  suppressed: boolean;
  suppressedBy: string | null;
}

export interface LexicalUrlMetadata {
  protocol: string;
  hostname: string;
  registeredDomain: string;
  subdomain: string;
  tld: string;
  port: string | number | null;
  explicitPort: boolean;
  isIpHost: boolean;
  pathname: string;
  urlLength: number;
  normalizedInput: string;
}

export interface LexicalAnalysisSuccess {
  ok: true;
  engine: 'url-lexical-intelligence';
  engineVersion: string;
  /** ISO-8601 scan time */
  timestamp: string;
  sourceUrl: string;
  correlationKey: string;
  urlMetadata: LexicalUrlMetadata;
  observations: AnnotatedObservation[];
  findings: LexicalFinding[];
}

export interface LexicalAnalysisFailure {
  ok: false;
  error: string;
  raw: string;
}

export type LexicalAnalysisResult = LexicalAnalysisSuccess | LexicalAnalysisFailure;
