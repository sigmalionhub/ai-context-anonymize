/**
 * Controls what happens when a rule matches a span of text.
 * - `MASK` — replace with a reversible token (e.g. `«em1·abc12»`); included in the restore map.
 * - `REDACT` — replace with `«REDACTED»`; not restorable.
 * - `BLOCK` — abort the entire request; `protectedText` is `""` and `isSafe` is `false`.
 */
export type SecurityLevel = "MASK" | "REDACT" | "BLOCK";
export const SecurityLevel = {
  MASK: "MASK" as SecurityLevel,
  REDACT: "REDACT" as SecurityLevel,
  BLOCK: "BLOCK" as SecurityLevel,
} as const;

/** Semantic category of the entity a rule detects. Used as the token prefix (e.g. `«em1·…»`). */
export type EntityCategory = "p" | "id" | "fin" | "cry" | "ph" | "em" | "k" | "db";
export const EntityCategory = {
  PERSON:    "p"   as EntityCategory,
  IDENTITY:  "id"  as EntityCategory,
  FINANCIAL: "fin" as EntityCategory,
  CRYPTO:    "cry" as EntityCategory,
  PHONE:     "ph"  as EntityCategory,
  EMAIL:     "em"  as EntityCategory,
  SECRET:    "k"   as EntityCategory,
  DATABASE:  "db"  as EntityCategory,
} as const;

/** A single PII/secret detection rule supplied to the anonymizer. */
export interface DetectorRule {
  /** Unique rule name used in `violations` arrays and token prefixes. */
  name: string;
  /** Entity category — determines the token prefix character. */
  category: EntityCategory;
  /** What to do when this rule fires. */
  level: SecurityLevel;
  /** One or more regexes to match against the input text. */
  patterns: RegExp[];
  /**
   * Optional post-match validator (e.g. Luhn check for credit cards).
   * Return `false` to skip this match entirely.
   */
  validate?: (match: string) => boolean;
}

/** Configuration passed to `Anonymizer`, `StreamingAnonymizer`, or the top-level `protect()`. */
export interface AnonymizerConfig {
  /** Additional rules to merge with (or replace) the built-in rule set. */
  rules?: DetectorRule[];
  /** When `true`, built-in rules are discarded and only `rules` are used. */
  replaceBuiltinRules?: boolean;
  /** Text inserted in place of a REDACT match. Defaults to `«REDACTED»`. */
  redactPlaceholder?: string;
  /**
   * Factory that produces the per-call nonce embedded in every token.
   * Defaults to a random 5-character base-36 string.
   * Pass `() => "fixed"` for deterministic output in tests/snapshots.
   */
  nonceProvider?: () => string;
  /**
   * `StreamingAnonymizer` only — number of trailing characters held back
   * as an overlap guard. Must be ≥ the longest possible PII match for the
   * active rules. Defaults to `2048`.
   */
  windowSize?: number;
  /**
   * `StreamingAnonymizer` only — maximum allowed buffer length.
   * Throws if exceeded. `0` (default) means unlimited.
   */
  maxBufferSize?: number;
}

/** Return value of `protect()` and `Anonymizer#protect()`. */
export interface ProtectResult {
  /**
   * Input text with PII replaced by tokens or redaction placeholders.
   * Always `""` when `isSafe` is `false`.
   */
  protectedText: string;
  /** Token → original-value map. Pass to `restore()` after the LLM responds. */
  map: Map<string, string>;
  /** `false` when at least one BLOCK rule fired; safe to send to LLM only when `true`. */
  isSafe: boolean;
  /** Names of BLOCK rules that fired. Empty when `isSafe` is `true`. */
  violations: string[];
}
