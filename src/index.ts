import { Anonymizer } from "./anonymizer.ts";
import type { AnonymizerConfig, ProtectResult } from "./types.ts";

export { Anonymizer } from "./anonymizer.ts";
export { StreamingAnonymizer } from "./streaming.ts";
export type { StreamWriteResult } from "./streaming.ts";
export { BUILT_IN_RULES } from "./rules.ts";
export type { AnonymizerConfig, DetectorRule, ProtectResult } from "./types.ts";
export { EntityCategory, SecurityLevel } from "./types.ts";
export { btcAddressCheck, ethAddressCheck, ibanCheck, luhnCheck, rnokkpCheck } from "./validators.ts";

const _default = new Anonymizer();

/**
 * Scan `text` for PII/secrets and replace them with reversible tokens.
 *
 * @param text - Raw input that may contain sensitive data.
 * @param config - Optional rule configuration. Passing a config creates a
 *   new `Anonymizer` instance; omit it (or reuse an `Anonymizer` instance)
 *   for repeated calls in a hot path.
 * @returns A `ProtectResult` with the safe text, a restore map, and safety flags.
 *
 * @example
 * const { protectedText, map, isSafe } = protect("Call me at +380501234567");
 * if (!isSafe) throw new Error("BLOCK rule fired");
 * const llmResponse = await callLLM(protectedText);
 * const answer = restore(llmResponse, map);
 */
export function protect(text: string, config?: AnonymizerConfig): ProtectResult {
  return config ? new Anonymizer(config).protect(text) : _default.protect(text);
}

/**
 * Replace every token in `text` with its original value using `map`.
 *
 * @param text - LLM response containing `«token»` placeholders.
 * @param map - The `map` from the corresponding `protect()` result.
 * @returns The de-anonymized string.
 */
export function restore(text: string, map: Map<string, string>): string {
  return _default.restore(text, map);
}

/**
 * Convert a token→value `Map` to a plain object for JSON serialization.
 *
 * @example
 * const json = JSON.stringify(mapToRecord(result.map));
 */
export function mapToRecord(map: Map<string, string>): Record<string, string> {
  return Object.fromEntries(map);
}
