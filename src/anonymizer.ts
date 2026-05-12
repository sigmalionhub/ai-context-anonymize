import type { AnonymizerConfig, ProtectResult } from "./types.ts";
import { buildRules, collectMatches, applyMatches } from "./engine.ts";

/**
 * Stateful anonymizer that compiles rules once and reuses them across calls.
 * Prefer this class over the top-level `protect()` when using custom config
 * in a loop to avoid recompiling rules on every invocation.
 *
 * @example
 * const anon = new Anonymizer({ rules: [myRule], replaceBuiltinRules: true });
 * const { protectedText, map } = anon.protect(userInput);
 */
export class Anonymizer {
  private readonly rules: ReturnType<typeof buildRules>;
  private readonly redactPlaceholder: string;
  private readonly nonceProvider: () => string;

  constructor(config: AnonymizerConfig = {}) {
    this.rules = buildRules(config);
    this.redactPlaceholder = config.redactPlaceholder ?? "«REDACTED»";
    this.nonceProvider = config.nonceProvider ?? (() => Math.random().toString(36).slice(2, 7));
  }

  /**
   * Scan `rawText` for PII/secrets and replace them with reversible tokens.
   * Input is NFC-normalized before matching to prevent homoglyph bypass.
   */
  protect(rawText: string): ProtectResult {
    const text = rawText.normalize("NFC");
    const allMatches = collectMatches(text, this.rules);
    const state = {
      valueToToken: new Map<string, string>(),
      tokenToValue: new Map<string, string>(),
      counters: new Map(),
      nonce: this.nonceProvider(),
    };
    const { output, violations } = applyMatches(text, allMatches, state, this.redactPlaceholder);
    if (violations.length > 0) {
      return { protectedText: "", map: new Map(), isSafe: false, violations };
    }
    return { protectedText: output, map: state.tokenToValue, isSafe: true, violations: [] };
  }

  /**
   * Replace every token in `text` with its original value from `map`.
   * `map` must be the one returned by the corresponding `protect()` call.
   */
  restore(text: string, map: Map<string, string>): string {
    let result = text;
    for (const [token, original] of map) {
      result = result.replaceAll(token, original);
    }
    return result;
  }
}
