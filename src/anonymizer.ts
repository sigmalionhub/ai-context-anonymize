import type { AnonymizerConfig, ProtectResult } from "./types.ts";
import { buildRules, collectMatches, applyMatches } from "./engine.ts";

export class Anonymizer {
  private readonly rules: ReturnType<typeof buildRules>;
  private readonly redactPlaceholder: string;
  private readonly nonceProvider: () => string;

  constructor(config: AnonymizerConfig = {}) {
    this.rules = buildRules(config);
    this.redactPlaceholder = config.redactPlaceholder ?? "«REDACTED»";
    this.nonceProvider = config.nonceProvider ?? (() => Math.random().toString(36).slice(2, 7));
  }

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

  restore(text: string, map: Map<string, string>): string {
    let result = text;
    for (const [token, original] of map) {
      result = result.replaceAll(token, original);
    }
    return result;
  }
}
