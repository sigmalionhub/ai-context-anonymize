import type { AnonymizerConfig, DetectorRule, ProtectResult } from "./types.ts";
import { EntityCategory, SecurityLevel } from "./types.ts";
import { BUILT_IN_RULES } from "./rules.ts";

interface MatchRecord {
  start: number;
  end: number;
  original: string;
  rule: DetectorRule;
}

type CategoryCounters = Map<EntityCategory, number>;

export class Anonymizer {
  private readonly rules: readonly DetectorRule[];
  private readonly redactPlaceholder: string;

  constructor(config: AnonymizerConfig = {}) {
    if (config.replaceBuiltinRules === true) {
      if (!config.rules?.length) {
        throw new Error("ai-context-anonymize: replaceBuiltinRules=true but config.rules is empty.");
      }
      this.rules = config.rules;
    } else {
      this.rules = config.rules ? [...BUILT_IN_RULES, ...config.rules] : BUILT_IN_RULES;
    }
    this.redactPlaceholder = config.redactPlaceholder ?? "«REDACTED»";
  }

  protect(text: string): ProtectResult {
    const allMatches = this._collectAllMatches(text);

    const violations: string[] = [];
    for (const m of allMatches) {
      if (m.rule.level === SecurityLevel.BLOCK && !violations.includes(m.rule.name)) {
        violations.push(m.rule.name);
      }
    }

    if (violations.length > 0) {
      return { protectedText: text, map: new Map(), isSafe: false, violations };
    }

    const matches = this._resolveOverlaps(allMatches);
    const valueToToken = new Map<string, string>();
    const tokenToValue = new Map<string, string>();
    const counters: CategoryCounters = new Map();

    const sorted = [...matches].sort((a, b) => b.start - a.start);
    let result = text;

    for (const m of sorted) {
      if (m.rule.level === SecurityLevel.REDACT) {
        result = result.slice(0, m.start) + this.redactPlaceholder + result.slice(m.end);
        continue;
      }

      let token = valueToToken.get(m.original);
      if (!token) {
        const prefix = m.rule.category as string;
        const count = (counters.get(m.rule.category) ?? 0) + 1;
        counters.set(m.rule.category, count);
        token = `«${prefix}${count}»`;
        valueToToken.set(m.original, token);
        tokenToValue.set(token, m.original);
      }
      result = result.slice(0, m.start) + token + result.slice(m.end);
    }

    return { protectedText: result, map: tokenToValue, isSafe: true, violations: [] };
  }

  restore(text: string, map: Map<string, string>): string {
    let result = text;
    for (const [token, original] of map) {
      const escaped = token.replaceAll(/[.*+?^${}()|[\]\\]/g, "\\$&");
      result = result.replaceAll(new RegExp(escaped, "g"), () => original);
    }
    return result;
  }

  private _collectAllMatches(text: string): MatchRecord[] {
    const records: MatchRecord[] = [];

    for (const rule of this.rules) {
      for (const pattern of rule.patterns) {
        const flags = pattern.flags.includes("g") ? pattern.flags : pattern.flags + "g";
        const re = new RegExp(pattern.source, flags);
        let m: RegExpExecArray | null;

        while ((m = re.exec(text)) !== null) {
          const raw = m[1] ?? m[0];
          const start = m.index + m[0].indexOf(raw);
          const end = start + raw.length;
          if (rule.validate && !rule.validate(raw)) continue;
          records.push({ start, end, original: raw, rule });
        }
      }
    }

    return records;
  }

  private _resolveOverlaps(records: MatchRecord[]): MatchRecord[] {
    const sorted = [...records].sort((a, b) => a.start - b.start || b.end - a.end);
    const result: MatchRecord[] = [];
    let lastEnd = -1;

    for (const rec of sorted) {
      if (rec.start >= lastEnd) {
        result.push(rec);
        lastEnd = rec.end;
      }
    }

    return result;
  }
}
