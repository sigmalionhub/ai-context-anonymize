import type { AnonymizerConfig, DetectorRule, EntityCategory } from "./types.ts";
import { SecurityLevel } from "./types.ts";
import { BUILT_IN_RULES } from "./rules.ts";

export interface CompiledRule extends DetectorRule {
  readonly _compiled: readonly RegExp[];
}

export interface MatchRecord {
  start: number;
  end: number;
  original: string;
  rule: DetectorRule;
}

export interface ApplyState {
  valueToToken: Map<string, string>;
  tokenToValue: Map<string, string>;
  counters: Map<EntityCategory, number>;
  nonce: string;
}

function compile(rules: readonly DetectorRule[]): readonly CompiledRule[] {
  return rules.map(rule => ({
    ...rule,
    _compiled: rule.patterns.map(p => {
      let flags = p.flags;
      if (!flags.includes("g")) flags += "g";
      if (!flags.includes("d")) flags += "d";
      return new RegExp(p.source, flags);
    }),
  }));
}

export function buildRules(config: AnonymizerConfig): readonly CompiledRule[] {
  if (config.replaceBuiltinRules === true) {
    if (!config.rules?.length) {
      throw new Error("ai-context-anonymize: replaceBuiltinRules=true but config.rules is empty.");
    }
    return compile(config.rules);
  }
  return compile(config.rules ? [...BUILT_IN_RULES, ...config.rules] : BUILT_IN_RULES);
}

export function collectMatches(text: string, rules: readonly CompiledRule[]): MatchRecord[] {
  const records: MatchRecord[] = [];
  for (const rule of rules) {
    for (const re of rule._compiled) {
      re.lastIndex = 0;
      let m: RegExpExecArray | null;
      while ((m = re.exec(text)) !== null) {
        const indices = m.indices!;
        const span = (indices[1] ?? indices[0])!;
        const [start, end] = span;
        const raw = m[1] ?? m[0];
        if (rule.validate && !rule.validate(raw)) continue;
        records.push({ start, end, original: raw, rule });
      }
    }
  }
  return records;
}

export function resolveOverlaps(records: MatchRecord[]): MatchRecord[] {
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

export function applyMatches(
  text: string,
  allMatches: MatchRecord[],
  state: ApplyState,
  redactPlaceholder: string,
): { output: string; violations: string[] } {
  const seen = new Set<string>();
  const violations: string[] = [];
  for (const m of allMatches) {
    if (m.rule.level === SecurityLevel.BLOCK && !seen.has(m.rule.name)) {
      seen.add(m.rule.name);
      violations.push(m.rule.name);
    }
  }
  if (violations.length > 0) return { output: "", violations };

  const matches = resolveOverlaps(allMatches);
  const sorted = [...matches].sort((a, b) => b.start - a.start);
  let result = text;

  for (const m of sorted) {
    if (m.rule.level === SecurityLevel.REDACT) {
      result = result.slice(0, m.start) + redactPlaceholder + result.slice(m.end);
      continue;
    }
    let token = state.valueToToken.get(m.original);
    if (!token) {
      const prefix = m.rule.category as string;
      const count = (state.counters.get(m.rule.category) ?? 0) + 1;
      state.counters.set(m.rule.category, count);
      token = `«${prefix}${count}·${state.nonce}»`;
      state.valueToToken.set(m.original, token);
      state.tokenToValue.set(token, m.original);
    }
    result = result.slice(0, m.start) + token + result.slice(m.end);
  }
  return { output: result, violations: [] };
}
