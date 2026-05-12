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

export function protect(text: string, config?: AnonymizerConfig): ProtectResult {
  return config ? new Anonymizer(config).protect(text) : _default.protect(text);
}

export function restore(text: string, map: Map<string, string>): string {
  return _default.restore(text, map);
}

export function mapToRecord(map: Map<string, string>): Record<string, string> {
  return Object.fromEntries(map);
}
