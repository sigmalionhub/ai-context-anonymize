export type SecurityLevel = "MASK" | "REDACT" | "BLOCK";
export const SecurityLevel = {
  MASK: "MASK" as SecurityLevel,
  REDACT: "REDACT" as SecurityLevel,
  BLOCK: "BLOCK" as SecurityLevel,
} as const;

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

export interface DetectorRule {
  name: string;
  category: EntityCategory;
  level: SecurityLevel;
  patterns: RegExp[];
  validate?: (match: string) => boolean;
}

export interface AnonymizerConfig {
  rules?: DetectorRule[];
  replaceBuiltinRules?: boolean;
  redactPlaceholder?: string;
  nonceProvider?: () => string;
  windowSize?: number;
  maxBufferSize?: number;
}

export interface ProtectResult {
  protectedText: string;
  map: Map<string, string>;
  isSafe: boolean;
  violations: string[];
}
