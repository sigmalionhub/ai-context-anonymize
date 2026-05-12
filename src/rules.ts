import type { DetectorRule } from "./types.ts";
import { EntityCategory, SecurityLevel } from "./types.ts";
import { btcAddressCheck, ethAddressCheck, ibanCheck, luhnCheck, rnokkpCheck } from "./validators.ts";

const M = SecurityLevel.MASK;
const B = SecurityLevel.BLOCK;

const RNOKKP: DetectorRule = {
  name: "UA_RNOKKP",
  category: EntityCategory.IDENTITY,
  level: M,
  patterns: [/\b([1-9]\d{9})\b/g],
  validate: rnokkpCheck,
};

const UA_PASSPORT: DetectorRule = {
  name: "UA_PASSPORT",
  category: EntityCategory.IDENTITY,
  level: M,
  patterns: [/\b([А-ЯҐЄІЇ]{2}\s?\d{6})\b/gu],
};

const US_SSN: DetectorRule = {
  name: "US_SSN",
  category: EntityCategory.IDENTITY,
  level: B,
  patterns: [/\b(\d{3}[-\s]\d{2}[-\s]\d{4})\b/g],
};

const CREDIT_CARD: DetectorRule = {
  name: "CREDIT_CARD",
  category: EntityCategory.FINANCIAL,
  level: B,
  patterns: [/\b(\d{4}[\s\-]?\d{4}[\s\-]?\d{4}[\s\-]?\d{1,7})\b/g],
  validate: luhnCheck,
};

const IBAN: DetectorRule = {
  name: "IBAN",
  category: EntityCategory.FINANCIAL,
  level: M,
  patterns: [/\b(UA\d{2}[A-Z0-9]{25})\b/g, /\b([A-Z]{2}\d{2}[A-Z0-9]{11,30})\b/g],
  validate: ibanCheck,
};

const BITCOIN_ADDRESS: DetectorRule = {
  name: "BTC_ADDRESS",
  category: EntityCategory.CRYPTO,
  level: M,
  patterns: [/\b([13][a-km-zA-HJ-NP-Z1-9]{25,34})\b/g, /\b(bc1[a-z0-9]{39,59})\b/g],
  validate: btcAddressCheck,
};

const ETH_ADDRESS: DetectorRule = {
  name: "ETH_ADDRESS",
  category: EntityCategory.CRYPTO,
  level: M,
  patterns: [/(0x[0-9a-fA-F]{40})\b/g],
  validate: ethAddressCheck,
};

const PHONE_UA: DetectorRule = {
  name: "PHONE_UA",
  category: EntityCategory.PHONE,
  level: M,
  patterns: [
    /(\+380[\s\-]?\(?\d{2}\)?[\s\-]?\d{3}[\s\-]?\d{2}[\s\-]?\d{2})\b/g,
    /(\+[1-9]\d{6,14})\b/g,
    /(\b0\d{2}[\s\-]?\d{3}[\s\-]?\d{2}[\s\-]?\d{2})\b/g,
  ],
};

const EMAIL: DetectorRule = {
  name: "EMAIL",
  category: EntityCategory.EMAIL,
  level: M,
  patterns: [/([a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,})/g],
};

const OPENAI_KEY: DetectorRule = {
  name: "OPENAI_API_KEY",
  category: EntityCategory.SECRET,
  level: B,
  patterns: [
    /(sk-[a-zA-Z0-9]{20,60}T3BlbkFJ[a-zA-Z0-9]{20,60})/g,
    /(sk-proj-[a-zA-Z0-9\-_]{40,120})/g,
    /(sk-svcacct-[a-zA-Z0-9\-_]{40,120})/g,
  ],
};

const AWS_KEY: DetectorRule = {
  name: "AWS_ACCESS_KEY",
  category: EntityCategory.SECRET,
  level: B,
  patterns: [/\b((?:AKIA|AROA|ASIA|ABIA|ACCA)[A-Z0-9]{16})\b/g],
};

const AWS_SECRET: DetectorRule = {
  name: "AWS_SECRET_KEY",
  category: EntityCategory.SECRET,
  level: B,
  patterns: [/(?:aws[_\-\s]?secret[_\-\s]?(?:access[_\-\s]?)?key\s*[=:]\s*)([A-Za-z0-9/+=]{40})/gi],
};

const AZURE_TOKEN: DetectorRule = {
  name: "AZURE_TOKEN",
  category: EntityCategory.SECRET,
  level: B,
  patterns: [
    /(?:DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=)([A-Za-z0-9+/=]{88})/g,
    /\b(sv=\d{4}-\d{2}-\d{2}&[^&\s"']{20,})/g,
  ],
};

const STRIPE_KEY: DetectorRule = {
  name: "STRIPE_SECRET_KEY",
  category: EntityCategory.SECRET,
  level: B,
  patterns: [/(sk_live_[a-zA-Z0-9]{24,99})/g, /(rk_live_[a-zA-Z0-9]{24,99})/g],
};

const BEARER_TOKEN: DetectorRule = {
  name: "BEARER_TOKEN",
  category: EntityCategory.SECRET,
  level: B,
  patterns: [/(?:Bearer\s+)([A-Za-z0-9\-_.~+/=]{20,})/gi],
};

const RSA_PRIVATE_KEY: DetectorRule = {
  name: "RSA_PRIVATE_KEY",
  category: EntityCategory.SECRET,
  level: B,
  patterns: [/-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----[\s\S]+?-----END (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----/g],
};

const SSH_PRIVATE_KEY: DetectorRule = {
  name: "SSH_PRIVATE_KEY",
  category: EntityCategory.SECRET,
  level: B,
  patterns: [/-----BEGIN OPENSSH PRIVATE KEY-----[\s\S]+?-----END OPENSSH PRIVATE KEY-----/g],
};

const DB_CONNECTION: DetectorRule = {
  name: "DB_CONNECTION_STRING",
  category: EntityCategory.DATABASE,
  level: B,
  patterns: [/\b((?:postgresql|postgres|mysql|mariadb|mongodb(?:\+srv)?|mssql|redis|amqp(?:s)?):\/\/[^\s"'<>]{8,})/gi],
};

const PASSWORD_ASSIGNMENT: DetectorRule = {
  name: "PASSWORD_IN_TEXT",
  category: EntityCategory.SECRET,
  level: B,
  patterns: [/(?:password|passwd|pwd|secret)\s*[=:]\s*["']?([^\s"',;]{8,})["']?/gi],
};

const GITHUB_TOKEN: DetectorRule = {
  name: "GITHUB_TOKEN",
  category: EntityCategory.SECRET,
  level: B,
  patterns: [/(gh[pousr]_[A-Za-z0-9]{36,})/g],
};

const JWT_TOKEN: DetectorRule = {
  name: "JWT_TOKEN",
  category: EntityCategory.SECRET,
  level: B,
  patterns: [/\b(eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})\b/g],
};

const GOOGLE_API_KEY: DetectorRule = {
  name: "GOOGLE_API_KEY",
  category: EntityCategory.SECRET,
  level: B,
  patterns: [/\b(AIza[0-9A-Za-z\-_]{35})\b/g],
};

const NPM_TOKEN: DetectorRule = {
  name: "NPM_TOKEN",
  category: EntityCategory.SECRET,
  level: B,
  patterns: [/(npm_[A-Za-z0-9]{36})/g],
};

export const BUILT_IN_RULES: readonly DetectorRule[] = Object.freeze([
  RNOKKP,
  UA_PASSPORT,
  US_SSN,
  CREDIT_CARD,
  IBAN,
  BITCOIN_ADDRESS,
  ETH_ADDRESS,
  PHONE_UA,
  EMAIL,
  OPENAI_KEY,
  AWS_KEY,
  AWS_SECRET,
  AZURE_TOKEN,
  STRIPE_KEY,
  BEARER_TOKEN,
  RSA_PRIVATE_KEY,
  SSH_PRIVATE_KEY,
  DB_CONNECTION,
  PASSWORD_ASSIGNMENT,
  GITHUB_TOKEN,
  JWT_TOKEN,
  GOOGLE_API_KEY,
  NPM_TOKEN,
]);
