# ai-context-anonymize

PII masking and DLP library for LLM pipelines. Detects sensitive data in text before it reaches a language model, replaces it with reversible tokens, and restores original values in the model's response.

Zero runtime dependencies. TypeScript-first.

## The problem it solves

When users send messages to an LLM they often include emails, phone numbers, IBANs, passport data, API keys, and database credentials. Sending this data to a third-party API violates GDPR and creates security risks.

This library sits between your app and the LLM:

```
user input → protect() → LLM → restore() → final response
```

- **MASK** — replaces PII with a reversible token (`«em1»`, `«ph1»`, `«fin1»`). The LLM works with tokens and returns them in the response. You restore the original values after.
- **REDACT** — replaces with `«REDACTED»`. Irreversible. For data that must not reach the model.
- **BLOCK** — sets `isSafe: false`. The request must not be sent to the LLM at all. For secrets and credentials.

## Install

```bash
npm install ai-context-anonymize
```

## Quick start

```ts
import { protect, restore } from "ai-context-anonymize";

const result = protect("Send the invoice to anna@company.ua, call +380 67 123 45 67.");

if (!result.isSafe) {
  console.error("Blocked:", result.violations);
  process.exit(1);
}

// result.protectedText → "Send the invoice to «em1», call «ph1»."
const llmResponse = await callLLM(result.protectedText);

// restore original values in the model's answer
const finalResponse = restore(llmResponse, result.map);
```

## API

### `protect(text, config?)`

Scans the text and returns a `ProtectResult`:

```ts
interface ProtectResult {
  protectedText: string;           // safe to send to LLM
  map: Map<string, string>;        // token → original value
  isSafe: boolean;                 // false = do not send to LLM
  violations: string[];            // names of BLOCK rules that fired
}
```

```ts
const result = protect("Transfer to UA213223130000026007233566001");
// result.isSafe        → true
// result.protectedText → "Transfer to «fin1»"
// result.map           → Map { "«fin1»" → "UA213223130000026007233566001" }
```

Blocked example:

```ts
const result = protect("password=s3cr3t123");
// result.isSafe      → false
// result.violations  → ["PASSWORD_IN_TEXT"]
// result.map         → Map {} (empty — nothing was sent)
```

### `restore(text, map)`

Replaces tokens in the LLM response with original values:

```ts
const final = restore("I will contact «em1» tomorrow.", result.map);
// → "I will contact anna@company.ua tomorrow."
```

### `new Anonymizer(config?)`

Use the class directly when you need custom rules or a non-default configuration:

```ts
import { Anonymizer, EntityCategory, SecurityLevel } from "ai-context-anonymize";

const anon = new Anonymizer({
  rules: [
    {
      name: "ORDER_ID",
      category: EntityCategory.IDENTITY,
      level: SecurityLevel.MASK,
      patterns: [/ORD-\d{6}/g],
    },
  ],
});

const result = anon.protect("Order ORD-123456 is ready.");
const response = anon.restore(llmText, result.map);
```

#### Config options

| Option | Type | Description |
|---|---|---|
| `rules` | `DetectorRule[]` | Additional rules merged on top of built-ins |
| `replaceBuiltinRules` | `boolean` | When `true`, use only `rules` — discard built-ins |
| `redactPlaceholder` | `string` | Custom placeholder for REDACT. Default: `«REDACTED»` |

## Built-in detectors

### MASK — anonymized, reversible

| Rule | Examples |
|---|---|
| `UA_RNOKKP` | `1234567899` (checksum-validated) |
| `UA_PASSPORT` | `АБ 123456` |
| `IBAN` | `UA213223130000026007233566001`, `DE89370400440532013000` |
| `BTC_ADDRESS` | P2PKH, P2SH, Bech32 |
| `ETH_ADDRESS` | `0x742d35Cc6634C0532925a3b844Bc454e4438f44e` |
| `PHONE_UA` | `+380 67 123 45 67`, `067 123 45 67` |
| `EMAIL` | `user@example.com` |

### BLOCK — request is rejected, `isSafe: false`

| Rule | What it catches |
|---|---|
| `US_SSN` | `123-45-6789` |
| `CREDIT_CARD` | 13–19 digit numbers, Luhn-validated |
| `OPENAI_API_KEY` | `sk-proj-…`, `sk-svcacct-…` |
| `AWS_ACCESS_KEY` | `AKIA…`, `AROA…` |
| `AWS_SECRET_KEY` | `aws_secret_key = …` |
| `AZURE_TOKEN` | Connection strings, SAS tokens |
| `STRIPE_SECRET_KEY` | `sk_live_…`, `rk_live_…` |
| `GITHUB_TOKEN` | `ghp_…`, `gho_…`, `ghu_…` |
| `GOOGLE_API_KEY` | `AIza…` |
| `NPM_TOKEN` | `npm_…` |
| `BEARER_TOKEN` | `Authorization: Bearer …` |
| `RSA_PRIVATE_KEY` | PEM blocks (RSA, EC, DSA, OpenSSH) |
| `SSH_PRIVATE_KEY` | OpenSSH private key blocks |
| `DB_CONNECTION_STRING` | `postgresql://…`, `mongodb://…`, `redis://…` |
| `JWT_TOKEN` | Three-part base64url tokens |
| `PASSWORD_IN_TEXT` | `password=…`, `token=…`, `secret:…` |

## Custom rules

```ts
import { Anonymizer, EntityCategory, SecurityLevel } from "ai-context-anonymize";

const anon = new Anonymizer({
  rules: [
    {
      name: "INTERNAL_TOKEN",
      category: EntityCategory.SECRET,
      level: SecurityLevel.REDACT,
      patterns: [/INT-[A-Z0-9]{16}/g],
    },
  ],
});
```

To replace all built-in rules:

```ts
const anon = new Anonymizer({
  replaceBuiltinRules: true,
  rules: [myRule1, myRule2],
});
```

Custom validators:

```ts
const anon = new Anonymizer({
  rules: [
    {
      name: "MY_ID",
      category: EntityCategory.IDENTITY,
      level: SecurityLevel.MASK,
      patterns: [/\d{8}/g],
      validate: (raw) => raw.startsWith("42"), // extra check after regex
    },
  ],
});
```

## Validators (exported)

The checksum validators used internally are also exported for standalone use:

```ts
import { luhnCheck, ibanCheck, rnokkpCheck, btcAddressCheck, ethAddressCheck } from "ai-context-anonymize";

luhnCheck("4532015112830366");     // true
ibanCheck("DE89370400440532013000"); // true
rnokkpCheck("1234567899");         // true
```

## Security levels

| Level | Behavior | `isSafe` | Token in map |
|---|---|---|---|
| `MASK` | Replaced with `«em1»`, `«ph1»`, etc. | `true` | yes |
| `REDACT` | Replaced with `«REDACTED»` | `true` | no |
| `BLOCK` | Text unchanged, request must be aborted | `false` | no |

## License

MIT
