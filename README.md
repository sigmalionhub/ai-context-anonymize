# ai-context-anonymize

PII masking and DLP library for LLM pipelines. Detects sensitive data in text before it reaches a language model, replaces it with reversible tokens, and restores original values in the model's response.

Zero runtime dependencies. TypeScript-first.

## The Problem

Every time a user sends a message to an LLM-powered feature, they risk exposing data they didn't mean to share — and your app becomes the vehicle for that leak.

Consider a typical support chat: a user pastes their IBAN to ask about a transfer, includes their email, mentions their tax ID. Your app forwards that message verbatim to OpenAI or Anthropic. That data now leaves your infrastructure, gets logged, potentially used for training, and is subject to the data retention policies of a third party you don't control.

Now multiply that by API keys accidentally pasted into prompts, database connection strings included in error messages, passwords in "can you help me fix this config" requests.

**The risks:**

- **GDPR violation** — personal data (emails, phone numbers, national IDs) sent to a third-party processor without a legal basis
- **Secret leakage** — API keys, credentials, and private keys sent to an external API and stored in its logs
- **Data residency** — PII leaving a jurisdiction it's not allowed to leave

The standard advice is "tell users not to paste sensitive data." That doesn't work. Users don't read warnings, and they shouldn't have to think about your infrastructure when asking for help.

## How it works

This library sits between your app and the LLM:

```
user input → protect() → LLM → restore() → final response
```

- **MASK** — replaces PII with a reversible token (`«em1·…»`, `«ph1·…»`). The LLM works with tokens and returns them in the response. You restore original values after.
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

// result.protectedText → "Send the invoice to «em1·…», call «ph1·…»."
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
// result.protectedText → "Transfer to «fin1·…»"
// result.map           → Map { "«fin1·…»" → "UA213223130000026007233566001" }
```

Blocked example:

```ts
const result = protect("password=s3cr3t123");
// result.isSafe        → false
// result.protectedText → ""  (never exposes the original text)
// result.violations    → ["PASSWORD_IN_TEXT"]
// result.map           → Map {} (empty — nothing was sent)
```

### `restore(text, map)`

Replaces tokens in the LLM response with original values:

```ts
const final = restore("I will contact «em1·…» tomorrow.", result.map);
// → "I will contact anna@company.ua tomorrow."
```

### `mapToRecord(map)`

Converts the token map to a plain object for JSON serialization:

```ts
import { protect, mapToRecord } from "ai-context-anonymize";

const result = protect("Contact user@example.com");
const serializable = mapToRecord(result.map);
// → { "«em1·…»": "user@example.com" }
JSON.stringify(serializable); // safe
```

### `new Anonymizer(config?)`

Use the class directly when you need custom rules or a shared instance for multiple calls:

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

### `new StreamingAnonymizer(config?)`

Processes LLM output token-by-token without buffering the full response. Useful when working with streaming APIs (OpenAI, Anthropic, etc.):

```ts
import { StreamingAnonymizer, restore } from "ai-context-anonymize";

const stream = new StreamingAnonymizer({ windowSize: 512 });
let fullOutput = "";

for await (const chunk of llmStream) {
  const { output, isSafe, violations } = stream.write(chunk);
  if (!isSafe) {
    console.error("Secret detected mid-stream:", violations);
    break;
  }
  fullOutput += output;
  forwardToUser(output); // safe to send immediately
}

const final = stream.flush(); // process remaining buffer
if (!final.isSafe) {
  console.error("Secret detected at end:", final.violations);
} else {
  fullOutput += final.protectedText;
  forwardToUser(final.protectedText);
}

// restore original values in the full response
const restored = restore(fullOutput, final.map);
```

**How the window works:** `StreamingAnonymizer` holds the last `windowSize` characters in a pending buffer — a span large enough to contain any possible PII match. Text that has moved beyond that window is confirmed safe and emitted by `write()`. The remaining buffer is flushed at the end.

**`windowSize` guidance:** default is `2048`, which covers all built-in rules except 4096-bit RSA private keys (~3.5 KB). Raise it if you enable rules that match longer spans.

**BLOCK in streaming:** if a BLOCK pattern is fully within the emitted zone, `write()` returns `isSafe: false` immediately and all subsequent `write()` calls return empty. If the pattern falls within the pending buffer, it is caught by `flush()`. Output already forwarded from previous `write()` calls cannot be recalled — handle `isSafe: false` by closing the connection.

#### Config options

| Option | Type | Default | Description |
|---|---|---|---|
| `rules` | `DetectorRule[]` | — | Additional rules merged on top of built-ins |
| `replaceBuiltinRules` | `boolean` | `false` | When `true`, use only `rules` — discard built-ins |
| `redactPlaceholder` | `string` | `«REDACTED»` | Custom placeholder for REDACT level |
| `nonceProvider` | `() => string` | `Math.random` | Token nonce source. Pass a fixed function for deterministic output in tests |
| `windowSize` | `number` | `2048` | Pending buffer size for `StreamingAnonymizer` (chars) |
| `maxBufferSize` | `number` | `0` (unlimited) | Hard cap on `StreamingAnonymizer` buffer. Throws if exceeded. |

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
| `DB_CONNECTION_STRING` | `postgresql://…`, `mongodb://…`, `redis://…` |
| `JWT_TOKEN` | Three-part base64url tokens |
| `PASSWORD_IN_TEXT` | `password=…`, `secret:…` |

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

Custom validator (runs after the regex, return `false` to discard the match):

```ts
const anon = new Anonymizer({
  rules: [
    {
      name: "MY_ID",
      category: EntityCategory.IDENTITY,
      level: SecurityLevel.MASK,
      patterns: [/\d{8}/g],
      validate: (raw) => raw.startsWith("42"),
    },
  ],
});
```

## Validators (exported)

The checksum validators used internally are also exported for standalone use:

```ts
import { luhnCheck, ibanCheck, rnokkpCheck, btcAddressCheck, ethAddressCheck } from "ai-context-anonymize";

luhnCheck("4532015112830366");        // true
ibanCheck("DE89370400440532013000"); // true
rnokkpCheck("1234567899");           // true
```

## Security levels

| Level | Behavior | `isSafe` | Token in map |
|---|---|---|---|
| `MASK` | Replaced with `«em1·…»`, `«ph1·…»`, etc. | `true` | yes |
| `REDACT` | Replaced with `«REDACTED»` | `true` | no |
| `BLOCK` | `protectedText: ""`, request must be aborted | `false` | no |

## License

MIT
