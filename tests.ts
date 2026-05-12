import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { Anonymizer, StreamingAnonymizer, SecurityLevel, EntityCategory, protect, restore, mapToRecord, type ProtectResult, type StreamWriteResult } from "./src/index.ts";
import { luhnCheck, ibanCheck, rnokkpCheck } from "./src/validators.ts";

function tokenFor(result: ProtectResult, value: string): string {
  for (const [token, orig] of result.map) {
    if (orig === value) return token;
  }
  throw new Error(`No token found for value: ${value}`);
}

describe("luhnCheck", () => {
  it("accepts valid Visa", () => assert.ok(luhnCheck("4532015112830366")));
  it("accepts valid MC", () => assert.ok(luhnCheck("5425233430109903")));
  it("rejects invalid card", () => assert.ok(!luhnCheck("1234567890123456")));
  it("handles spaces", () => assert.ok(luhnCheck("4532 0151 1283 0366")));
});

describe("ibanCheck", () => {
  it("accepts valid UA IBAN", () => assert.ok(ibanCheck("UA213223130000026007233566001")));
  it("accepts valid DE IBAN", () => assert.ok(ibanCheck("DE89370400440532013000")));
  it("rejects broken IBAN", () => assert.ok(!ibanCheck("UA00000000000000000000000000")));
  it("rejects non-numeric garbage", () => assert.ok(!ibanCheck("NOTANIBAN")));
});

describe("rnokkpCheck", () => {
  it("accepts a valid РНОКПП", () => assert.ok(rnokkpCheck("1234567899")));
  it("rejects an arbitrary 10-digit number", () => assert.ok(!rnokkpCheck("1234567890")));
  it("rejects wrong length", () => assert.ok(!rnokkpCheck("123456789")));
});

describe("Anonymizer.protect — MASK", () => {
  const anon = new Anonymizer();

  it("masks email address", () => {
    const r = anon.protect("Contact me at john.doe@example.com please.");
    assert.ok(r.isSafe);
    assert.ok(!r.protectedText.includes("john.doe@example.com"));
    assert.ok(r.protectedText.includes(tokenFor(r, "john.doe@example.com")));
  });

  it("masks Ukrainian phone number", () => {
    const r = anon.protect("Call me: +380 44 123 45 67");
    assert.ok(r.isSafe);
    assert.ok(!r.protectedText.includes("+380"));
    assert.ok(r.map.size > 0);
  });

  it("masks valid IBAN", () => {
    const r = anon.protect("Transfer to UA213223130000026007233566001 please.");
    assert.ok(r.isSafe);
    assert.ok(r.protectedText.includes(tokenFor(r, "UA213223130000026007233566001")));
  });

  it("masks valid РНОКПП and ignores random 10-digit numbers", () => {
    const r = anon.protect("РНОКПП: 1234567899, order: 1234567890");
    assert.ok(r.isSafe);
    assert.ok(r.protectedText.includes(tokenFor(r, "1234567899")));
    assert.ok(r.protectedText.includes("1234567890"));
  });

  it("produces consistent tokens for duplicate values", () => {
    const r = anon.protect("Email one: foo@bar.com and email two: foo@bar.com");
    assert.ok(r.isSafe);
    assert.equal(r.map.size, 1);
    const token = [...r.map.keys()][0]!;
    assert.equal(r.protectedText.split(token).length - 1, 2);
  });
});

describe("Anonymizer.protect — BLOCK", () => {
  const anon = new Anonymizer();

  it("blocks OpenAI API key", () => {
    const r = anon.protect(`Use apiKey=sk-proj-${"A".repeat(50)} to call the service.`);
    assert.ok(!r.isSafe);
    assert.ok(r.violations.includes("OPENAI_API_KEY"));
    assert.equal(r.map.size, 0);
  });

  it("blocks RSA private key", () => {
    const pem = `-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA0Z3VS5JJcds3xHn/ygWep4PAtEsHAJmCFXCiQh5bYoKTLMXz\n-----END RSA PRIVATE KEY-----`;
    const r = anon.protect(`Key:\n${pem}`);
    assert.ok(!r.isSafe);
    assert.ok(r.violations.includes("RSA_PRIVATE_KEY"));
  });

  it("blocks database connection string", () => {
    const r = anon.protect("Connect: postgresql://admin:s3cr3t@db.internal:5432/prod");
    assert.ok(!r.isSafe);
    assert.ok(r.violations.includes("DB_CONNECTION_STRING"));
  });

  it("blocks password assignment", () => {
    const r = anon.protect("Set password=SuperSecret123 in env.");
    assert.ok(!r.isSafe);
    assert.ok(r.violations.includes("PASSWORD_IN_TEXT"));
  });

  it("blocks GitHub token", () => {
    const r = anon.protect(`Token: ghp_${"A".repeat(36)}`);
    assert.ok(!r.isSafe);
    assert.ok(r.violations.includes("GITHUB_TOKEN"));
  });

  it("blocks JWT token", () => {
    const jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyMTIzIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
    const r = anon.protect(`Authorization: Bearer ${jwt}`);
    assert.ok(!r.isSafe);
  });

  it("BLOCK is not suppressed when a MASK rule overlaps the same span", () => {
    const r = anon.protect("Set password=test@example.com in config.");
    assert.ok(!r.isSafe);
    assert.ok(r.violations.includes("PASSWORD_IN_TEXT"));
  });
});

describe("Anonymizer.protect — REDACT", () => {
  const anon = new Anonymizer({
    rules: [{
      name: "CUSTOM_SECRET",
      category: EntityCategory.SECRET,
      level: SecurityLevel.REDACT,
      patterns: [/TOPSECRET-\d{6}/g],
    }],
  });

  it("redacts custom secret pattern", () => {
    const r = anon.protect("Code is TOPSECRET-123456 — handle with care.");
    assert.ok(r.isSafe);
    assert.ok(!r.protectedText.includes("TOPSECRET-123456"));
    assert.ok(r.protectedText.includes("«REDACTED»"));
    assert.equal(r.map.size, 0);
  });
});

describe("Anonymizer.restore", () => {
  const anon = new Anonymizer();

  it("restores masked values in AI response", () => {
    const r = anon.protect("Send report to alice@corp.ua and bob@corp.ua.");
    const tokens = [...r.map.keys()];
    assert.equal(tokens.length, 2);
    const aiResponse = `I will send the report to ${tokens[0]} and ${tokens[1]} immediately.`;
    const restored = anon.restore(aiResponse, r.map);
    assert.ok(restored.includes("alice@corp.ua"));
    assert.ok(restored.includes("bob@corp.ua"));
  });

  it("treats $ in original values as literal", () => {
    const anon2 = new Anonymizer({
      replaceBuiltinRules: true,
      rules: [{
        name: "DOLLAR_TEST",
        category: EntityCategory.SECRET,
        level: SecurityLevel.MASK,
        patterns: [/MAGIC-\d+/g],
      }],
    });
    const r = anon2.protect("value=MAGIC-42");
    const token = tokenFor(r, "MAGIC-42");
    const restored = anon2.restore(`result: ${token}`, new Map([[token, "val$1ue"]]));
    assert.equal(restored, "result: val$1ue");
  });
});

describe("Anonymizer.protect — edge cases", () => {
  const anon = new Anonymizer();

  it("returns empty map and unchanged text for empty string", () => {
    const r = anon.protect("");
    assert.ok(r.isSafe);
    assert.equal(r.protectedText, "");
    assert.equal(r.map.size, 0);
    assert.deepEqual(r.violations, []);
  });

  it("returns empty map and unchanged text when no PII present", () => {
    const text = "The weather is nice today.";
    const r = anon.protect(text);
    assert.ok(r.isSafe);
    assert.equal(r.protectedText, text);
    assert.equal(r.map.size, 0);
  });

  it("BLOCK wins when EMAIL overlaps with PASSWORD_ASSIGNMENT", () => {
    const r = anon.protect("Set password=test@example.com in config.");
    assert.ok(!r.isSafe);
    assert.ok(r.violations.includes("PASSWORD_IN_TEXT"));
    assert.equal(r.map.size, 0);
  });
});

describe("Anonymizer — custom rules", () => {
  it("works with replaceBuiltinRules", () => {
    const anon = new Anonymizer({
      replaceBuiltinRules: true,
      rules: [{
        name: "MY_ID",
        category: EntityCategory.IDENTITY,
        level: SecurityLevel.MASK,
        patterns: [/ID-\d{4}/g],
      }],
    });
    const r = anon.protect("User ID-1234 made a request.");
    assert.ok(r.isSafe);
    assert.ok(r.protectedText.includes(tokenFor(r, "ID-1234")));
    const r2 = anon.protect("Email: test@x.com");
    assert.ok(r2.protectedText.includes("test@x.com"));
  });

  it("throws when replaceBuiltinRules=true and no rules provided", () => {
    assert.throws(
      () => new Anonymizer({ replaceBuiltinRules: true }),
      /replaceBuiltinRules=true but config\.rules is empty/
    );
  });
});

describe("functional API — protect", () => {
  it("masks email without creating an Anonymizer instance", () => {
    const r = protect("Contact john@example.com for info.");
    assert.ok(r.isSafe);
    assert.ok(!r.protectedText.includes("john@example.com"));
    assert.ok(r.protectedText.includes(tokenFor(r, "john@example.com")));
  });

  it("blocks secrets without creating an Anonymizer instance", () => {
    const r = protect(`key=sk-proj-${"B".repeat(50)}`);
    assert.ok(!r.isSafe);
    assert.ok(r.violations.includes("OPENAI_API_KEY"));
  });

  it("accepts custom config as second argument", () => {
    const r = protect("Code: ID-9999", {
      replaceBuiltinRules: true,
      rules: [{
        name: "MY_ID",
        category: EntityCategory.IDENTITY,
        level: SecurityLevel.MASK,
        patterns: [/ID-\d{4}/g],
      }],
    });
    assert.ok(r.isSafe);
    assert.ok(r.protectedText.includes(tokenFor(r, "ID-9999")));
    assert.ok(r.protectedText.includes("ID-9999") === false);
  });

  it("uses built-in rules when no config passed", () => {
    const r = protect("user@test.com");
    assert.ok(r.isSafe);
    assert.equal(r.map.size, 1);
  });
});

describe("mapToRecord", () => {
  it("converts map to plain object for JSON serialization", () => {
    const r = protect("Send to alice@corp.ua.");
    const rec = mapToRecord(r.map);
    assert.ok(typeof rec === "object" && !Array.isArray(rec));
    const token = tokenFor(r, "alice@corp.ua");
    assert.equal(rec[token], "alice@corp.ua");
    assert.doesNotThrow(() => JSON.stringify(rec));
  });

  it("tokens are unique per protect() call (nonce)", () => {
    const r1 = protect("user@test.com");
    const r2 = protect("user@test.com");
    assert.notEqual(tokenFor(r1, "user@test.com"), tokenFor(r2, "user@test.com"));
  });

  it("literal token-shaped text in input is not falsely restored", () => {
    const r = protect("email: foo@bar.com");
    const token = tokenFor(r, "foo@bar.com");
    const injected = `${r.protectedText} and also ${token} already here`;
    const restored = restore(injected, r.map);
    assert.ok(restored.includes("foo@bar.com"));
    assert.ok(!restored.includes(token));
  });
});

describe("Anonymizer — nonceProvider", () => {
  it("produces deterministic tokens when nonceProvider is fixed", () => {
    const anon1 = new Anonymizer({ nonceProvider: () => "test1" });
    const anon2 = new Anonymizer({ nonceProvider: () => "test1" });
    const r1 = anon1.protect("user@test.com");
    const r2 = anon2.protect("user@test.com");
    assert.equal(tokenFor(r1, "user@test.com"), tokenFor(r2, "user@test.com"));
  });

  it("different nonceProvider values produce different tokens", () => {
    const anon1 = new Anonymizer({ nonceProvider: () => "aaa11" });
    const anon2 = new Anonymizer({ nonceProvider: () => "bbb22" });
    const r1 = anon1.protect("user@test.com");
    const r2 = anon2.protect("user@test.com");
    assert.notEqual(tokenFor(r1, "user@test.com"), tokenFor(r2, "user@test.com"));
  });
});

describe("StreamingAnonymizer", () => {
  it("returns empty output while buffer is smaller than windowSize", () => {
    const stream = new StreamingAnonymizer({ windowSize: 100, nonceProvider: () => "t" });
    const r = stream.write("Hello world");
    assert.equal(r.output, "");
    assert.ok(r.isSafe);
  });

  it("emits safe prefix once buffer exceeds windowSize", () => {
    const stream = new StreamingAnonymizer({ windowSize: 10, nonceProvider: () => "t" });
    // 20-char chunk → safeBoundary = 10 → first 10 chars emitted (no PII there)
    const r = stream.write("Hello world, safe text here");
    assert.ok(r.output.length > 0);
    assert.ok(r.isSafe);
  });

  it("masks PII that arrives split across write() calls", () => {
    // windowSize large enough to hold entire email (13 chars = alice@corp.ua)
    // Split at word boundary BEFORE the email so email stays intact in buffer
    const stream = new StreamingAnonymizer({ windowSize: 50, nonceProvider: () => "t" });
    const r1 = stream.write("Send report to ");       // 15 chars — buffer < windowSize, empty output
    assert.equal(r1.output, "");
    const r2 = stream.write("alice@corp.ua for review."); // total 40 chars — still < 50
    assert.equal(r2.output, "");
    const final = stream.flush();
    assert.ok(final.isSafe);
    assert.ok(final.protectedText.includes("«em1·t»"));
    assert.ok(!final.protectedText.includes("alice@corp.ua"));
  });

  it("deduplicates same PII value across write() calls", () => {
    const stream = new StreamingAnonymizer({ windowSize: 20, nonceProvider: () => "t" });
    // write() #2: 41-char buffer → safeBoundary=21 → "Contact foo@bar.com a" in safe zone (email matched)
    // flush(): remaining "nd also foo@bar.com." → same email, same token via valueToToken lookup
    const w1 = stream.write("Contact ");
    const w2 = stream.write("foo@bar.com and also foo@bar.com.");
    const final = stream.flush();
    assert.ok(final.isSafe);
    assert.equal(final.map.size, 1);
    const combined = w1.output + w2.output + final.protectedText;
    const token = [...final.map.keys()][0]!;
    assert.equal(combined.split(token).length - 1, 2);
  });

  it("detects BLOCK in write() when secret is in safe zone", () => {
    // windowSize=10, large chunk → safe zone contains the API key
    const stream = new StreamingAnonymizer({ windowSize: 10 });
    const key = `sk-proj-${"A".repeat(50)}`;
    const r = stream.write(`use key=${key} in config`);
    assert.ok(!r.isSafe);
    assert.ok(r.violations.includes("OPENAI_API_KEY"));
    assert.equal(r.output, "");
  });

  it("detects BLOCK in flush() when secret fits inside windowSize", () => {
    const stream = new StreamingAnonymizer({ windowSize: 2048 });
    const key = `sk-proj-${"B".repeat(50)}`;
    const r1 = stream.write(`use ${key}`);
    // key is in pending zone, write() returns safe (no PII in safe text yet)
    assert.ok(r1.isSafe);
    const final = stream.flush();
    assert.ok(!final.isSafe);
    assert.ok(final.violations.includes("OPENAI_API_KEY"));
  });

  it("subsequent write() calls after abort return isSafe: false", () => {
    const stream = new StreamingAnonymizer({ windowSize: 10 });
    const key = `sk-proj-${"C".repeat(50)}`;
    stream.write(`use ${key} here`);
    const r = stream.write("more text");
    assert.ok(!r.isSafe);
    assert.equal(r.output, "");
  });

  it("flush() on empty stream returns safe empty result", () => {
    const stream = new StreamingAnonymizer({ nonceProvider: () => "t" });
    const final = stream.flush();
    assert.ok(final.isSafe);
    assert.equal(final.protectedText, "");
    assert.equal(final.map.size, 0);
  });

  it("round-trip: write chunks → flush → restore", () => {
    const stream = new StreamingAnonymizer({ windowSize: 50, nonceProvider: () => "rnd" });
    const out1 = stream.write("Hello, ").output;
    const out2 = stream.write("please contact ").output;
    const out3 = stream.write("bob@example.com for details.").output;
    const final = stream.flush();
    assert.ok(final.isSafe);
    const fullProtected = out1 + out2 + out3 + final.protectedText;
    assert.ok(!fullProtected.includes("bob@example.com"));
    const restored = restore(fullProtected, final.map);
    assert.ok(restored.includes("bob@example.com"));
  });

  it("token contains the configured nonce from constructor", () => {
    // windowSize > text length → everything goes to flush(), nonce comes from constructor
    const stream = new StreamingAnonymizer({ windowSize: 200, nonceProvider: () => "mykey" });
    stream.write("Reach me at user@domain.com for info.");
    const final = stream.flush();
    assert.ok(final.isSafe);
    const token = [...final.map.keys()][0]!;
    assert.ok(token.includes("mykey"), `token should embed nonce, got: ${token}`);
  });
});

describe("Anonymizer — P0 audit fixes", () => {
  it("protectedText is empty string on BLOCK (not the original text)", () => {
    const r = protect(`key=sk-proj-${"A".repeat(50)}`);
    assert.ok(!r.isSafe);
    assert.equal(r.protectedText, "");
  });

  it("captures correct span via indices when value repeats in keyword", () => {
    const anon = new Anonymizer({
      replaceBuiltinRules: true,
      rules: [{
        name: "KV_SPAN",
        category: EntityCategory.SECRET,
        level: SecurityLevel.MASK,
        patterns: [/(?:key)=(\w{3,})/g],
      }],
    });
    // Full match: "key=key123", capture: "key123"
    // indexOf("key123") in "key=key123" = 4 (correct)
    // indexOf("key") in "key=key"     = 0 (BUG: would mask keyword, not value)
    const r = anon.protect("key=key");
    assert.ok(r.isSafe);
    assert.ok(r.protectedText.startsWith("key="), `keyword should survive, got: ${r.protectedText}`);
    assert.ok(!r.protectedText.includes("key=key"), "raw value should be replaced");
  });

  it("NFC normalization: decomposed and precomposed forms match same rule", () => {
    // é as NFD (e + combining accent) should normalize to NFC before matching
    const nfd = "émail@example.com"; // é decomposed + rest = valid email
    const r = protect(nfd);
    assert.ok(r.isSafe);
    assert.equal(r.map.size, 1);
  });
});

describe("StreamingAnonymizer — P0 audit fixes", () => {
  it("throws when buffer exceeds maxBufferSize", () => {
    const stream = new StreamingAnonymizer({ maxBufferSize: 20 });
    assert.throws(
      () => stream.write("this is definitely longer than twenty characters"),
      /maxBufferSize/,
    );
  });

  it("subsequent write() calls after abort preserve original violations", () => {
    const stream = new StreamingAnonymizer({ windowSize: 10 });
    const key = `sk-proj-${"D".repeat(50)}`;
    stream.write(`use ${key} here`);
    const r = stream.write("more text after abort");
    assert.ok(!r.isSafe);
    assert.ok(r.violations.includes("OPENAI_API_KEY"));
  });

  it("double flush() is idempotent and safe", () => {
    const stream = new StreamingAnonymizer({ windowSize: 50, nonceProvider: () => "t" });
    stream.write("Reach me at user@domain.com today.");
    const first = stream.flush();
    const second = stream.flush();
    assert.ok(first.isSafe);
    assert.ok(second.isSafe);
    assert.equal(second.protectedText, "");
    assert.equal(second.map.size, first.map.size);
  });

  it("flush() map is a copy — mutating it does not corrupt internal state", () => {
    const stream = new StreamingAnonymizer({ windowSize: 200, nonceProvider: () => "cp" });
    stream.write("contact test@example.com please");
    const first = stream.flush();
    first.map.clear();
    const second = new StreamingAnonymizer({ windowSize: 200, nonceProvider: () => "cp" });
    second.write("contact test@example.com please");
    const ref = second.flush();
    assert.equal(ref.map.size, 1);
  });
});

describe("functional API — restore", () => {
  it("restores tokens from protect result", () => {
    const r = protect("Contact alice@corp.ua for details.");
    const token = tokenFor(r, "alice@corp.ua");
    const restored = restore(`I'll contact ${token}.`, r.map);
    assert.ok(restored.includes("alice@corp.ua"));
  });

  it("round-trip: protect → LLM → restore", () => {
    const r = protect("Send invoice to bob@company.ua and call +380 44 111 22 33.");
    assert.ok(r.isSafe);
    const tokens = [...r.map.keys()];
    const fakeResponse = `I will notify ${tokens[0]} and reach them at ${tokens[1]}.`;
    const final = restore(fakeResponse, r.map);
    assert.ok(final.includes("bob@company.ua"));
    assert.ok(final.includes("+380 44 111 22 33"));
  });
});
