import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { Anonymizer, SecurityLevel, EntityCategory, protect, restore, type ProtectResult } from "./src/index.ts";
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
    const r1 = protect("user@test.com");
    const r2 = protect("user@test.com");
    assert.equal(
      tokenFor(r1, "user@test.com"),
      tokenFor(r2, "user@test.com"),
      "default instance produces same token prefix for same category"
    );
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
