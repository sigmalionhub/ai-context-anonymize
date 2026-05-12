/**
 * Validate a credit/debit card number using the Luhn algorithm.
 * Accepts digits with optional spaces or hyphens (13–19 digits after stripping).
 */
export function luhnCheck(raw: string): boolean {
  const digits = raw.replaceAll(/[\s\-]/g, "");
  if (!/^\d{13,19}$/.test(digits)) return false;

  let sum = 0;
  let shouldDouble = false;

  for (const ch of [...digits].reverse()) {
    let d = Number.parseInt(ch, 10);
    if (shouldDouble) {
      d *= 2;
      if (d > 9) d -= 9;
    }
    sum += d;
    shouldDouble = !shouldDouble;
  }
  return sum % 10 === 0;
}

/**
 * Validate an IBAN using the ISO 13616 mod-97 checksum.
 * Accepts IBANs with or without spaces (15–34 characters after stripping).
 */
export function ibanCheck(raw: string): boolean {
  const iban = raw.replaceAll(/\s/g, "").toUpperCase();
  if (iban.length < 15 || iban.length > 34) return false;

  const rearranged = iban.slice(4) + iban.slice(0, 4);
  const numeric = rearranged.replaceAll(/[A-Z]/g, (c) => String((c.codePointAt(0) ?? 0) - 55));

  let remainder = 0n;
  for (const ch of numeric) {
    const digit = Number.parseInt(ch, 10);
    if (Number.isNaN(digit)) return false;
    remainder = (remainder * 10n + BigInt(digit)) % 97n;
  }
  return remainder === 1n;
}

/** Validate an Ethereum address (`0x` prefix + 40 hex characters). */
export function ethAddressCheck(raw: string): boolean {
  return /^0x[0-9a-fA-F]{40}$/.test(raw);
}

/** Validate a Bitcoin address — Legacy (P2PKH/P2SH) or Bech32 (P2WPKH/P2WSH). */
export function btcAddressCheck(raw: string): boolean {
  return (
    /^[13][a-km-zA-HJ-NP-Z1-9]{25,34}$/.test(raw) ||
    /^bc1[a-z0-9]{39,59}$/.test(raw)
  );
}

/**
 * Validate a Ukrainian individual tax number (РНОКПП / RNOKKP) using the
 * official 9-weight checksum algorithm.
 */
export function rnokkpCheck(raw: string): boolean {
  if (!/^\d{10}$/.test(raw)) return false;
  const weights = [-1, 5, 7, 9, 4, 6, 10, 5, 7];
  const digits = Array.from(raw, Number);
  let sum = 0;
  for (let i = 0; i < 9; i++) sum += (weights[i] ?? 0) * (digits[i] ?? 0);
  return ((sum % 11) % 10) === (digits[9] ?? -1);
}
