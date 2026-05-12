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

export function ibanCheck(raw: string): boolean {
  const iban = raw.replaceAll(/\s/g, "").toUpperCase();
  if (iban.length < 15 || iban.length > 34) return false;

  const rearranged = iban.slice(4) + iban.slice(0, 4);
  const numeric = rearranged.replaceAll(/[A-Z]/g, (c) => String((c.codePointAt(0) ?? 0) - 55));

  let remainder = 0n;
  for (const ch of numeric) {
    remainder = (remainder * 10n + BigInt(ch)) % 97n;
  }
  return remainder === 1n;
}

export function ethAddressCheck(raw: string): boolean {
  return /^0x[0-9a-fA-F]{40}$/.test(raw);
}

export function btcAddressCheck(raw: string): boolean {
  return (
    /^[13][a-km-zA-HJ-NP-Z1-9]{25,34}$/.test(raw) ||
    /^bc1[a-z0-9]{39,59}$/.test(raw)
  );
}

export function rnokkpCheck(raw: string): boolean {
  if (!/^\d{10}$/.test(raw)) return false;
  const weights = [-1, 5, 7, 9, 4, 6, 10, 5, 7];
  const digits = Array.from(raw, Number);
  let sum = 0;
  for (let i = 0; i < 9; i++) sum += (weights[i] ?? 0) * (digits[i] ?? 0);
  return ((sum % 11) % 10) === (digits[9] ?? -1);
}
