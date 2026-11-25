const DECIMAL = /^\d+(?:\.\d+)?$/;
function parseDecimal(flag, raw) {
  if (typeof raw !== 'string' || !DECIMAL.test(raw.trim())) {
    throw new Error(`${flag} must be a number (got: ${JSON.stringify(raw)})`);
  }
  return Number(raw.trim());
}
export function parsePercentArg(flag, raw) {
  const n = parseDecimal(flag, raw);
  if (!Number.isFinite(n) || n > 100) {
    throw new Error(`${flag} must be within 0-100 (got: ${JSON.stringify(raw)})`);
  }
  return n;
}
export function parsePositiveArg(flag, raw) {
  const n = parseDecimal(flag, raw);
  if (!Number.isFinite(n) || n <= 0) {
    throw new Error(`${flag} must be a positive number (got: ${JSON.stringify(raw)})`);
  }
  return n;
}
export function parseIntegerArg(flag, raw, { min, max }) {
  if (typeof raw !== 'string' || !/^\d+$/.test(raw)) {
    throw new Error(`${flag} must be an integer (got: ${JSON.stringify(raw)})`);
  }
  const n = Number(raw);
  if (!Number.isSafeInteger(n) || n < min || n > max) {
    throw new Error(`${flag} must be within ${min}-${max} (got: ${JSON.stringify(raw)})`);
  }
  return n;
}
