const SIMPLE_ESCAPES = {
  a: 0x07,
  b: 0x08,
  t: 0x09,
  n: 0x0a,
  v: 0x0b,
  f: 0x0c,
  r: 0x0d,
  '"': 0x22,
  '\\': 0x5c,
};
export function unquoteGitPath(raw) {
  if (raw.length < 2 || !raw.startsWith('"') || !raw.endsWith('"')) return raw;
  const body = raw.slice(1, -1);
  const bytes = [];
  for (let i = 0; i < body.length; i += 1) {
    const ch = body[i];
    if (ch !== '\\') {
      bytes.push(...Buffer.from(ch, 'utf8'));
      continue;
    }
    const next = body[i + 1];
    if (next !== undefined && next in SIMPLE_ESCAPES) {
      bytes.push(SIMPLE_ESCAPES[next]);
      i += 1;
      continue;
    }
    const octal = /^[0-3][0-7]{2}/.exec(body.slice(i + 1, i + 4));
    if (!octal) throw new Error(`invalid escape in quoted git path: ${raw}`);
    bytes.push(Number.parseInt(octal[0], 8));
    i += 3;
  }
  return new TextDecoder('utf-8', { fatal: true }).decode(Uint8Array.from(bytes));
}
