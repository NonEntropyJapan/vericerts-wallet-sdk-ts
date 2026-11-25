import { expect, test } from 'bun:test';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { formatLogEntrySchema } from './gen-log-entry-schema.mjs';

test.each([
  'check',
  'generate',
])('%s rejects an invalid optional subschema before writing', (mode) => {
  const dir = mkdtempSync(join(tmpdir(), 'sdk-log-schema-'));
  try {
    const path = join(dir, 'log-entry.json');
    const schema = JSON.parse(
      readFileSync(new URL('../schemas/log-entry.json', import.meta.url), 'utf8'),
    );
    schema.properties.extra = { type: 'strnig' };
    const input = JSON.stringify(schema);
    writeFileSync(path, input);
    expect(() => formatLogEntrySchema(path, mode === 'check')).toThrow(/properties\/extra\/type/);
    expect(readFileSync(path, 'utf8')).toBe(input);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
