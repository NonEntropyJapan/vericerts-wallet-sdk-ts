// SDK が所有するログスキーマを検証し、配布用の JSON 表記を揃える。
import { readFileSync, writeFileSync } from 'node:fs';
import { pathToFileURL } from 'node:url';
import Ajv2020 from 'ajv/dist/2020.js';

// このコンパイラは開発時にローカルのスキーマだけを読み、SDK 本体には含めない。
export function formatLogEntrySchema(schemaUrl, checkOnly) {
  const current = readFileSync(schemaUrl, 'utf8');
  const schema = JSON.parse(current);
  if (schema?.$id !== 'https://vericerts.dev/schemas/log-entry.json' || schema.type !== 'object') {
    throw new Error('Expected the public SDK log-entry object schema in schemas/log-entry.json');
  }
  // ここで検査するのはスキーマ文書。日時の値は SDK のログ契約テストが検証する。
  new Ajv2020({ formats: { 'date-time': true } }).compile(schema);

  const canonical = `${JSON.stringify(schema, null, 2)}\n`;
  if (current === canonical) return;
  if (checkOnly) {
    throw new Error('Run `bun run gen:log-entry-schema` to format schemas/log-entry.json');
  }
  writeFileSync(schemaUrl, canonical);
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  formatLogEntrySchema(
    new URL('../schemas/log-entry.json', import.meta.url),
    process.argv.includes('--check'),
  );
}
