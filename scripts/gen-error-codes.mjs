/** SDK 内の正本を検証し、既存 consumer が使う数値順の JSON に整形する。 */
import { readFileSync, writeFileSync } from 'node:fs';
import { buildRegistryObject, validateRegistry } from './error-codes-registry.mjs';

const path = new URL('../schemas/error-codes.json', import.meta.url);
const current = readFileSync(path, 'utf8');
const registry = JSON.parse(current);
validateRegistry(registry);
registry.codes.sort((left, right) => Number(left.code) - Number(right.code));
const generated = `${JSON.stringify(buildRegistryObject(registry.codes), null, 2)}\n`;

if (process.argv.includes('--check')) {
  if (current !== generated)
    throw new Error('error-codes: bun run gen:error-codes で正規化してください');
} else {
  writeFileSync(path, generated);
}
console.log(`error-codes: validated ${registry.codes.length} entries`);
