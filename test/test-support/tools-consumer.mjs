import assert from 'node:assert/strict';
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import ts from 'typescript';
import { hostedWebVh, localDids } from './tools/did-fixtures.mjs';
import { findInheritedReads } from './tools/inherited-reads.mjs';
import { verifyMaterials } from './verify.mjs';

verifyMaterials();
const options = {
  host: 'consumer.example',
  versions: 8,
  witness: true,
  seed: 67,
  time: '2026-01-01T00:00:00Z',
};
const did = await hostedWebVh(options);
assert.deepEqual(await hostedWebVh(options), did);
assert.equal(did.bodies['/.well-known/did.jsonl'].text.trim().split('\n').length, 8);
assert.equal(JSON.parse(did.bodies['/.well-known/did-witness.json'].text).length, 1);
assert.ok(localDids().ipid.did.startsWith('did:ipid:'));

const root = mkdtempSync(join(tmpdir(), 'sdk-tool-consumer-'));
try {
  mkdirSync(join(root, 'src'));
  writeFileSync(
    join(root, 'tsconfig.json'),
    JSON.stringify({
      compilerOptions: { strict: true, target: 'ES2022', module: 'ESNext', noEmit: true },
      include: ['src/**/*.ts'],
    }),
  );
  const file = join(root, 'src/input.ts');
  writeFileSync(file, 'export function read(opts: { limit?: number }) { return opts.limit; }');
  assert.deepEqual(
    findInheritedReads(root, ts).map((read) => read.expression),
    ['opts.limit'],
  );
  writeFileSync(
    file,
    'export function read(opts: { limit?: number }) { return Object.hasOwn(opts, "limit") ? opts.limit : 0; }',
  );
  assert.deepEqual(findInheritedReads(root, ts), []);
} finally {
  rmSync(root, { recursive: true, force: true });
}
console.log('test-support: standalone Node dev tools passed');
