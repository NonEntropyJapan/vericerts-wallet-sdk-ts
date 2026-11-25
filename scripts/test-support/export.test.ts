import { afterAll, beforeAll, describe, expect, it } from 'bun:test';
import { cp, mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';
import ts from 'typescript';
import { verifyMaterials } from '../../test/test-support/verify.mjs';
import { exportMaterials } from './export.js';

let temporary: string;
let materials: string;
beforeAll(async () => {
  temporary = await mkdtemp(join(tmpdir(), 'sdk-test-support-'));
  materials = join(temporary, 'materials');
  await exportMaterials(materials);
}, 60_000);
afterAll(async () => {
  await rm(temporary, { recursive: true, force: true });
});

describe('independently supplied SDK test material', () => {
  it('has SDK provenance, fixed counts and hashes, and reproducible output', async () => {
    const first = verifyMaterials(materials);
    const second = await exportMaterials(join(temporary, 'second'));
    expect(second).toEqual(first);
    expect(first.files['vectors/did.json'].caseCount).toBe(3);
    expect(first.files['vectors/credential.json'].caseCount).toBe(1);
    expect(first.files['vectors/status-list.json'].caseCount).toBe(6);
    expect(first.files['vectors/conformance.json'].caseCount).toBeGreaterThan(20);
    const didBundle = await readFile(join(materials, 'tools/did-fixtures.mjs'), 'utf8');
    expect(didBundle).not.toContain(process.cwd());
  }, 60_000);

  it('does not overwrite an existing output', async () => {
    await expect(exportMaterials(materials)).rejects.toThrow('must be empty');
  });

  for (const kind of ['tamper', 'missing', 'count', 'version', 'omitted', 'extra'] as const) {
    it(`rejects ${kind} material`, async () => {
      const root = join(temporary, kind);
      await cp(materials, root, { recursive: true });
      const manifestPath = join(root, 'manifest.json');
      const manifest = JSON.parse(await readFile(manifestPath, 'utf8'));
      if (kind === 'tamper') await writeFile(join(root, 'vectors/status-list.json'), '{}');
      if (kind === 'missing') await rm(join(root, 'vectors/status-list.json'));
      if (kind === 'count') manifest.files['vectors/status-list.json'].caseCount += 1;
      if (kind === 'version') manifest.materialVersion = '2.0.0';
      if (kind === 'omitted') delete manifest.files['vectors/status-list.json'];
      if (kind === 'extra') await writeFile(join(root, 'unapproved.txt'), 'extra');
      await writeFile(manifestPath, JSON.stringify(manifest));
      expect(() => verifyMaterials(root)).toThrow();
    });
  }

  it('runs the DID generator without SDK source or node_modules', async () => {
    const { hostedWebVh, localDids } = await import(
      pathToFileURL(join(materials, 'tools/did-fixtures.mjs')).href
    );
    const options = {
      host: 'independent.example',
      versions: 8,
      seed: 67,
      time: '2026-01-01T00:00:00Z',
      witness: true,
    };
    const first = await hostedWebVh(options);
    expect(await hostedWebVh(options)).toEqual(first);
    expect(first.bodies['/.well-known/did.jsonl'].text.trim().split('\n')).toHaveLength(8);
    expect(JSON.parse(first.bodies['/.well-known/did-witness.json'].text)).toHaveLength(1);
    expect(localDids().ipid.did).toStartWith('did:ipid:');
  });

  it('runs the bundled scanner with the consumer TypeScript API and detects unsafe input', async () => {
    const { findInheritedReads } = await import(
      pathToFileURL(join(materials, 'tools/inherited-reads.mjs')).href
    );
    const root = join(temporary, 'scanner-consumer');
    await mkdir(join(root, 'src'), { recursive: true });
    await writeFile(
      join(root, 'tsconfig.json'),
      JSON.stringify({
        compilerOptions: { strict: true, target: 'ES2022', module: 'ESNext', noEmit: true },
        include: ['src/**/*.ts'],
      }),
    );
    const source = join(root, 'src/input.ts');
    await writeFile(
      source,
      'export function read(opts: { limit?: number }) { return opts.limit; }',
    );
    expect(
      findInheritedReads(root, ts).map((read: { expression: string }) => read.expression),
    ).toEqual(['opts.limit']);
    await writeFile(
      source,
      'export function read(opts: { limit?: number }) { return Object.hasOwn(opts, "limit") ? opts.limit : 0; }',
    );
    expect(findInheritedReads(root, ts)).toEqual([]);
  }, 120_000);
});
