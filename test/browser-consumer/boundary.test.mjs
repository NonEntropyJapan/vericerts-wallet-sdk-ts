import { afterAll, expect, test } from 'bun:test';
import { mkdirSync, mkdtempSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';
import { browserFileBoundary } from './boundary.mjs';

const root = mkdtempSync(join(tmpdir(), 'browser-boundary-unit-'));
const consumer = join(root, 'consumer');
mkdirSync(join(consumer, 'node_modules/dep'), { recursive: true });
const own = join(consumer, 'node_modules/dep/asset.svg');
writeFileSync(own, '<svg/>');
const external = join(root, 'private.js');
writeFileSync(external, 'export const value=1;');
const check = browserFileBoundary(consumer);
afterAll(() => rmSync(root, { recursive: true, force: true }));

test('browser boundary accepts own dependency files, Vite queries and standard file URLs', () => {
  for (const id of [own, `${own}?url#fragment`, pathToFileURL(own).href])
    expect(() => check(id)).not.toThrow();
});

test('browser boundary preserves Vite virtual module IDs without treating them as files', () => {
  for (const id of ['\0vite/preload-helper.js', '__vite-browser-external:node:crypto'])
    expect(() => check(id)).not.toThrow();
});

test('browser boundary refuses external realpaths including symlinks and prefix lookalikes', () => {
  const lookalike = `${consumer}-outside`;
  mkdirSync(lookalike);
  writeFileSync(join(lookalike, 'private.js'), '');
  const link = join(consumer, 'linked.js');
  symlinkSync(external, link);
  for (const id of [external, pathToFileURL(external).href, link, join(lookalike, 'private.js')])
    expect(() => check(id)).toThrow();
});

test('browser boundary fails closed on unresolved and missing modules', () => {
  for (const id of [
    'unknown-dep',
    'https://example.invalid/module.js',
    join(consumer, 'missing.js'),
  ])
    expect(() => check(id)).toThrow();
});
