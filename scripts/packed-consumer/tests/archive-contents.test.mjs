import { afterEach, expect, test } from 'bun:test';
import { rmSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { inspectArtifact } from '../archive.mjs';
import { fixture } from '../artifact-fixtures.mjs';

const roots = [];
function setup() {
  const f = fixture();
  roots.push(f.root);
  return f;
}
afterEach(() => {
  for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true });
});

test('only the public root README may be packed alongside required legal documents', () => {
  const f = setup();
  writeFileSync(join(f.packageRoot, 'README.md'), '# VeriCerts Wallet SDK\n');
  f.repack();
  expect(inspectArtifact(f.tarball)).toBeDefined();
  writeFileSync(join(f.packageRoot, 'INTERNAL.md'), 'Not for distribution\n');
  f.repack();
  expect(() => inspectArtifact(f.tarball)).toThrow('Unexpected packed file: INTERNAL.md');
});

test.each([
  ['dist/index.d.ts', ['extension', 'src', 'fixture.ts'], '/'],
  ['dist/index.d.ts', ['extension', 'src'], '/'],
  ['dist/index.js', ['extension', 'public', 'manifest.json'], '/'],
  ['dist/index.js', ['extension', 'sdk-alias.config.ts'], '/'],
  ['dist/index.js', ['extension', 'vite.config.ts'], '/'],
  ['README.md', ['extension', 'test', 'fixture.ts'], '\\'],
  ['README.md', ['file:///tmp', 'extension', 'src', 'fixture.ts'], '/'],
  [
    'README.md',
    ['https://github.com', 'sample', 'example', 'blob', 'main', 'extension', 'src', 'file.ts'],
    '/',
  ],
  ['README.md', ['https://www.w3.org/TR/example?source=extension', 'src', 'file.ts'], '/'],
  ['README.md', ['https://www.w3.org/TR/example then ../extension', 'src', 'file.ts'], '/'],
  ['README.md', ['spec', 'content', 'docs', 'fixture.md'], '/'],
  ['dist/index.d.ts', ['spec', '...', 'fixture.md'], '/'],
])('rejects private repository paths inside packed %s (%j)', (name, parts, separator) => {
  const f = setup();
  writeFileSync(join(f.packageRoot, name), `/** See \`${parts.join(separator)}\`. */\n`);
  f.repack();
  expect(() => inspectArtifact(f.tarball)).toThrow(`Private repository path in ${name}`);
});

test('public specifications, extension terminology and unrelated module paths may be packed', () => {
  const f = setup();
  writeFileSync(
    join(f.packageRoot, 'README.md'),
    [
      'A browser extension may use this SDK. See https://openid.net/specs/openid-4-verifiable-presentations-1_0.html.',
      'Public specification at https://spec.example.org/v1. The extension uses its own manifest.',
      ['https://example.org/another-extension', 'src', 'api.js'].join('/'),
      ['https://www.w3.org/TR/example', 'extension', 'src', 'syntax'].join('/'),
      ['https://openid.net/specs/example', 'spec', 'content', 'docs', 'section'].join('/'),
      ['http://datatracker.ietf.org/doc/example', 'extension', 'test', 'syntax'].join('/'),
      ['extension', 'srcset', 'items.js'].join('/'),
    ].join('\n'),
  );
  f.repack();
  expect(inspectArtifact(f.tarball).artifact.files).toContain('README.md');
});

test('private source and missing distribution documents are rejected', () => {
  const f = setup();
  writeFileSync(join(f.packageRoot, 'source.ts'), 'export const secret = 1;');
  f.repack();
  expect(() => inspectArtifact(f.tarball)).toThrow('Unexpected packed file');
  rmSync(join(f.packageRoot, 'source.ts'));
  rmSync(join(f.packageRoot, 'NOTICE'));
  f.repack();
  expect(() => inspectArtifact(f.tarball)).toThrow('Missing packed file');
});
