import { afterAll, describe, expect, test } from 'bun:test';
import { mkdirSync, readFileSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { fixture } from './gates-fixture';

const f = fixture();
afterAll(() => f.close());
f.write(
  'scripts/gen-notice.mjs',
  readFileSync(new URL('../gen-notice.mjs', import.meta.url), 'utf8'),
);
f.write(
  'scripts/licenses/permissionless-0.2.57.LICENSE',
  readFileSync(new URL('../licenses/permissionless-0.2.57.LICENSE', import.meta.url), 'utf8'),
);
const pkg = (name: string, extra = {}) => {
  f.write(
    `node_modules/${name}/package.json`,
    JSON.stringify({ name, version: '1.0.0', main: 'index.js', ...extra }),
  );
  f.write(`node_modules/${name}/index.js`, '// Copyright Fixture\nmodule.exports={};\n');
  f.write(`node_modules/${name}/LICENSE`, `License for ${name}\n`);
};
const inputs = (...files: string[]) => {
  const json = JSON.stringify({
    outputs: {
      'dist/index.js': {
        inputs: Object.fromEntries(files.map((file) => [file, { bytesInOutput: 1 }])),
      },
    },
  });
  for (const build of ['esm', 'cjs', 'otel']) f.write(`.build-meta-${build}.json`, json);
};
const run = () => f.node('scripts/gen-notice.mjs');
pkg('notice-fixture');
describe('NOTICE uses only actual SDK inputs and packages', () => {
  test('preserves the deterministic NOTICE bytes and vendored license behavior', () => {
    inputs('node_modules/notice-fixture/index.js');
    expect(run().status).toBe(0);
    expect(f.read('NOTICE')).toBe(
      'VeriCerts Wallet SDK\n\nCopyright (c) 2026 VeriCerts Wallet contributors\n\nThird-party notices\n\nnotice-fixture@1.0.0\n\nCopyright Fixture\n\nLICENSE\nLicense for notice-fixture\n\n\n',
    );
    pkg('permissionless', { version: '0.2.57' });
    rmSync(path.join(f.root, 'node_modules/permissionless/LICENSE'));
    inputs('node_modules/permissionless/index.js');
    expect(run().status).toBe(0);
    expect(f.read('NOTICE')).toContain('permissionless@0.2.57');
    expect(f.read('NOTICE')).toContain('MIT License');
  });
  test('accepts a contained native resolver dependency from the bundled package', () => {
    pkg('jsonpath-plus', { dependencies: { 'notice-child': '^1' } });
    pkg('notice-child');
    inputs('node_modules/jsonpath-plus/index.js');
    expect(run().status).toBe(0);
    expect(f.read('NOTICE')).toContain('notice-child@1.0.0');
  });
  test('rejects producer and symlink input/manifest/metadata/output paths', () => {
    const foreign = path.join(f.parent, 'foreign.js');
    writeFileSync(foreign, 'outside-sentinel');
    symlinkSync(foreign, path.join(f.root, 'foreign.js'));
    for (const file of [foreign, 'foreign.js']) {
      inputs(file);
      expect(run().status).toBe(1);
    }
    inputs('node_modules/notice-fixture/index.js');
    const metadata = path.join(f.root, '.build-meta-esm.json');
    const saved = f.read('.build-meta-esm.json');
    rmSync(metadata);
    symlinkSync(foreign, metadata);
    expect(run().status).toBe(1);
    rmSync(metadata);
    f.write('.build-meta-esm.json', saved);
    const manifest = path.join(f.root, 'node_modules/notice-fixture/package.json');
    const manifestBytes = readFileSync(manifest, 'utf8');
    rmSync(manifest);
    symlinkSync(foreign, manifest);
    expect(run().status).toBe(1);
    rmSync(manifest);
    writeFileSync(manifest, manifestBytes);
    rmSync(path.join(f.root, 'NOTICE'));
    symlinkSync(foreign, path.join(f.root, 'NOTICE'));
    expect(run().status).toBe(1);
    expect(readFileSync(foreign, 'utf8')).toBe('outside-sentinel');
    rmSync(path.join(f.root, 'NOTICE'));
  });
  test('rejects ancestor resolution and symlinked package/license sources', () => {
    rmSync(path.join(f.root, 'node_modules/notice-child'), { recursive: true });
    const outside = path.join(f.parent, 'node_modules/notice-child');
    mkdirSync(outside, { recursive: true });
    writeFileSync(
      path.join(outside, 'package.json'),
      '{"name":"notice-child","version":"1.0.0","main":"index.js"}',
    );
    writeFileSync(path.join(outside, 'index.js'), 'module.exports=1;');
    inputs('node_modules/jsonpath-plus/index.js');
    expect(run().status).toBe(1);
    symlinkSync(outside, path.join(f.root, 'node_modules/notice-child'), 'dir');
    expect(run().status).toBe(1);
    const license = path.join(f.root, 'node_modules/notice-fixture/LICENSE');
    rmSync(license);
    symlinkSync(path.join(outside, 'index.js'), license);
    inputs('node_modules/notice-fixture/index.js');
    expect(run().status).toBe(1);
  });
});
