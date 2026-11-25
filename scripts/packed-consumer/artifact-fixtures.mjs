import { mkdirSync, mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { inspectArtifact } from './archive.mjs';
import { run } from './process.mjs';
import { newReceipt, saveReceipt } from './receipt.mjs';

export const sourceSha = 'a'.repeat(40);

export function fixture() {
  const root = mkdtempSync(join(tmpdir(), 'sdk-artifact-test-'));
  const packageRoot = join(root, 'package');
  mkdirSync(join(packageRoot, 'dist'), { recursive: true });
  mkdirSync(join(packageRoot, 'sbom'));
  const pkg = {
    name: 'vericerts-wallet-sdk',
    version: '0.0.0',
    type: 'module',
    license: 'Apache-2.0',
    engines: { node: '>=20.19.0' },
    exports: {
      '.': { types: './dist/index.d.ts', import: './dist/index.js' },
      './package.json': './package.json',
    },
    scripts: {
      prepublishOnly: 'node -e "process.exit(42)"',
      prepack: 'node -e "process.exit(43)"',
    },
  };
  writeFileSync(join(packageRoot, 'package.json'), JSON.stringify(pkg));
  writeFileSync(join(packageRoot, 'dist/index.js'), 'export const version = "0.0.0";\n');
  writeFileSync(join(packageRoot, 'dist/index.d.ts'), 'export declare const version: string;\n');
  writeFileSync(
    join(packageRoot, 'LICENSE'),
    readFileSync(new URL('../../LICENSE', import.meta.url)),
  );
  writeFileSync(join(packageRoot, 'NOTICE'), 'Fixture notice\n');
  writeFileSync(
    join(packageRoot, 'sbom/sdk.cdx.json'),
    JSON.stringify({
      bomFormat: 'CycloneDX',
      metadata: { component: { name: pkg.name, version: pkg.version } },
      components: [{ name: 'fixture-dependency', version: '1.0.0' }],
      dependencies: [{ ref: pkg.name }],
    }),
  );
  const tarball = join(root, 'sdk.tgz');
  const repack = () => run('tar', ['-czf', tarball, '-C', root, 'package'], root);
  repack();
  const { artifact } = inspectArtifact(tarball);
  const receipt = newReceipt(
    artifact,
    tarball,
    {
      context: 'private-validation',
      validationOrigin: 'committed-projection',
      publicRevision: null,
      privateRevision: {
        sha: sourceSha,
        tree: 'b'.repeat(40),
        clean: true,
        lockSha256: 'c'.repeat(64),
        sourceSchemas: Object.fromEntries(
          ['error-codes.json', 'log-entry.json', 'conformance-vectors.json'].map((name) => [
            name,
            'd'.repeat(64),
          ]),
        ),
      },
    },
    { typescript: '5.9.3', bun: '1.4.4' },
  );
  receipt.checks.node = ['20.19.0', '22.16.0', '24.22.1'].map((version) => ({
    status: 'passed',
    version,
    formats: ['esm', 'cjs'],
    strictTypeModes: 5,
    optionalPeers: ['absent', 'installed'],
  }));
  receipt.checks.browser = { status: 'passed', optionalPeers: ['absent', 'installed'] };
  receipt.checks.bun = {
    status: 'passed',
    version: '1.4.4',
    formats: ['esm', 'cjs'],
    optionalPeers: ['absent', 'installed'],
  };
  const receiptPath = join(root, 'receipt.json');
  saveReceipt(receiptPath, receipt);
  return {
    root,
    packageRoot,
    tarball,
    receipt,
    receiptPath,
    repack,
    options: { tarball, receipt: receiptPath, 'source-sha': sourceSha },
  };
}
