import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import {
  existsSync,
  lstatSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  realpathSync,
  rmSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join, posix } from 'node:path';
import { isAllowedPackFile, readPackMetadata } from './metadata.mjs';
import { run } from './process.mjs';

const privateExtensionPath =
  /(?<![\w.@-])extension[/\\]+(?:assets|e2e|public|scripts|src|test|test-support|testdata|(?:sdk-alias|vite)\.config\.ts)\b(?![.-]\w)/;
const privateSpecPath = /(?<![\w.@-])spec[/\\]+(?:content[/\\]+docs|\.\.\.)[/\\]+/;
// Standards URL path segments may resemble repository paths. Keep surrounding prose,
// query parameters, fragments, and links to code hosts in the scan.
const standardsDocumentUrl =
  /(?<![\w/:?&=#%@.-])https?:\/\/(?:www\.w3\.org\/TR|openid\.net\/specs|datatracker\.ietf\.org\/doc)\/[\w.%~/-]+/g;

export function digest(bytes, algorithm = 'sha256', encoding = 'hex') {
  return createHash(algorithm).update(bytes).digest(encoding);
}

function targets(value) {
  if (typeof value === 'string') return [value];
  assert.ok(value && typeof value === 'object', 'Invalid exports condition');
  return Object.values(value).flatMap(targets);
}

function checkFiles(root, pkg, files) {
  assert.equal(pkg.name, 'vericerts-wallet-sdk', 'Unexpected artifact package');
  assert.equal(pkg.license, 'Apache-2.0');
  assert.match(pkg.version, /^\d+\.\d+\.\d+(?:-[\w.-]+)?$/);
  assert.equal(pkg.engines?.node, '>=20.19.0');
  for (const name of files) {
    assert.ok(isAllowedPackFile(name), `Unexpected packed file: ${name}`);
  }
  for (const name of ['LICENSE', 'NOTICE', 'sbom/sdk.cdx.json']) {
    assert.ok(files.includes(name), `Missing packed file: ${name}`);
  }
  const license = readFileSync(join(root, 'LICENSE'), 'utf8');
  assert.ok(license.includes('Apache License') && license.includes('END OF TERMS AND CONDITIONS'));
  assert.ok(readFileSync(join(root, 'NOTICE'), 'utf8').trim().length > 0, 'Empty NOTICE');
  const bom = JSON.parse(readFileSync(join(root, 'sbom/sdk.cdx.json'), 'utf8'));
  assert.equal(bom.bomFormat, 'CycloneDX');
  assert.equal(bom.metadata?.component?.name, pkg.name);
  assert.equal(bom.metadata?.component?.version, pkg.version);
  assert.ok(bom.components?.length && bom.dependencies?.length, 'Incomplete SBOM');
  assert.ok(pkg.exports && Object.keys(pkg.exports).length > 1, 'Missing exports');
  for (const target of targets(pkg.exports)) {
    assert.ok(target.startsWith('./') && !target.includes('*'), 'Unsupported export target');
    assert.ok(files.includes(target.slice(2)), `Missing export target: ${target}`);
  }
  for (const name of files) {
    const source = readFileSync(join(root, name), 'utf8');
    const text = source.replace(standardsDocumentUrl, ' ');
    assert.ok(
      !privateExtensionPath.test(text) && !privateSpecPath.test(text),
      `Private repository path in ${name}`,
    );
    // TypeScript also checks bare dependencies in five strict modes. Relative
    // declarations must stay inside this package rather than resolving into a producer.
    if (!/\.d\.[cm]?ts$/.test(name)) continue;
    const references = [
      ...source.matchAll(/(?:from\s*|import\s*\(\s*|import\s*)(['"])([^'"\r\n]+)\1/g),
    ].map((match) => match[2]);
    for (const specifier of references) {
      assert.ok(!/^(?:[\\/]|[A-Za-z]:|file:)/.test(specifier), 'Absolute declaration reference');
      if (!specifier.startsWith('.')) continue;
      const target = posix.normalize(posix.join(posix.dirname(name), specifier));
      assert.ok(
        !target.startsWith('../') && !posix.isAbsolute(target),
        'Escaping declaration reference',
      );
      const candidates = [
        target,
        `${target}.d.ts`,
        `${target}/index.d.ts`,
        target.replace(/\.[cm]?js$/, '.d.ts'),
        target.replace(/\.mjs$/, '.d.mts'),
        target.replace(/\.cjs$/, '.d.cts'),
      ];
      assert.ok(
        candidates.some((candidate) => files.includes(candidate)),
        `Missing relative declaration: ${name} -> ${specifier}`,
      );
    }
  }
}

export function requirePackedRelativePath(name) {
  assert.match(name, /^[A-Za-z0-9_@+.,/-]*$/, 'Unsafe tar path');
  assert.ok(!name.split('/').some((part) => part === '..' || part === '.'), 'Unsafe tar traversal');
}

export function inspectArtifact(tarball, { includeFileDigests = false } = {}) {
  const bytes = readFileSync(tarball);
  const staging = mkdtempSync(join(tmpdir(), 'sdk-artifact-inspect-'));
  try {
    const expectedIntegrity = `sha512-${digest(bytes, 'sha512', 'base64')}`;
    const metadata = readPackMetadata(tarball, staging, bytes.length, expectedIntegrity);
    const listing = run('tar', ['-tzf', tarball], tmpdir()).trim().split('\n');
    assert.equal(new Set(listing).size, listing.length, 'Duplicate tar paths');
    for (const name of listing) {
      assert.ok(name.startsWith('package/'), 'Unsafe tar path');
      requirePackedRelativePath(name.slice('package/'.length));
    }
    const verbose = run('tar', ['-tvzf', tarball], tmpdir()).trim().split('\n');
    assert.ok(
      verbose.every((line) => /^[-d]/.test(line)),
      'Tar links or special entries are forbidden',
    );
    run('tar', ['-xzf', tarball, '-C', staging], tmpdir());
    const root = join(staging, 'package');
    const files = [];
    function walk(dir, prefix = '') {
      for (const name of readdirSync(dir)) {
        const path = join(dir, name);
        assert.ok(!lstatSync(path).isSymbolicLink(), 'Packed symlink');
        if (lstatSync(path).isDirectory()) walk(path, `${prefix}${name}/`);
        else {
          assert.ok(lstatSync(path).isFile(), 'Packed special file');
          assert.ok(realpathSync(path).startsWith(`${realpathSync(root)}/`));
          files.push(`${prefix}${name}`);
        }
      }
    }
    assert.ok(existsSync(join(root, 'package.json')));
    walk(root);
    files.sort();
    assert.deepEqual(
      files,
      metadata.files
        .map((entry) => entry.path)
        .filter((name) => name && !name.endsWith('/'))
        .sort(),
      'Tar extraction changed the packlist',
    );
    const pkg = JSON.parse(readFileSync(join(root, 'package.json'), 'utf8'));
    checkFiles(root, pkg, files);
    return {
      pkg,
      ...(includeFileDigests && {
        fileDigests: Object.fromEntries(
          files.map((name) => {
            const contents = readFileSync(join(root, name));
            return [name, { bytes: contents.length, sha256: digest(contents) }];
          }),
        ),
      }),
      artifact: {
        name: pkg.name,
        version: pkg.version,
        sha256: digest(bytes),
        integrity: `sha512-${digest(bytes, 'sha512', 'base64')}`,
        bytes: bytes.length,
        exports: Object.keys(pkg.exports).sort(),
        files,
        packlistSha256: digest(JSON.stringify(files)),
        packedSchemaPaths: files.filter((name) => /schema.*\.json$/i.test(name)),
      },
    };
  } finally {
    rmSync(staging, { recursive: true, force: true });
  }
}
