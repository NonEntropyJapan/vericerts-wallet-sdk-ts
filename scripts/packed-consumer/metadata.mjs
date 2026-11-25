import assert from 'node:assert/strict';
import { readdirSync } from 'node:fs';
import { run } from './process.mjs';

export const isAllowedPackFile = (name) =>
  /^(package\.json|README\.md|LICENSE|NOTICE|sbom\/sdk\.cdx\.json|dist\/.+)$/.test(name);

export function readPackMetadata(tarball, staging, bytes, integrity) {
  // Read the existing archive through npm, without running lifecycle scripts or
  // writing another tgz. This sees metadata entries hidden by BSD tar's listing.
  const result = JSON.parse(
    run(
      'npm',
      ['pack', tarball, '--dry-run', '--json', '--ignore-scripts', '--pack-destination', staging],
      staging,
    ),
  );
  assert.ok(Array.isArray(result) && result.length === 1, 'Expected one artifact metadata result');
  assert.deepEqual(readdirSync(staging), [], 'Metadata inspection wrote another artifact');
  const metadata = result[0];
  assert.equal(metadata.size, bytes, 'npm inspected a different archive size');
  assert.equal(metadata.integrity, integrity, 'npm inspected different archive bytes');
  assert.ok(Array.isArray(metadata.files) && metadata.files.length > 0, 'Empty packlist');
  const names = metadata.files.map((entry) => entry.path);
  assert.equal(new Set(names).size, names.length, 'Duplicate packlist paths');
  for (const name of names.filter((name) => name && !name.endsWith('/'))) {
    assert.ok(isAllowedPackFile(name), `Unexpected packed file: ${name}`);
    assert.ok(!name.split('/').some((part) => part === '..' || part === '.'), 'Unsafe packed path');
    assert.ok(!name.includes('\\'), 'Unsafe packed path');
  }
  return metadata;
}
