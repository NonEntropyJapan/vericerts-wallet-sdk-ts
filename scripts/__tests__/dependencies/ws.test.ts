import { expect, test } from 'bun:test';
import { readFileSync } from 'node:fs';
import { semver } from '../../lib/load-semver.mjs';

test('rejects ws releases affected by GHSA-96hv-2xvq-fx4p or GHSA-58qx-3vcg-4xpx in SDK and interop locks', () => {
  const sdkRoot = new URL('../../../', import.meta.url);
  const sdk = JSON.parse(readFileSync(new URL('package.json', sdkRoot), 'utf8'));
  expect(semver.intersects(sdk.dependencies.ethers, '<6.17.0')).toBe(false);
  expect(semver.intersects(sdk.dependencies.viem, '<2.54.2')).toBe(false);
  const bunLock = Bun.JSONC.parse(readFileSync(new URL('bun.lock', sdkRoot), 'utf8'));
  const versions = Object.values<[string, ...unknown[]]>(bunLock.packages)
    .map(([descriptor]) => descriptor)
    .filter((descriptor) => descriptor.startsWith('ws@'))
    .map((descriptor) => descriptor.slice(3));
  for (const lockPath of [
    'test/browser-consumer/package-lock.json',
    'test/interop/adapters/sphereon/package-lock.json',
    'test/interop/adapters/veramo/package-lock.json',
  ]) {
    const lock = JSON.parse(readFileSync(new URL(lockPath, sdkRoot), 'utf8'));
    for (const [path, entry] of Object.entries<{ version: string }>(lock.packages)) {
      if (path.endsWith('/ws')) versions.push(entry.version);
    }
  }
  const vulnerable = '>=1.1.0 <5.2.5 || >=6.0.0 <6.2.4 || >=7.0.0 <7.5.11 || >=8.0.0 <8.21.0';
  expect(versions.filter((version) => semver.satisfies(version, vulnerable))).toEqual([]);
});
