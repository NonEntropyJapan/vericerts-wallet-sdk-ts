import assert from 'node:assert/strict';

export function checkPublishResult(output, artifact) {
  const value = JSON.parse(output);
  let packages;
  if (Array.isArray(value)) packages = value;
  else if (value && typeof value === 'object' && typeof value.name === 'string') packages = [value];
  else {
    assert.ok(value && typeof value === 'object', 'Invalid npm publish metadata');
    packages = Object.entries(value).map(([name, entry]) => {
      assert.equal(name, entry?.name, 'npm package map key mismatch');
      return entry;
    });
  }
  assert.equal(packages.length, 1, 'npm did not report exactly one SDK artifact');
  const [reported] = packages;
  assert.equal(reported?.name, artifact.name, 'npm reported a different package');
  assert.equal(reported.version, artifact.version, 'npm reported a different version');
  assert.equal(reported.integrity, artifact.integrity, 'npm used different tarball bytes');
  assert.equal(reported.size, artifact.bytes, 'npm used a different tarball size');
}
