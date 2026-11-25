import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { interopGroups } from './groups.mjs';

const sha256 = (data) => createHash('sha256').update(data).digest('hex');
const runtimeByFile = new Map(
  interopGroups.flatMap(({ runtime, targets }) => targets.map((file) => [file, runtime])),
);

export function interopCaseKey({ file, classname, name, runtime }) {
  return JSON.stringify([file, classname, name, runtime]);
}

function expectedKeys(byFile, runtime) {
  const rows = Object.entries(byFile).flatMap(([file, byClassname]) => {
    assert.equal(
      runtimeByFile.get(file),
      runtime,
      `Wrong runtime in Interop case contract: ${file}`,
    );
    return Object.entries(byClassname).flatMap(([classname, names]) => {
      assert.ok(Array.isArray(names) && names.length > 0, `Empty case contract for ${file}`);
      return names.map((name) => {
        assert.ok(typeof name === 'string' && name.length > 0, `Invalid case name for ${file}`);
        return interopCaseKey({ file, classname, name, runtime });
      });
    });
  });
  const keys = new Set(rows);
  assert.equal(rows.length, keys.size, 'Duplicate identity in Interop case contract');
  return keys;
}

function loadContract(runtime) {
  const path = `test/interop/contracts/public-cases-${runtime}.json`;
  const bytes = readFileSync(new URL(`../../../${path}`, import.meta.url));
  const contract = JSON.parse(bytes);
  assert.equal(contract.version, 1, 'Unsupported Interop case contract');
  assert.equal(contract.runtime, runtime, 'Interop case contract runtime differs from its path');
  assert.deepEqual(
    Object.keys(contract.originalCases).sort(),
    interopGroups
      .filter((group) => group.runtime === runtime)
      .flatMap((group) => group.targets)
      .sort(),
    'Original public case contract must cover every Interop test file',
  );
  const original = expectedKeys(contract.originalCases, runtime);
  const additional = expectedKeys(contract.additionalCases, runtime);
  const renamedKeys = contract.renamedCases.map((row) => interopCaseKey({ ...row, runtime }));
  const renames = new Set(renamedKeys);
  assert.ok(
    renames.size === renamedKeys.length && renamedKeys.every((key) => original.has(key)),
    'Renamed public cases must be unique original identities',
  );
  return { original, additional, renames, input: { path, sha256: sha256(bytes) } };
}

const fragments = ['bun', 'node'].map(loadContract);
const contractSha256 = sha256(JSON.stringify(fragments.map(({ input }) => input)));
const original = new Set(fragments.flatMap((fragment) => [...fragment.original]));
const additional = new Set(fragments.flatMap((fragment) => [...fragment.additional]));
const expected = new Set([...original, ...additional]);
assert.equal(original.size, 235, 'Original public case contract must retain all 235 identities');
assert.equal(
  expected.size,
  original.size + additional.size,
  'An added case duplicates an original',
);
const allowedRenames = fragments.reduce((count, fragment) => count + fragment.renames.size, 0);
assert.equal(allowedRenames, 3, 'Public case contract must record all three approved renames');

export function verifyInteropCases(cases) {
  assert.ok(Array.isArray(cases), 'Interop cases must be an array');
  const seen = new Set();
  for (const row of cases) {
    assert.ok(row && row.status === 'passed', 'Interop cases must have passed');
    const key = interopCaseKey(row);
    assert.ok(expected.has(key), `Unexpected public Interop case: ${key}`);
    assert.ok(!seen.has(key), `Duplicate public Interop case: ${key}`);
    seen.add(key);
  }
  const missing = [...expected].filter((key) => !seen.has(key));
  assert.ok(
    missing.length === 0,
    `Missing ${missing.length} public Interop cases: ${missing.slice(0, 3).join(', ')}`,
  );
  return { contractSha256, missing: 0, duplicate: 0, unexpected: 0, allowedRenames };
}
