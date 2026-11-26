import assert from 'node:assert/strict';
import test from 'node:test';
import { prepareSdkBom } from './sdk-bom.mjs';

const pkg = {
  name: 'example-sdk',
  version: '1.0.0',
  license: 'Apache-2.0',
  peerDependencies: { '@example/peer': '^1' },
};
const lockPath = '/private/checkout/sdk/bun.lock';
const locked = { '@example/peer': ['@example/peer@1.2.0'] };
const licenses = [{ license: { id: 'MIT' } }];

function generatedBom() {
  return {
    metadata: {
      component: {
        ...pkg,
        'bom-ref': 'sdk',
        type: 'application',
        licenses: [{ license: { id: pkg.license } }],
      },
    },
    components: [
      { group: '@example', name: 'peer', version: '2.0.0', 'bom-ref': 'nested-peer', licenses },
      {
        group: '@example',
        name: 'peer',
        version: '1.2.0',
        'bom-ref': 'sdk-peer',
        licenses,
        evidence: { identity: { methods: [{ technique: 'manifest-analysis', value: lockPath }] } },
      },
    ],
    dependencies: [{ ref: 'sdk', dependsOn: ['other-dependency'] }],
  };
}

test('publishes relative lockfile evidence and connects the SDK to its locked peer version', () => {
  const bom = prepareSdkBom(JSON.stringify(generatedBom()), pkg, locked, lockPath);
  assert.equal(bom.metadata.component.type, 'library');
  assert.deepEqual(bom.dependencies[0].dependsOn, ['other-dependency', 'sdk-peer']);
  assert.equal(bom.components[1].evidence.identity.methods[0].value, 'bun.lock');
  assert.ok(!JSON.stringify(bom).includes(lockPath));
});

test('rejects a BOM that omits the SDK license', () => {
  const bom = generatedBom();
  delete bom.metadata.component.licenses;
  assert.throws(
    () => prepareSdkBom(JSON.stringify(bom), pkg, locked, lockPath),
    /Incomplete SDK SBOM/,
  );
});

test('rejects a missing locked peer even when another peer version exists', () => {
  const bom = generatedBom();
  bom.components.pop();
  assert.throws(
    () => prepareSdkBom(JSON.stringify(bom), pkg, locked, lockPath),
    /Missing locked peer/,
  );
});

test('requires the expected npm scope and package name in the CycloneDX root', () => {
  const bom = generatedBom();
  const scoped = { ...pkg, name: '@vericerts/example-sdk' };
  bom.metadata.component.group = '@vericerts';
  assert.equal(
    prepareSdkBom(JSON.stringify(bom), scoped, locked, lockPath).metadata.component.group,
    '@vericerts',
  );
  bom.metadata.component.group = '@other';
  assert.throws(
    () => prepareSdkBom(JSON.stringify(bom), scoped, locked, lockPath),
    /Incomplete SDK SBOM/,
  );
});
