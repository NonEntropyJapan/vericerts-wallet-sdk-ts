const assert = require('node:assert/strict');

const suppressionEnv = 'VERICERTS_WALLET_SDK_SUPPRESS_EXPERIMENTAL_WARNINGS';
const importAsset = () => import('vericerts-wallet-sdk/asset');
const requireAsset = () => require('vericerts-wallet-sdk/asset');

module.exports = async function checkAssetWarning(sdk, firstFormat, suppressFirst = false) {
  assert.ok(
    !Object.hasOwn(sdk, 'personalSignMessageBytes'),
    'personalSignMessageBytes leaked into the main barrel',
  );
  const savedSuppression = process.env[suppressionEnv];
  const savedWarn = console.warn;
  const warnings = [];
  try {
    if (suppressFirst) process.env[suppressionEnv] = '1';
    else delete process.env[suppressionEnv];
    console.warn = (message) => warnings.push(String(message));
    const [first, second] =
      firstFormat === 'esm'
        ? [await importAsset(), requireAsset()]
        : [requireAsset(), await importAsset()];
    assert.deepEqual(warnings, []);
    for (const asset of [first, second]) {
      asset.assertPersonalSignAllowed('0x61');
      asset.personalSignPayload('0x61');
    }
    assert.deepEqual(warnings, []);

    assert.deepEqual(first.personalSignMessageBytes('0x61'), new Uint8Array([0x61]));
    const expectedWarningCount = suppressFirst ? 0 : 1;
    assert.equal(warnings.length, expectedWarningCount);
    if (!suppressFirst) assert.match(warnings[0], /`personalSignMessageBytes` is @experimental/);

    delete process.env[suppressionEnv];
    for (const asset of [first, second]) {
      assert.deepEqual(asset.personalSignMessageBytes('b'), new Uint8Array([0x62]));
    }
    assert.equal(warnings.length, expectedWarningCount);
  } finally {
    console.warn = savedWarn;
    if (savedSuppression === undefined) delete process.env[suppressionEnv];
    else process.env[suppressionEnv] = savedSuppression;
  }
};
