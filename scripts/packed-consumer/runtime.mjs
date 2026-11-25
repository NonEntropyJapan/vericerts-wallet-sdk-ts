import assert from 'node:assert/strict';
import { cpSync, existsSync, lstatSync, readdirSync, readFileSync, realpathSync } from 'node:fs';
import { createRequire } from 'node:module';
import { dirname, join } from 'node:path';
import { runInNewContext } from 'node:vm';

const require = createRequire(import.meta.url);
const manifestPath = require.resolve('vericerts-wallet-sdk/package.json');
const pkg = JSON.parse(readFileSync(manifestPath, 'utf8'));
const cjs = process.argv[2] === 'cjs';
const withOtel = process.argv[3] === 'otel';
const load = cjs ? (name) => require(name) : (name) => import(name);
const main = await load(pkg.name);
const entries = Object.keys(pkg.exports).filter(
  (name) => name !== './package.json' && name !== './otel',
);
for (const name of entries) {
  const entry = await load(name === '.' ? pkg.name : `${pkg.name}/${name.slice(2)}`);
  assert.ok(Object.keys(entry).length > 0, `Empty entry ${name}`);
  for (const [key, value] of Object.entries(entry)) {
    if (Object.hasOwn(main, key))
      assert.equal(value, main[key], `Identity mismatch: ${name}/${key}`);
  }
}
const common = await load(`${pkg.name}/common`);
await assert.rejects(
  () => common.createNonceStore({ backend: 'memory' }).put('x', { flow: 'dpop', jkt: 'x' }, 1000),
  (error) => error instanceof main.VericertsError,
);
const credential = await load(`${pkg.name}/credential`);
const identity = await load(`${pkg.name}/identity`);
const handle = identity.createDidResolutionResources({ maxInflightBytes: 2 * 1024 * 1024 });
assert.equal(main.createDidResolutionResources, identity.createDidResolutionResources);
const rootHandle = main.createDidResolutionResources({ maxInflightBytes: 4 * 1024 * 1024 });
assert.equal(Object.isFrozen(handle), true);
assert.deepEqual(Reflect.ownKeys(handle), []);
const resourceDid = 'did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK';
assert.equal(
  (await main.createDidResolver({}, { webResolutionResources: handle }).resolve(resourceDid)).id,
  resourceDid,
);
assert.equal(
  (
    await identity
      .createDidResolver({}, { webResolutionResources: rootHandle })
      .resolveUncached(resourceDid)
  ).id,
  resourceDid,
);

// Node and Bun can share the same installed consumer, so their physical copies must be distinct.
const installedSdk = dirname(manifestPath);
const runtime = process.versions.bun ? 'bun' : 'node';
const foreignName = `${pkg.name}-foreign-${runtime}-${cjs ? 'cjs' : 'esm'}-${withOtel ? 'otel' : 'plain'}`;
const foreignSdk = join(dirname(installedSdk), foreignName);
cpSync(installedSdk, foreignSdk, { recursive: true, errorOnExist: true, force: false });
assert.equal(existsSync(join(installedSdk, 'src')), false);
assert.equal(existsSync(join(foreignSdk, 'src')), false);
assert.notEqual(realpathSync(installedSdk), realpathSync(foreignSdk));
function assertCopiedBytesAndModes(source, copy) {
  assert.deepEqual(readdirSync(source).sort(), readdirSync(copy).sort());
  for (const name of readdirSync(source)) {
    const from = join(source, name);
    const to = join(copy, name);
    const a = lstatSync(from);
    const b = lstatSync(to);
    assert.equal(a.isSymbolicLink(), false);
    assert.equal(b.isSymbolicLink(), false);
    assert.equal(a.mode, b.mode);
    if (a.isDirectory()) assertCopiedBytesAndModes(from, to);
    else assert.deepEqual(readFileSync(from), readFileSync(to));
  }
}
assertCopiedBytesAndModes(installedSdk, foreignSdk);
const foreignIdentity = await load(`${foreignName}/identity`);
const foreignHandle = foreignIdentity.createDidResolutionResources({
  maxInflightBytes: 2 * 1024 * 1024,
});
assert.throws(
  () => identity.createDidResolver({}, { webResolutionResources: foreignHandle }),
  TypeError,
);
assert.throws(
  () => foreignIdentity.createDidResolver({}, { webResolutionResources: handle }),
  TypeError,
);
console.log(
  `packed resources: ${cjs ? 'CJS' : 'ESM'} root/identity handle sharing and distinct SDK rejection passed`,
);
const issuerSigner = credential.createPrivateKeySigner(new Uint8Array(32).fill(7), 'ES256');
const issuerDid = identity.createDidJwk(issuerSigner.publicKeyJwk).id;
const vct = 'https://issuer.example.org/identity';
const raw = credential.createSdJwt(issuerSigner, {
  issuer: issuerDid,
  vct,
  disclosureClaims: ['name'],
  claims: { name: 'Alice' },
});
const issuerTrust = credential.buildReceivedIssuerTrust(
  {},
  identity.createDidResolver({}),
  undefined,
);
assert.equal(credential.parseReceivedCredential(raw).verification, 'unverified');
const verified = await credential.verifyReceivedSdJwtCredential(raw, {
  issuerTrust,
  expectedVct: vct,
});
assert.equal(verified.verification, 'verified');
assert.equal(verified.claims.name, 'Alice');
await assert.rejects(
  () => credential.verifyReceivedSdJwtCredential(raw, { issuerTrust, expectedVct: `${vct}/other` }),
  (error) => error instanceof main.VericertsError && error.code === '3010',
);
const gdpr = await load(`${pkg.name}/gdpr`);
const unhandled = [];
const onUnhandled = (error) => unhandled.push(error);
process.on('unhandledRejection', onUnhandled);
try {
  const source = {
    crossBorderWarning: true,
    rpIdentifier: 'test',
    country: 'US',
    origin: 'https://rp.example',
  };
  const failingLog = {
    async append() {
      throw Object.assign(new Error('write failed'), { code: 'NON_SDK_CODE' });
    },
  };
  const warnings = [];
  await gdpr.recordTransferWarning(source, failingLog, undefined, (warning) =>
    warnings.push(warning),
  );
  assert.equal(warnings.length, 1);
  assert.equal(Object.hasOwn(warnings[0].attributes, 'error_code'), false);
  const foreignSink = runInNewContext('() => Promise.reject(new Error("foreign sink failure"))');
  await gdpr.recordTransferWarning(source, failingLog, undefined, foreignSink);
  await new Promise((resolve) => setTimeout(resolve, 20));
  assert.deepEqual(unhandled, []);

  class AnchorFailingStorage extends main.MemoryStorage {
    async set(key, value) {
      if (key.startsWith('anchor/')) throw new Error('anchor write failed');
      return super.set(key, value);
    }
  }
  class Options {
    storage = new AnchorFailingStorage();
    #warnings = [];
    onWarning(warning) {
      this.#warnings.push(warning);
    }
    get warnings() {
      return this.#warnings;
    }
  }
  const options = new Options();
  const wallet = await main.createWallet(options);
  await wallet.importMnemonic(
    'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about',
  );
  const persona = await wallet.createPersona();
  await wallet.setActivePersona(persona.id);
  await wallet.storeCredential({
    '@context': ['https://www.w3.org/ns/credentials/v2'],
    type: ['VerifiableCredential'],
    issuer: 'did:example:issuer',
    credentialSubject: { id: 'did:example:subject' },
    issuanceDate: '2026-01-01T00:00:00Z',
    id: 'warning-test',
  });
  await wallet.markCredentialDisputed('warning-test', 'test');
  assert.ok(options.warnings.length > 0);
  assert.ok(
    options.warnings.every((warning) => warning.code === 'dashboard_log.tail_anchor_write_failed'),
  );
} finally {
  process.off('unhandledRejection', onUnhandled);
}
if (withOtel) {
  const otel = await load(`${pkg.name}/otel`);
  for (const name of ['createOtelLogger', 'createOtelMetrics', 'createOtelTracer'])
    assert.equal(typeof otel[name], 'function');
} else {
  await assert.rejects(
    async () => load(`${pkg.name}/otel`),
    (error) => /@opentelemetry/.test(error.message),
  );
  assert.equal(require.resolve(pkg.name).startsWith(join(process.cwd(), 'node_modules')), true);
}
console.log(
  `packed consumer: ${cjs ? 'CJS' : 'ESM'} ${entries.length + Number(withOtel)} entries; OTel peers ${withOtel ? 'installed' : 'absent'}`,
);
