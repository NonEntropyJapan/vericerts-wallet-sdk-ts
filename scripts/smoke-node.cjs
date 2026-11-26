const assert = require('node:assert/strict');
const path = require('node:path');

const distPath = path.join(__dirname, '..', 'dist', 'index.cjs');
const sdk = require(distPath);
const { SDK_VERSION } = sdk;

const semverPattern = /^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$/;

if (typeof SDK_VERSION !== 'string' || !semverPattern.test(SDK_VERSION)) {
  console.error(`cjs smoke failed: SDK_VERSION is not valid semver: ${String(SDK_VERSION)}`);
  process.exit(1);
}

// ビルド成果物に公開 API が載っていることを確認する。
const requiredExports = [
  'issueCredential',
  'issuePresentation',
  'verifyCredential',
  'verifyPresentation',
  'createSdJwt',
  'parseSdJwt',
  'verifySdJwt',
  'createDpopProof',
];
const missing = requiredExports.filter((name) => typeof sdk[name] !== 'function');
if (missing.length > 0) {
  console.error(`cjs smoke failed: missing public exports: ${missing.join(', ')}`);
  process.exit(1);
}

// `@experimental` はメインバレルに載せず、サブパス経由でのみ公開する。
// 相対パスではなくパッケージ名で require し、exports マップの `./experimental` が
// Node の CJS 解決で実際に引けることまで確かめる（自己参照解決）。
const experimental = require('@vericerts/vericerts-wallet-sdk/experimental');
const experimentalEudi = require('@vericerts/vericerts-wallet-sdk/experimental/eudi');
const experimentalOid4vci = require('@vericerts/vericerts-wallet-sdk/experimental/oid4vci');

for (const name of [
  'presentEAACredential',
  'presentPIDCredential',
  'receiveVerifiedEAA',
  'receiveVerifiedPID',
]) {
  if (experimental[name] !== experimentalEudi[name] || sdk[name] !== undefined) {
    throw new Error(`experimental/eudi wrapper mismatch or root leak: ${name}`);
  }
}
if (
  experimental.fetchIssuerMetadata !== experimentalOid4vci.fetchIssuerMetadata ||
  sdk.fetchIssuerMetadata !== undefined
) {
  throw new Error('experimental/oid4vci wrapper mismatch or root leak');
}

const requiredExperimentalExports = [
  'buildDerivedCredential',
  'checkTermsOfUse',
  'interpretEvidence',
  'validateTermsOfUseOnPresentation',
  'verifyCredentialChain',
  'verifyCredentialChainOnPresentation',
  'verifyEvidence',
  'ChainVerificationCache',
  'obtainWalletUnitAttestation',
];
const missingExperimental = requiredExperimentalExports.filter(
  (name) => typeof experimental[name] !== 'function',
);
if (missingExperimental.length > 0) {
  console.error(
    `cjs smoke failed: missing experimental exports: ${missingExperimental.join(', ')}`,
  );
  process.exit(1);
}

const leaked = requiredExperimentalExports.filter((name) => sdk[name] !== undefined);
if (leaked.length > 0) {
  console.error(
    `cjs smoke failed: experimental names leaked into the main barrel: ${leaked.join(', ')}`,
  );
  process.exit(1);
}

// 型だけの再エクスポートではなく実際に呼べること（Proxy ラップ越しでも動く）。
const cache = new experimental.ChainVerificationCache();
if (cache.get('missing', Date.now()) !== undefined) {
  console.error('cjs smoke failed: ChainVerificationCache returned a value for an unknown key');
  process.exit(1);
}

// CJS の内部実体がメインバレルと `./experimental` で 1 つに保たれていること。
// 2 バンドルに分けると内部モジュールが二重化し、`./experimental` が投げたエラーが
// メインバレルの `VericertsError` の `instanceof` に一致しなくなる。利用者の
// `catch (e) { if (e instanceof VericertsError) }` が無警告で壊れるため、ここで固定する。
let thrown;
try {
  experimental.parseWalletUnitAttestation('not-a-jwt');
} catch (error) {
  thrown = error;
}
if (thrown === undefined) {
  console.error('cjs smoke failed: parseWalletUnitAttestation did not reject an invalid JWT');
  process.exit(1);
}
if (!(thrown instanceof sdk.VericertsError)) {
  console.error(
    'cjs smoke failed: an error thrown from the experimental subpath is not an instanceof the ' +
      'main barrel VericertsError (the CJS build duplicated the internal modules)',
  );
  process.exit(1);
}
if (thrown.constructor !== sdk.VericertsError) {
  console.error('cjs smoke failed: VericertsError constructor identity differs across surfaces');
  process.exit(1);
}

// `./otel` サブパスの解決と公開シンボル。`@opentelemetry/*` は optional peer のため、
// 共有バンドル（メインの `require` が読む）にインライン展開されておらず、`./otel` 側は裸 `require`
// で peer を引くこと。
const otel = require('@vericerts/vericerts-wallet-sdk/otel');
const requiredOtelExports = ['createOtelLogger', 'createOtelMetrics', 'createOtelTracer'];
const missingOtel = requiredOtelExports.filter((name) => typeof otel[name] !== 'function');
if (missingOtel.length > 0) {
  console.error(`cjs smoke failed: missing otel exports: ${missingOtel.join(', ')}`);
  process.exit(1);
}

const readDist = (relativePath) =>
  require('node:fs').readFileSync(path.join(__dirname, '..', 'dist', relativePath), 'utf8');
// cbor-x の native addon は利用側の Node が解決する。Bun が cbor-extract の
// __dirname をインライン化すると開発マシンのパスが配布物に入る。
const sharedBundle = readDist('_shared.cjs');
assert.match(sharedBundle, /require\(["']cbor-x["']\)/);
assert.ok(!sharedBundle.includes(path.resolve(__dirname, '..')), 'CJS bundle contains build path');
const backup = {
  version: sdk.WALLET_BACKUP_VERSION,
  encryption: {},
  credentials: [],
  personas: [],
  dids: [],
  settings: {},
  integrity: {},
};
const restored = sdk.deserializeBackupFromCbor(sdk.serializeBackupToCbor(backup));
assert.deepEqual(JSON.parse(JSON.stringify(restored)), backup);

if (sharedBundle.includes('node_modules/@opentelemetry')) {
  console.error('cjs smoke failed: @opentelemetry was inlined into dist/_shared.cjs');
  process.exit(1);
}
const otelBundle = readDist('exports/otel.cjs');
if (
  otelBundle.includes('node_modules/@opentelemetry') ||
  !/require\(["']@opentelemetry\/api["']\)/.test(otelBundle)
) {
  console.error(
    'cjs smoke failed: dist/exports/otel.cjs must require @opentelemetry/api as a peer',
  );
  process.exit(1);
}

// 用途別 entry。パッケージ名で require し、exports マップが CJS 解決で引けることと、
// メインと内部実体を共有していること（クラスの同一性）を確かめる。
// 各 entry の代表シンボル。メインバレルの同名値と同一参照であること。
const PURPOSE_ENTRY_SYMBOLS = {
  // サブパス専用。メインと共有する値が無いため、公開値は下の個別検査で確かめる。
  aa: [],
  asset: ['buildTransferTx', 'signAndSendTransaction'],
  common: ['VericertsError', 'createNonceStore'],
  credential: ['issueCredential', 'requireStandardSigner', 'verifyCredential'],
  eudi: ['presentPseudonym', 'extractTransactionData'],
  gdpr: ['DashboardLog', 'discoverDpoContact'],
  identity: [
    'buildDidCoreDocument',
    'buildDidWebDocument',
    'createDidKey',
    'createDidResolver',
    'createExternalKeySigner',
    'importPersonaFromDid',
    'inlineExternalMethods',
    'personaKid',
    'resolveDelegatedSigner',
    'resolvePersonaSigner',
    'samePublicKeyJwk',
    'serializeDidDocument',
    'signMessageJws',
    'verifyHeldKeyAgainstDid',
    'verifyMessageJws',
  ],
  keymanager: ['KeyManager', 'signP256'],
  oid4vci: ['parseCredentialOffer', 'requestCredential', 'PRE_AUTHORIZED_CODE_GRANT'],
  oid4vp: ['evaluateDcql', 'parsePresentationRequest', 'FORMAT_SD_JWT_VC'],
  persona: ['PersonaManager', 'personaKeyPath'],
  trust: ['evaluateTrust', 'entityConfigurationUrl'],
};
const PURPOSE_ENTRIES = Object.keys(PURPOSE_ENTRY_SYMBOLS);
// 不正入力で `VericertsError` を投げる呼び出し（同期・非同期どちらも）。
const PURPOSE_ENTRY_FAILURES = {
  aa: (m) => m.signUserOpWithPasskey({}, { clientDataJSON: new Uint8Array(0) }, ''),
  asset: (m) => m.buildTransferTx({}),
  // 不正な nonce で nonce 処理が実際に投げる `VericertsError`（NONCE_MALFORMED）を確かめる。
  common: (m) =>
    m.createNonceStore({ backend: 'memory' }).put('x', { flow: 'dpop', jkt: 'x' }, 1000),
  credential: (m) => m.parseSdJwt('not-an-sd-jwt'),
  eudi: (m) => m.extractTransactionData('x'),
  gdpr: (m) => m.discoverDpoContact(),
  identity: (m) => m.parseDidEthr('not-a-did'),
  keymanager: (m) => m.p1363ToDer(new Uint8Array(3)),
  oid4vci: (m) => m.parseCredentialOffer('x'),
  oid4vp: (m) => m.parsePresentationRequest('x'),
  persona: (m) => m.personaKeyPath(-1, 'x'),
  trust: (m) => m.entityConfigurationUrl('x'),
};

async function checkPurposeEntries() {
  for (const name of PURPOSE_ENTRIES) {
    const entry = require(`@vericerts/vericerts-wallet-sdk/${name}`);
    for (const symbol of PURPOSE_ENTRY_SYMBOLS[name]) {
      assert.ok(
        entry[symbol] !== undefined && entry[symbol] === sdk[symbol],
        `cjs smoke failed: ./${name} ${symbol} is missing or not shared with the main barrel`,
      );
    }
    let entryError;
    try {
      await PURPOSE_ENTRY_FAILURES[name](entry);
    } catch (error) {
      entryError = error;
    }
    assert.ok(
      entryError instanceof sdk.VericertsError,
      `cjs smoke failed: an error thrown from ./${name} is not an instanceof the main barrel VericertsError`,
    );
    assert.equal(entryError.constructor, sdk.VericertsError);
  }
}

// サブパス専用の ./aa。公開値が引けて、メインバレルへ流れていないこと。
const aaEntry = require('@vericerts/vericerts-wallet-sdk/aa');
assert.equal(typeof aaEntry.signUserOpWithPasskey, 'function');
assert.equal(aaEntry.ENTRY_POINT_V07_ADDRESS, '0x0000000071727De22E5E9d8BAf0edAc6f37da032');
for (const name of ['ENTRY_POINT_V07_ADDRESS', 'signUserOpWithPasskey']) {
  assert.equal(sdk[name], undefined, `./aa ${name} leaked into the main barrel`);
}

// 配布 CJS の追加公開値と共有 DCQL 予算を確認する。
function checkVcOid4vp() {
  const credentialEntry = require('@vericerts/vericerts-wallet-sdk/credential');
  const oid4vpEntry = require('@vericerts/vericerts-wallet-sdk/oid4vp');
  for (const name of [
    'assertVerifiableCredentialV2Members',
    'assertTimeClaims',
    'resolveClockSkewSeconds',
    'decodeCompactJws',
    'verifyWithJwk',
    'jwtVcBodyOf',
  ]) {
    assert.equal(typeof credentialEntry[name], 'function', `./credential ${name}`);
  }
  assert.equal(credentialEntry.VC_TYPE, 'VerifiableCredential');
  assert.equal(credentialEntry.VC_V2_CONTEXT, 'https://www.w3.org/ns/credentials/v2');
  assert.equal(credentialEntry.resolveClockSkewSeconds('vc', undefined), 120);
  assert.equal(credentialEntry.jwtVcBodyOf({ vc: 1 }).body, 1);
  assert.equal(typeof oid4vpEntry.createPresentation, 'function');
  assert.equal(typeof sdk.createPresentation, 'undefined');
  const dcqlQuery = { credentials: [{ id: 'q', format: 'jwt_vc_json' }] };
  const queryables = [{ id: 'vc', format: 'jwt_vc_json', claims: {} }];
  const budget = oid4vpEntry.createDcqlWorkBudget();
  budget.remaining = 1;
  assert.deepEqual(oid4vpEntry.findMatchingCredentialIndexes(dcqlQuery, queryables, budget), [0]);
  assert.equal(budget.remaining, 0);
  assert.throws(() => oid4vpEntry.evaluateDcql(dcqlQuery, queryables, budget), sdk.VericertsError);
  assert.equal(budget.exhausted, true);
}

// exports マップの全 target が dist に実在し、npm pack の実配布にも含まれること。
function checkExportTargets() {
  const pkgJson = require('../package.json');
  const targets = [];
  const collect = (value) => {
    if (typeof value === 'string') targets.push(value.replace(/^\.\//, ''));
    else for (const nested of Object.values(value)) collect(nested);
  };
  collect(pkgJson.exports);
  const packed = JSON.parse(
    require('node:child_process').execFileSync(
      'npm',
      ['pack', '--dry-run', '--json', '--ignore-scripts'],
      { cwd: path.join(__dirname, '..'), encoding: 'utf8' },
    ),
  )[0].files.map((file) => file.path);
  const absent = targets.filter((target) => !packed.includes(target));
  assert.deepEqual(
    absent,
    [],
    `cjs smoke failed: exports targets missing from the tarball: ${absent}`,
  );
  return targets.length;
}

checkPurposeEntries()
  .then(async () => {
    await require('./smoke-asset-warning.cjs')(sdk, 'cjs');
    checkVcOid4vp();
    const exportTargets = checkExportTargets();
    console.log(
      `cjs smoke ok: SDK_VERSION=${SDK_VERSION}, public exports=${requiredExports.length}, experimental subpath exports=${requiredExperimentalExports.length}, shared VericertsError identity ok, purpose entries=${PURPOSE_ENTRIES.length}, export targets=${exportTargets}`,
    );
  })
  .catch((error) => {
    console.error(error);
    process.exit(1);
  });
