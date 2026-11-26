import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import checkAssetWarning from './smoke-asset-warning.cjs';

const readDist = (relativePath) =>
  readFileSync(new URL(`../dist/${relativePath}`, import.meta.url), 'utf8');

const distUrl = new URL('../dist/index.js', import.meta.url);
const sdk = await import(distUrl.href);
const { SDK_VERSION } = sdk;

const semverPattern = /^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$/;

if (typeof SDK_VERSION !== 'string' || !semverPattern.test(SDK_VERSION)) {
  console.error(`smoke failed: SDK_VERSION is not valid semver: ${String(SDK_VERSION)}`);
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
  console.error(`smoke failed: missing public exports: ${missing.join(', ')}`);
  process.exit(1);
}

// `@experimental` はメインバレルに載せず、サブパス経由でのみ公開する。
// 相対パスではなくパッケージ名で import し、exports マップの `./experimental` が
// Node の ESM 解決で実際に引けることまで確かめる（自己参照解決）。
const experimental = await import('@vericerts/vericerts-wallet-sdk/experimental');
const experimentalEudi = await import('@vericerts/vericerts-wallet-sdk/experimental/eudi');
const experimentalOid4vci = await import('@vericerts/vericerts-wallet-sdk/experimental/oid4vci');

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
  console.error(`smoke failed: missing experimental exports: ${missingExperimental.join(', ')}`);
  process.exit(1);
}

const leaked = requiredExperimentalExports.filter((name) => sdk[name] !== undefined);
if (leaked.length > 0) {
  console.error(
    `smoke failed: experimental names leaked into the main barrel: ${leaked.join(', ')}`,
  );
  process.exit(1);
}

// 型だけの再エクスポートではなく実際に呼べること（Proxy ラップ越しでも動く）。
const cache = new experimental.ChainVerificationCache();
if (cache.get('missing', Date.now()) !== undefined) {
  console.error('smoke failed: ChainVerificationCache returned a value for an unknown key');
  process.exit(1);
}

// 用途別 entry。パッケージ名で import し、exports マップが ESM 解決で引けることと、
// メインバレルと実体（クラス・関数）を共有していること（`--splitting` の共有チャンク）を確かめる。
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
for (const name of PURPOSE_ENTRIES) {
  const entry = await import(`@vericerts/vericerts-wallet-sdk/${name}`);
  for (const symbol of PURPOSE_ENTRY_SYMBOLS[name]) {
    if (entry[symbol] === undefined || entry[symbol] !== sdk[symbol]) {
      console.error(
        `smoke failed: ./${name} ${symbol} is missing or not shared with the main barrel`,
      );
      process.exit(1);
    }
  }
  let thrown;
  try {
    await PURPOSE_ENTRY_FAILURES[name](entry);
  } catch (error) {
    thrown = error;
  }
  if (!(thrown instanceof sdk.VericertsError)) {
    console.error(
      `smoke failed: an error thrown from ./${name} is not an instanceof the main barrel VericertsError`,
    );
    process.exit(1);
  }
  if (readDist(`exports/${name}.js`).includes('@opentelemetry')) {
    console.error(`smoke failed: dist/exports/${name}.js references @opentelemetry`);
    process.exit(1);
  }
}

await checkAssetWarning(sdk, 'esm');

// サブパス専用の ./aa。公開値が引けて、メインバレルへ流れていないこと。
const aaEntry = await import('@vericerts/vericerts-wallet-sdk/aa');
assert.equal(typeof aaEntry.signUserOpWithPasskey, 'function');
assert.equal(aaEntry.ENTRY_POINT_V07_ADDRESS, '0x0000000071727De22E5E9d8BAf0edAc6f37da032');
for (const name of ['ENTRY_POINT_V07_ADDRESS', 'signUserOpWithPasskey']) {
  assert.equal(sdk[name], undefined, `./aa ${name} leaked into the main barrel`);
}

// ./aa から到達する全チャンクに viem / permissionless が入っていないこと（ビルドの metafile で確かめる）。
// 内部バレル internal/aa/index.ts を経由すると UserOpHash 計算・Bundler 送信の依存が混入する。
// metafile が無い・aa.js の出力や import 先が見つからない場合は失敗させる（fail-closed）。
// ESM の metafile だけを見る。CJS は全サーフェス共有の `_shared.cjs` 1 本なので、entry 単位の分離の検査対象にならない。
const esmMeta = JSON.parse(
  readFileSync(new URL('../.build-meta-esm.json', import.meta.url), 'utf8'),
);
// bun の metafile は output のキーと import の path がいずれも outdir 相対で、`./` の有無だけが揺れる。
const metaKey = (file) => file.replace(/^\.\//, '');
const esmOutputs = new Map(Object.entries(esmMeta.outputs).map(([k, v]) => [metaKey(k), v]));
const aaReachable = new Set();
const aaPending = ['exports/aa.js'];
while (aaPending.length > 0) {
  const file = aaPending.pop();
  if (aaReachable.has(file)) continue;
  const output = esmOutputs.get(file);
  assert.ok(output, `smoke failed: ${file} is missing from .build-meta-esm.json`);
  aaReachable.add(file);
  for (const { path, external } of output.imports ?? []) {
    // external の import は dist の output ではないので辿らない（それ以外の未解決は上の assert で落とす）。
    if (external !== true) aaPending.push(metaKey(path));
  }
}
const aaHeavyInputs = [...aaReachable].flatMap((file) =>
  Object.keys(esmOutputs.get(file).inputs)
    .filter((input) => /node_modules\/(?:viem|permissionless)\//.test(input))
    .map((input) => `${file} <- ${input}`),
);
assert.deepEqual(aaHeavyInputs, [], 'smoke failed: ./aa chunks include viem / permissionless');

// 配布 ESM の追加公開値と共有 DCQL 予算を確認する。
const credentialEntry = await import('@vericerts/vericerts-wallet-sdk/credential');
const oid4vpEntry = await import('@vericerts/vericerts-wallet-sdk/oid4vp');
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

// `./otel` サブパスの解決と公開シンボル。`@opentelemetry/*` は optional peer のため
// external 化されていること（バンドルへインライン展開されていないこと）も実成果物で確かめる。
const otel = await import('@vericerts/vericerts-wallet-sdk/otel');
const requiredOtelExports = ['createOtelLogger', 'createOtelMetrics', 'createOtelTracer'];
const missingOtel = requiredOtelExports.filter((name) => typeof otel[name] !== 'function');
if (missingOtel.length > 0) {
  console.error(`smoke failed: missing otel exports: ${missingOtel.join(', ')}`);
  process.exit(1);
}

const inlinedOtel = [
  'index.js',
  'exports/experimental.js',
  'exports/otel.js',
  ...PURPOSE_ENTRIES.map((name) => `exports/${name}.js`),
].filter((file) => readDist(file).includes('node_modules/@opentelemetry'));
if (inlinedOtel.length > 0) {
  console.error(`smoke failed: @opentelemetry was inlined into: ${inlinedOtel.join(', ')}`);
  process.exit(1);
}
if (!/from\s*["']@opentelemetry\/api["']/.test(readDist('exports/otel.js'))) {
  console.error('smoke failed: dist/exports/otel.js does not import @opentelemetry/api as a peer');
  process.exit(1);
}

console.log(
  `smoke ok: SDK_VERSION=${SDK_VERSION}, public exports=${requiredExports.length}, experimental subpath exports=${requiredExperimentalExports.length}, purpose entries=${PURPOSE_ENTRIES.length}`,
);
