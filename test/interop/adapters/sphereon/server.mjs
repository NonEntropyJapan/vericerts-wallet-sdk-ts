// test/interop/adapters/sphereon/server.mjs
//
// Sphereon SSI-SDK（実ライブラリ・npm 公式パッケージ、モックなし）を相互運用テスト harness の
// ネイティブ VC-API 契約（`GET /health`・`GET /did`・`POST /credentials/issue`・
// `POST /credentials/verify`、test/interop/adapters/didkit 相当。didkit は外部イメージなので
// アダプタは持たない）で公開する薄いアダプタ。
//
// 背景: `@sphereon/ssi-sdk.credential-vcdm`（JWT 発行を含む汎用プラグイン）は
// 独自の `IVcdmCredentialProvider` インターフェース（`canIssueCredentialType` 等）を要求し、
// Veramo 標準の `@veramo/credential-jwt` の `CredentialProviderJWT` はこれを実装しないため
// 組み込めない（TypeError）。一方 `@sphereon/ssi-sdk.credential-vcdm-jsonld-provider`
// （JSON-LD/LD-Proof 発行）はこのインターフェースを正しく実装している。よってこのアダプタは
// LD-Proof で発行し（`interop:sphereon:sphereon` 自己ループ）、検証は LD-Proof（自己発行分）と
// JWT-VC（uniform ピアが発行したコンパクト JWT、`interop:vericerts:sphereon` /
// `interop:veramo:sphereon`）の両方を受け付ける。JWT 検証は Veramo プラグインを介さず
// `did-jwt-vc`（`@sphereon/ssi-sdk.credential-vcdm` 自身の推移的依存と同一ライブラリ）を直接
// 呼ぶ — インターフェース不整合を経由しない代替発行/検証経路。
//
// 依存解決の回避策: `@digitalcredentials/http-client@1.2.2`
// （`@veramo-community/lds-ecdsa-secp256k1-recovery2020`・`@sphereon/vc-status-list` 経由）と
// `@digitalbazaar/http-client`（`jsonld-checker` 経由）がいずれも廃止された
// `ky-universal@0.8.2` に依存し、その `require('ky/umd')` が現行 `ky@1.x` の exports map に
// 存在せず `ERR_PACKAGE_PATH_NOT_EXPORTED` になる。`package.json` の `overrides` で両パッケージを
// ky-universal を使わない最新版に固定して回避する。
//
// 発行鍵は test/interop/fixtures/sphereon-issuer.json 固定（相互運用テスト専用、本番鍵ではない）。
// didkit と同様、他ピア（run-peer-matrix.mjs）が事前にこの DID を知っている必要があるため、
// veramo アダプタと異なり起動のたびに新規鍵を生成せず、固定鍵を import する。

import { readFileSync } from 'node:fs';
import { createServer } from 'node:http';
import { VcdmCredentialPlugin } from '@sphereon/ssi-sdk.credential-vcdm';
import {
  CredentialProviderJsonld,
  SphereonEd25519Signature2018,
} from '@sphereon/ssi-sdk.credential-vcdm-jsonld-provider';
import { getDidJwkResolver } from '@sphereon/ssi-sdk-ext.did-resolver-jwk';
import { createAgent } from '@veramo/core';
import { DIDManager, MemoryDIDStore } from '@veramo/did-manager';
import { KeyDIDProvider } from '@veramo/did-provider-key';
import { DIDResolverPlugin } from '@veramo/did-resolver';
import { KeyManager, MemoryKeyStore, MemoryPrivateKeyStore } from '@veramo/key-manager';
import { KeyManagementSystem } from '@veramo/kms-local';
import { verifyCredential as verifyJwtCredential } from 'did-jwt-vc';
import { Resolver } from 'did-resolver';
import { getResolver as getKeyResolver } from 'key-did-resolver';

const FIXTURE = JSON.parse(
  readFileSync(new URL('../../fixtures/sphereon-issuer.json', import.meta.url), 'utf8'),
);

// JWT-VC 検証（`did-jwt-vc`）は did:key だけを解決できればよい一方、DID 解決マトリクス
// では Sphereon の did:jwk も検証する。
// did:jwk の解決器は Sphereon 自身の `@sphereon/ssi-sdk-ext.did-resolver-jwk`（既存の
// `@sphereon/ssi-sdk.*` と同じ 0.40.1 系）で、「Sphereon が解決できるか」を検証する意味を保つ。
// did:web / did:ethr は解決先の HTTPS ホスト・EIP-1056 registry のチェーン fixture が harness に
// 無く、登録しても一度も駆動できないため入れない。
const keyResolver = new Resolver({ ...getKeyResolver(), ...getDidJwkResolver() });

const agent = createAgent({
  plugins: [
    new KeyManager({
      store: new MemoryKeyStore(),
      kms: { local: new KeyManagementSystem(new MemoryPrivateKeyStore()) },
    }),
    new DIDManager({
      store: new MemoryDIDStore(),
      defaultProvider: 'did:key',
      providers: { 'did:key': new KeyDIDProvider({ defaultKms: 'local' }) },
    }),
    new DIDResolverPlugin({ resolver: keyResolver }),
    new VcdmCredentialPlugin({
      issuers: [
        new CredentialProviderJsonld({
          suites: [new SphereonEd25519Signature2018()],
          // did:key は本アダプタの DIDResolverPlugin（key-did-resolver）で解決する。
          documentLoader: {
            localResolution: false,
            uniresolverResolution: false,
            resolverResolution: true,
          },
        }),
      ],
    }),
  ],
});

// 起動のたびに固定鍵（FIXTURE）を import する。他ピアが事前にこの DID を知っている必要が
// あるため（VC-API `/credentials/issue` はリクエスト側が issuer DID を指定する）、didkit と
// 同じく固定鍵を使う。
await agent.didManagerImport({
  did: FIXTURE.did,
  provider: 'did:key',
  controllerKeyId: FIXTURE.verificationMethod,
  keys: [
    {
      kid: FIXTURE.verificationMethod,
      type: FIXTURE.type,
      kms: 'local',
      publicKeyHex: FIXTURE.publicKeyHex,
      privateKeyHex: FIXTURE.privateKeyHex,
    },
  ],
});

const PORT = Number(process.env.PORT ?? 8096);

function readJsonBody(req) {
  return new Promise((resolve, reject) => {
    let raw = '';
    req.on('data', (chunk) => {
      raw += chunk;
    });
    req.on('end', () => {
      if (!raw) {
        resolve({});
        return;
      }
      try {
        resolve(JSON.parse(raw));
      } catch (error) {
        reject(error);
      }
    });
    req.on('error', reject);
  });
}

function sendJson(res, status, body) {
  const payload = JSON.stringify(body);
  res.writeHead(status, { 'content-type': 'application/json' });
  res.end(payload);
}

/** VC-API `/credentials/issue`: LD-Proof（Ed25519Signature2018）で 1 通発行する。 */
async function handleIssue(req, res) {
  const body = await readJsonBody(req);
  const credential = body?.credential;
  if (!credential || typeof credential !== 'object') {
    return sendJson(res, 400, { errors: ['credential is required'] });
  }
  const verifiableCredential = await agent.createVerifiableCredential({
    credential,
    proofFormat: 'lds',
  });
  return sendJson(res, 201, { verifiableCredential });
}

/**
 * VC-API `/credentials/verify`: `verifiableCredential` がコンパクト JWT 文字列なら
 * `did-jwt-vc` で直接検証し（uniform ピア発行分）、JSON-LD オブジェクトなら本アダプタの
 * LD-Proof エージェントで検証する（自己発行分）。
 */
async function handleVerify(req, res) {
  const body = await readJsonBody(req);
  const verifiableCredential = body?.verifiableCredential;
  if (verifiableCredential === undefined) {
    return sendJson(res, 400, { errors: ['verifiableCredential is required'] });
  }
  try {
    if (typeof verifiableCredential === 'string') {
      const result = await verifyJwtCredential(verifiableCredential, keyResolver);
      return sendJson(
        res,
        200,
        result.verified
          ? { checks: ['proof'], warnings: [], errors: [] }
          : { checks: [], warnings: [], errors: ['jwt-vc verification returned verified=false'] },
      );
    }
    const result = await agent.verifyCredential({ credential: verifiableCredential });
    return sendJson(
      res,
      200,
      result.verified
        ? { checks: ['proof'], warnings: [], errors: [] }
        : {
            checks: [],
            warnings: [],
            errors: [result.error?.message ?? 'verification returned verified=false'],
          },
    );
  } catch (error) {
    return sendJson(res, 200, {
      checks: [],
      warnings: [],
      errors: [String(error?.message ?? error)],
    });
  }
}

const IDENTIFIERS_PREFIX = '/identifiers/';

/**
 * DIF DID Resolution HTTPS Binding の `GET /identifiers/{did}`。
 *
 * 解決は Sphereon の解決器を載せた agent の `resolveDid` に委譲し、Resolution Result
 * （`didResolutionMetadata` / `didDocument` / `didDocumentMetadata`）をそのまま返す。
 * 解決できなかった場合は 404 にして、呼び出し側（`run-did-resolution-matrix.mjs`）が 2xx を
 * 「解決できた」と誤認しないようにする。
 */
async function handleResolve(res, pathname) {
  const didUrl = decodeURIComponent(pathname.slice(IDENTIFIERS_PREFIX.length));
  if (didUrl === '') {
    return sendJson(res, 400, { didResolutionMetadata: { error: 'invalidDid' } });
  }
  const result = await agent.resolveDid({ didUrl });
  const error = result?.didResolutionMetadata?.error;
  return sendJson(res, error === undefined || error === null ? 200 : 404, result);
}

const server = createServer(async (req, res) => {
  try {
    // クエリ（DIF Binding の解決オプション）を落としてパスだけで分岐する。
    const { pathname } = new URL(req.url, 'http://localhost');
    if (req.method === 'GET' && pathname.startsWith(IDENTIFIERS_PREFIX)) {
      return await handleResolve(res, pathname);
    }
    if (req.method === 'GET' && req.url === '/health') {
      return sendJson(res, 200, { ok: true });
    }
    if (req.method === 'GET' && req.url === '/did') {
      return sendJson(res, 200, { did: FIXTURE.did });
    }
    if (req.method === 'POST' && req.url === '/credentials/issue') {
      return await handleIssue(req, res);
    }
    if (req.method === 'POST' && req.url === '/credentials/verify') {
      return await handleVerify(req, res);
    }
    return sendJson(res, 404, { error: 'not found' });
  } catch (error) {
    return sendJson(res, 500, { error: String(error) });
  }
});

server.listen(PORT, () => {
  console.log(`[sphereon-peer] listening on :${PORT} (issuer ${FIXTURE.did})`);
});
