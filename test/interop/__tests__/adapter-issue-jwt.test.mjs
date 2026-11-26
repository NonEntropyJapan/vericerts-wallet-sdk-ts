// test/interop/__tests__/adapter-issue-jwt.test.mjs
//
// 相互運用アダプタ（vericerts / veramo）が発行する JWT-VC の JWS ヘッダに `kid`（`<did>#<fragment>`、
// did:key は `did:key:Z#Z`）が載ることの回帰テスト。
//
// didkit-http（ssi crate）は JWT-VC の検証鍵をヘッダの `kid` からのみ解決し、`kid` の無い JWT を
// `missing public key`（HTTP 400）で拒否する。`kid` を省いても VCDM 1.1 §6.3.1 上は規格違反でない
// ため、didkit ペアの fail は発行側アダプタが `kid` を出すことで解消する。
//
// パッケージをインストールした consumer で `bun test` を実行する（README 参照）。
// Veramo アダプタの発行関数は agent を引数で受けるため、スタブ agent で呼び出し引数を検証する
// （実 Veramo での発行は `adapter-issue-jwt.veramo.test.mjs`、didkit-http での検証は Nightly の
// `interop:veramo:didkit` が担う）。

import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';
import {
  didDocumentToVerifierKey,
  verifyCredential,
} from '@vericerts/vericerts-wallet-sdk/credential';
import { createDidKey, resolveDidKey } from '@vericerts/vericerts-wallet-sdk/identity';
import {
  didKeyVerificationMethod,
  issueJwtVc as issueVeramoJwtVc,
} from '../adapters/veramo/issue-jwt.mjs';
import {
  createIssuerSigner,
  issueJwtVc as issueVericertsJwtVc,
} from '../adapters/vericerts/issue-jwt.mjs';
import { handleVerify } from '../adapters/vericerts/server.mjs';

const FIXTURE = JSON.parse(
  readFileSync(new URL('../fixtures/vericerts-issuer.json', import.meta.url), 'utf8'),
);

/** did:key の検証メソッド DID URL（`did:key:Z#Z`: フラグメントはメソッド固有 ID と同一）。 */
const DID_KEY_VM = /^(did:key:(z[1-9A-HJ-NP-Za-km-z]+))#\2$/;

function decodeJwtHeader(jwt) {
  const [headerB64] = jwt.split('.');
  return JSON.parse(Buffer.from(headerB64, 'base64url').toString('utf8'));
}

test('vericerts adapter: JWT-VC の JWS ヘッダに kid=<did>#<fragment> を載せる', () => {
  const signer = createIssuerSigner(FIXTURE);
  const jwt = issueVericertsJwtVc(FIXTURE, signer, { name: 'x' }, new Date('2026-01-01T00:00:00Z'));

  const header = decodeJwtHeader(jwt);
  assert.equal(header.alg, 'EdDSA');
  assert.equal(header.typ, 'JWT');
  assert.equal(header.kid, FIXTURE.verificationMethod);
  const match = DID_KEY_VM.exec(header.kid);
  assert.ok(match, `kid が did:key:Z#Z 形式でない: ${header.kid}`);
  assert.equal(match[1], FIXTURE.did, 'kid の DID 部分が発行者 DID と一致しない');
});

test('vericerts adapter: kid 付き JWT-VC も SDK の verifyCredential で検証できる', () => {
  const signer = createIssuerSigner(FIXTURE);
  const jwt = issueVericertsJwtVc(FIXTURE, signer, {}, new Date());

  const result = verifyCredential(jwt, { key: { publicKeyJwk: FIXTURE.publicKeyJwk } });
  assert.equal(result.payload.iss, FIXTURE.did);
});

test('veramo adapter: createVerifiableCredential に header.kid=<did>#<fragment> を渡す', async () => {
  const did = FIXTURE.did;
  const calls = [];
  const agent = {
    async createVerifiableCredential(args) {
      calls.push(args);
      return { proof: { jwt: 'stub.jwt.token' } };
    },
  };

  const jwt = await issueVeramoJwtVc(agent, { did }, { name: 'x' });

  assert.equal(jwt, 'stub.jwt.token');
  assert.equal(calls.length, 1);
  const [args] = calls;
  assert.equal(args.proofFormat, 'jwt');
  assert.equal(args.credential.issuer.id, did);
  assert.deepEqual(args.credential.credentialSubject, { id: did, name: 'x' });
  assert.equal(args.header.kid, FIXTURE.verificationMethod);
  assert.ok(DID_KEY_VM.test(args.header.kid), `kid が did:key:Z#Z 形式でない: ${args.header.kid}`);
});

test('veramo adapter: didKeyVerificationMethod は did:key 以外を拒否する', () => {
  assert.equal(didKeyVerificationMethod(FIXTURE.did), FIXTURE.verificationMethod);
  assert.throws(() => didKeyVerificationMethod('did:web:example.com'), /did:key/);
});

test('vericerts adapter: 公開 DID API で Ed25519 発行者鍵を解決し、不正な鍵を拒否する', async () => {
  const verify = (jwt) =>
    handleVerify(
      new Request('http://adapter.test/vc/verify', {
        method: 'POST',
        body: JSON.stringify({ jwt }),
      }),
    );
  const { publicKeyJwk } = didDocumentToVerifierKey(resolveDidKey(FIXTURE.did));
  assert.deepEqual(publicKeyJwk, FIXTURE.publicKeyJwk);

  const signer = createIssuerSigner(FIXTURE);
  const response = await verify(issueVericertsJwtVc(FIXTURE, signer, {}, new Date()));
  assert.equal(response.status, 200);
  assert.deepEqual(await response.json(), { verified: true, issuer: FIXTURE.did });

  const p256 = createDidKey(
    'P-256',
    Buffer.from('036b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296', 'hex'),
  ).id;
  const invalid = [
    ['did:web:example.test', /unsupported issuer DID method/],
    ['did:key:z0', /^cannot resolve issuer did:key:/],
    ['did:key:z2', /^cannot resolve issuer did:key:/],
    ['did:key:zK36', /^cannot resolve issuer did:key:/], // Ed25519 codec without its key bytes.
    [p256, /unsupported did:key codec \(expected Ed25519 0xed01\)/],
  ];
  for (const [iss, reason] of invalid) {
    const payload = Buffer.from(JSON.stringify({ iss })).toString('base64url');
    const rejected = await verify(`header.${payload}.signature`);
    assert.equal(rejected.status, 200, iss);
    const body = await rejected.json();
    assert.equal(body.verified, false, iss);
    assert.match(body.error, /^cannot resolve issuer did:key:/, iss);
    assert.match(body.error, reason, iss);
  }
});
