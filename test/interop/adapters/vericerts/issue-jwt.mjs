// test/interop/adapters/vericerts/issue-jwt.mjs
//
// vericerts アダプタの JWT-VC 発行部分（`server.mjs` から `/vc/issue` が呼ぶ）。HTTP サーバを
// 起動せずに単体テストできるよう `server.mjs`（import 時に `Bun.serve` を起動する）から分離した。
//
// JWS ヘッダへ `kid`（発行者鍵の DID URL）を載せる。didkit-http（ssi crate）は JWT-VC の検証鍵を
// ヘッダの `kid` からのみ解決し、`kid` が無いと `missing public key`（HTTP 400）で拒否する。
// VCDM 1.1 §6.3.1 では `kid` は MAY のため、`kid` を省くこと自体は規格違反ではない。

import { createPrivateKeySigner, issueCredential } from 'vericerts-wallet-sdk/credential';

/**
 * フィクスチャの固定鍵から、`kid` 付きの `CredentialSigner` を生成する。
 *
 * `CredentialSigner.kid` は SDK の既存の公開フィールド（`issueCredential` が JWS ヘッダへ反映する）。
 *
 * @param fixture `test/interop/fixtures/vericerts-issuer.json` の内容。
 * @returns `kid` に `fixture.verificationMethod`（`did:key:Z#Z`）を持つ署名器。
 */
export function createIssuerSigner(fixture) {
  const seed = Uint8Array.from(Buffer.from(fixture.seedHex, 'hex'));
  return { ...createPrivateKeySigner(seed, fixture.alg), kid: fixture.verificationMethod };
}

/**
 * フィクスチャの発行者として JWT-VC を 1 通発行する。
 *
 * @param fixture `test/interop/fixtures/vericerts-issuer.json` の内容。
 * @param signer `createIssuerSigner(fixture)` が返す署名器。
 * @param subject `credentialSubject` へ展開する追加クレーム。
 * @param now 発行時刻。
 * @returns コンパクト形式の JWT-VC。
 */
export function issueJwtVc(fixture, signer, subject, now) {
  const vc = {
    '@context': ['https://www.w3.org/ns/credentials/v2'],
    type: ['VerifiableCredential'],
    issuer: fixture.did,
    credentialSubject: { id: fixture.did, ...subject },
    issuanceDate: now.toISOString(),
  };
  return issueCredential(vc, signer, { nowSeconds: Math.floor(now.getTime() / 1000) });
}
