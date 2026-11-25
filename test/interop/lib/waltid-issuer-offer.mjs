// test/interop/lib/waltid-issuer-offer.mjs
//
// walt.id issuer-api への Offer 発行要求（Offer → Receive の手順 1）。
// `run-waltid-protocol.mjs` を Linterly の 1 ファイル 300 行上限に収めるため切り出した。

import { readFileSync } from 'node:fs';
import { createPrivateKeySigner } from 'vericerts-wallet-sdk/credential';
import { CREDENTIAL_TYPE, fetchJson, issuerAdminBaseUrl } from './waltid-admin-api.mjs';

const CREDENTIAL_CONFIGURATION_ID = 'OpenBadgeCredential_jwt_vc_json';

const ISSUER_FIXTURE = JSON.parse(
  readFileSync(new URL('../fixtures/waltid-issuer.json', import.meta.url), 'utf8'),
);

/** walt.id issuer-api の JWK 形式へ Ed25519 秘密鍵を変換する。 */
function issuerJwk(seedHex, publicKeyJwk) {
  return {
    kty: 'OKP',
    crv: 'Ed25519',
    x: publicKeyJwk.x,
    d: Buffer.from(seedHex, 'hex').toString('base64url'),
  };
}

/** walt.id issuer-api に Offer 発行を要求する（管理系呼び出し、平文 HTTP で十分。§3.2 手順 1）。 */
export async function createIssuerOffer(fetchImpl = fetch) {
  const adminBaseUrl = issuerAdminBaseUrl();
  const issuerSigner = createPrivateKeySigner(
    Uint8Array.from(Buffer.from(ISSUER_FIXTURE.seedHex, 'hex')),
    ISSUER_FIXTURE.alg,
  );
  const jwk = issuerJwk(ISSUER_FIXTURE.seedHex, issuerSigner.publicKeyJwk);
  const { ok, body } = await fetchJson(
    `${adminBaseUrl}/openid4vc/jwt/issue`,
    {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        issuerKey: { type: 'jwk', jwk },
        issuerDid: ISSUER_FIXTURE.did,
        credentialConfigurationId: CREDENTIAL_CONFIGURATION_ID,
        credentialData: {
          // 本 SDK の `assertVcV2Context`（`credential/presentation/vp.ts`）は VC 2.0 の
          // `https://www.w3.org/ns/credentials/v2` を先頭に要求する。
          // OpenBadge 3.0 の最終仕様（IMS Global）も VC 2.0 準拠のため、この組み合わせが正しい。
          '@context': [
            'https://www.w3.org/ns/credentials/v2',
            'https://purl.imsglobal.org/spec/ob/v3p0/context.json',
          ],
          id: `urn:uuid:${crypto.randomUUID()}`,
          type: ['VerifiableCredential', CREDENTIAL_TYPE],
          name: 'interop-matrix-test',
          // 本 SDK の `verifyCredential`（`credential/vc/verify.ts`）は W3C VC 2.0 の issuer を
          // 簡略形（非空文字列の DID）のみ受理し、OpenBadge 3.0 の慣例である Profile オブジェクト
          // 形（`{ id, type, name }`）は 3002（VC_SCHEMA_INVALID）で拒否する。下記 mapping が
          // 文字列プレースホルダを issuerDid で置き換える。
          issuer: '',
          // walt.id の mapping（下記）が置き換える対象キー。walt.id はテンプレートに存在しない
          // キーへは値を注入しない（Data Functions ドキュメント参照）ため、プレースホルダとして
          // 空文字を用意しておく必要がある。本 SDK の `verifyCredential` / `toReceivedCredential`
          // は `vc.issuanceDate` を必須とするため、欠落すると 8020 / SIG_INVALID で fail する。
          issuanceDate: '',
          expirationDate: '',
          credentialSubject: {
            // walt.id は Credential Request の proof JWT `iss`（Holder DID）を envelope の `sub`
            // クレームへ常に載せる。本 SDK の `verifyCredential` は `sub` と `vc.credentialSubject.id`
            // の自己整合を要求する（confused deputy 対策、`credential/vc/verify.ts`）ため、
            // `credentialSubject.id` を欠くと `sub` だけが載った不整合な VC になり 3002 で拒否される。
            // 下記 `mapping.credentialSubject.id` が Holder DID で埋める。
            id: '',
            type: ['AchievementSubject'],
            achievement: {
              id: `urn:uuid:${crypto.randomUUID()}`,
              type: ['Achievement'],
              name: 'interop-matrix-test',
            },
          },
        },
        mapping: {
          id: '<uuid>',
          issuer: '<issuerDid>',
          issuanceDate: '<timestamp>',
          expirationDate: '<timestamp-in:365d>',
          credentialSubject: { id: '<subjectDid>' },
        },
      }),
    },
    fetchImpl,
  );
  if (!ok || typeof body !== 'string' || !body.startsWith('openid-credential-offer://')) {
    throw new Error(`waltid-issuer offer creation failed: ${JSON.stringify(body)}`);
  }
  return { offerUri: body, issuerPublicKeyJwk: issuerSigner.publicKeyJwk };
}
