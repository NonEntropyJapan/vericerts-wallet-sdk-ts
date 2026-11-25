/**
 * Remote Signer の low-S 正規化に対する回帰テスト（実鍵・モック禁止）。
 *
 * AWS KMS / PKCS#11 トークン等の外部署名サービスは high-S（`s > n/2`）の ECDSA 署名を正当に返す。
 * SDK の JWS 検証は ES256 の high-S も受理するが、ES256K（常に low-S のみ）や、署名バイト列を
 * 識別子に使う経路（DPoP / did:jwt）、他実装の検証者のため、adapter は発行側で low-S へ揃える。
 *
 * ここでは「必ず high-S を返す fake KMS」を用意し、`createRemoteSigner` 経由で発行した
 * credential が既存の `verifyCredential` / `verifySdJwt` 経路で通ることを確認する。
 * `signatureFormat` の `raw` / `der` 両経路（DER 経路は `derToP1363` を通るがこちらも
 * 正規化しない）と `ES256` / `ES256K` 両 alg を網羅する。
 *
 * 秘密鍵は fake KMS のクロージャに閉じ込め、SDK には署名関数のみを渡す。
 */

import { describe, expect, it } from 'bun:test';
import { p256 } from '@noble/curves/nist.js';
import { secp256k1 } from '@noble/curves/secp256k1.js';
import { sha256 } from '@noble/hashes/sha2.js';
import type { PublicKeyJwk } from '../../../../identity/did.js';
import {
  createRemoteSigner,
  type RemoteSignatureFormat,
} from '../../../../keymanager/jws/remote-signer.js';
import {
  type EcdsaCurve,
  getP256PublicKey,
  getSecp256k1PublicKey,
  p1363ToDer,
  signP256,
  signSecp256k1Recoverable,
} from '../../../../keymanager/signer.js';
import { createSdJwtAsync } from '../../../sdjwt/sdjwt.js';
import { verifySdJwt } from '../../../sdjwt/verify.js';
import { issueCredentialAsync } from '../../issue.js';
import type { CredentialAlg } from '../../jws.js';
import type { VerifiableCredential } from '../../vc.js';
import { verifyCredential } from '../../verify.js';

/** ECDSA ベースの alg のみ（EdDSA は DER / low-S を持たないため本 suite の対象外）。 */
type EcdsaCredentialAlg = Exclude<CredentialAlg, 'EdDSA'>;

/** fake KMS が保持する秘密鍵（SDK 側へは一切渡さない）。 */
const KMS_P256_KEY = new Uint8Array(32).fill(41);
const KMS_SECP_KEY = new Uint8Array(32).fill(43);

/** テスト用の固定現在時刻・発行日時・有効期限。 */
const NOW = 1_767_225_600;
const ISSUANCE = '2025-12-01T00:00:00Z';
const EXPIRATION = '2027-01-01T00:00:00Z';

/** 非圧縮公開鍵（0x04 || x || y）から EC 公開鍵 JWK を構築する。 */
function toJwk(pub: Uint8Array, crv: string): PublicKeyJwk {
  const b64u = (b: Uint8Array): string => Buffer.from(b).toString('base64url');
  return { kty: 'EC', crv, x: b64u(pub.subarray(1, 33)), y: b64u(pub.subarray(33, 65)) };
}

/** alg ごとの fake KMS 鍵・公開鍵 JWK・曲線・`@noble` の ECDSA 実装。 */
const FIXTURES: Record<
  EcdsaCredentialAlg,
  {
    readonly privateKey: Uint8Array;
    readonly jwk: PublicKeyJwk;
    readonly curve: EcdsaCurve;
    readonly ec: typeof secp256k1;
  }
> = {
  ES256: {
    privateKey: KMS_P256_KEY,
    jwk: toJwk(getP256PublicKey(KMS_P256_KEY, false), 'P-256'),
    curve: 'p256',
    ec: p256,
  },
  ES256K: {
    privateKey: KMS_SECP_KEY,
    jwk: toJwk(getSecp256k1PublicKey(KMS_SECP_KEY, false), 'secp256k1'),
    curve: 'secp256k1',
    ec: secp256k1,
  },
};

/**
 * digest に対して必ず high-S の 64B raw 署名を返す。
 *
 * `@noble` の `sign()` は low-S を返すため、`s` を `n - s` に置き換えて high-S を強制する
 * （ECDSA では `(r, n - s)` も同一鍵・同一 digest に対して有効な署名）。
 */
function highSRawSign(alg: EcdsaCredentialAlg, digest: Uint8Array): Uint8Array {
  const { privateKey, ec } = FIXTURES[alg];
  const lowS =
    alg === 'ES256'
      ? signP256(digest, privateKey)
      : signSecp256k1Recoverable(digest, privateKey).signature.subarray(0, 64);
  const sig = ec.Signature.fromBytes(lowS, 'compact');
  const flipped = new ec.Signature(sig.r, ec.Point.Fn.ORDER - sig.s);
  // 本テストの前提（high-S を確実に生成できていること）を明示的に固定する。
  expect(flipped.hasHighS()).toBe(true);
  return flipped.toBytes('compact');
}

/** 必ず high-S 署名を返す fake KMS（`signatureFormat` に応じて raw / DER を返す）。 */
function highSKms(
  alg: EcdsaCredentialAlg,
  format: RemoteSignatureFormat,
): (message: Uint8Array) => Promise<Uint8Array> {
  return async (message: Uint8Array): Promise<Uint8Array> => {
    const raw = highSRawSign(alg, sha256(message));
    return format === 'der' ? p1363ToDer(raw, FIXTURES[alg].curve) : raw;
  };
}

/** サンプル VC を作る。 */
function sampleVc(): VerifiableCredential {
  return {
    '@context': ['https://www.w3.org/ns/credentials/v2'],
    type: ['VerifiableCredential'],
    issuer: 'did:example:issuer',
    credentialSubject: { id: 'did:example:subject', name: 'Alice' },
    issuanceDate: ISSUANCE,
    expirationDate: EXPIRATION,
    id: 'urn:uuid:high-s',
  };
}

/** JWT の署名セグメントを 64B raw 署名として取り出す。 */
function signatureOf(jwt: string): Uint8Array {
  return new Uint8Array(Buffer.from(jwt.split('.')[2] ?? '', 'base64url'));
}

/** alg × signatureFormat の全組み合わせ。 */
const CASES: readonly (readonly [EcdsaCredentialAlg, RemoteSignatureFormat])[] = [
  ['ES256', 'raw'],
  ['ES256', 'der'],
  ['ES256K', 'raw'],
  ['ES256K', 'der'],
];

describe('createRemoteSigner の low-S 正規化（high-S を返す KMS への回帰テスト）', () => {
  it.each(
    CASES,
  )('high-S 署名を返す KMS でも JWT-VC が既存検証経路で通る（%s / %s）', async (alg, signatureFormat) => {
    const signer = createRemoteSigner({
      alg,
      publicKeyJwk: FIXTURES[alg].jwk,
      signatureFormat,
      sign: highSKms(alg, signatureFormat),
    });
    const jwt = await issueCredentialAsync(sampleVc(), signer, { nowSeconds: NOW });
    const result = verifyCredential(jwt, {
      key: { publicKeyJwk: FIXTURES[alg].jwk },
      nowSeconds: NOW,
    });
    expect(result.header.alg).toBe(alg);
    expect((result.payload.vc as VerifiableCredential).credentialSubject.name).toBe('Alice');
  });

  it.each(
    CASES,
  )('JWS へ載る署名そのものが low-S に正規化されている（%s / %s）', async (alg, signatureFormat) => {
    const signer = createRemoteSigner({
      alg,
      publicKeyJwk: FIXTURES[alg].jwk,
      signatureFormat,
      sign: highSKms(alg, signatureFormat),
    });
    const jwt = await issueCredentialAsync(sampleVc(), signer, { nowSeconds: NOW });
    const raw = signatureOf(jwt);
    expect(raw.length).toBe(64);
    expect(FIXTURES[alg].ec.Signature.fromBytes(raw, 'compact').hasHighS()).toBe(false);
  });

  it('high-S 署名を返す KMS でも SD-JWT VC が既存検証経路で通る', async () => {
    const vct = 'https://example.com/credentials/identity';
    const signer = createRemoteSigner({
      alg: 'ES256',
      publicKeyJwk: FIXTURES.ES256.jwk,
      sign: highSKms('ES256', 'raw'),
    });
    const sdJwt = await createSdJwtAsync(signer, {
      vct,
      issuer: 'did:example:issuer',
      disclosureClaims: ['name'],
      claims: { name: 'Alice' },
      salts: { name: 'salt-name' },
    });
    expect(
      verifySdJwt(sdJwt, { issuerKey: FIXTURES.ES256.jwk, expectedVct: vct }).claims.name,
    ).toBe('Alice');
  });
});
