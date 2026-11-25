/**
 * Remote Signer（KMS / HSM 外部署名）アダプタのユニットテスト（実鍵・モック禁止）。
 *
 * 外部署名サービスは「秘密鍵を閉じ込めた async クロージャ（fake KMS）」で代替し、SDK 側へは
 * 署名関数のみを渡す。検証は既存の `verifyCredential` / `verifySdJwt` 経路をそのまま用いる。
 *
 * 検証内容:
 * - fake KMS + `issueCredentialAsync` の JWT-VC が既存検証経路で通る（ES256）。
 * - fake KMS + `createSdJwtAsync` の SD-JWT VC が既存検証経路で通る（受入条件）。
 * - `signatureFormat: 'der'` の DER 署名を 64B raw へ変換して発行できる（ES256 / ES256K）。
 * - `messageFormat: 'digest'` で外部へ渡るのが sha256(signing-input) の 32B である。
 * - `kid` の header 反映と、未設定時の `issueCredential` とのバイト一致（local signer 後方互換）。
 *
 * 秘密情報の非漏洩は `remote-signer.security.test.ts`、EdDSA（Ed25519）経路は
 * `remote-signer.eddsa.test.ts`、未対応 alg の拒否は `remote-signer.alg.test.ts` で検証する。
 */

import { describe, expect, it } from 'bun:test';
import { sha256 } from '@noble/hashes/sha2.js';
import type { PublicKeyJwk } from '../../../../identity/did.js';
import { createRemoteSigner } from '../../../../keymanager/jws/remote-signer.js';
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
import { issueCredential, issueCredentialAsync } from '../../issue.js';
import type { CredentialAlg } from '../../jws.js';
import { createPrivateKeySigner } from '../../signer.js';
import type { VerifiableCredential } from '../../vc.js';
import { verifyCredential } from '../../verify.js';

/** ECDSA ベースの alg のみ（EdDSA は DER / low-S を持たないため本 suite の対象外）。 */
type EcdsaCredentialAlg = Exclude<CredentialAlg, 'EdDSA'>;

/** fake KMS が保持する秘密鍵（SDK 側へは一切渡さない）。 */
const KMS_P256_KEY = new Uint8Array(32).fill(23);
const KMS_SECP_KEY = new Uint8Array(32).fill(29);

/** テスト用の固定現在時刻・発行日時・有効期限。 */
const NOW = 1_767_225_600;
const ISSUANCE = '2025-12-01T00:00:00Z';
const EXPIRATION = '2027-01-01T00:00:00Z';

/** 非圧縮公開鍵（0x04 || x || y）から EC 公開鍵 JWK を構築する。 */
function toJwk(pub: Uint8Array, crv: string): PublicKeyJwk {
  const b64u = (b: Uint8Array): string => Buffer.from(b).toString('base64url');
  return { kty: 'EC', crv, x: b64u(pub.subarray(1, 33)), y: b64u(pub.subarray(33, 65)) };
}

/** alg ごとの fake KMS 鍵・公開鍵 JWK・曲線。 */
const FIXTURES: Record<
  EcdsaCredentialAlg,
  { readonly privateKey: Uint8Array; readonly jwk: PublicKeyJwk; readonly curve: EcdsaCurve }
> = {
  ES256: {
    privateKey: KMS_P256_KEY,
    jwk: toJwk(getP256PublicKey(KMS_P256_KEY, false), 'P-256'),
    curve: 'p256',
  },
  ES256K: {
    privateKey: KMS_SECP_KEY,
    jwk: toJwk(getSecp256k1PublicKey(KMS_SECP_KEY, false), 'secp256k1'),
    curve: 'secp256k1',
  },
};

/** digest に対する 64B raw 署名（alg 別）。 */
function rawSign(alg: EcdsaCredentialAlg, digest: Uint8Array): Uint8Array {
  const { privateKey } = FIXTURES[alg];
  return alg === 'ES256'
    ? signP256(digest, privateKey)
    : signSecp256k1Recoverable(digest, privateKey).signature.subarray(0, 64);
}

/** fake KMS の挙動設定（外部サービスの入出力表現を模す）。 */
interface FakeKmsOptions {
  /** 受け取る message が digest 済みか（`messageFormat: 'digest'` と対応させる）。 */
  readonly prehashed?: boolean;
  /** DER 署名を返すか（`signatureFormat: 'der'` と対応させる）。 */
  readonly der?: boolean;
  /** 受け取った message を記録する（digest 形式の検証用）。 */
  readonly received?: Uint8Array[];
}

/**
 * 秘密鍵をクロージャに閉じ込めた fake KMS 署名関数を作る。
 *
 * SDK には本関数だけを渡し、鍵 material は一切渡さない（Remote Signer の前提）。
 */
function fakeKms(
  alg: EcdsaCredentialAlg,
  opts: FakeKmsOptions = {},
): (message: Uint8Array) => Promise<Uint8Array> {
  return async (message: Uint8Array): Promise<Uint8Array> => {
    opts.received?.push(message);
    const digest = opts.prehashed === true ? message : sha256(message);
    const raw = rawSign(alg, digest);
    return opts.der === true ? p1363ToDer(raw, FIXTURES[alg].curve) : raw;
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
    id: 'urn:uuid:1234',
  };
}

/** JWT のヘッダセグメントをデコードする。 */
function decodeHeader(jwt: string): Record<string, unknown> {
  const headerSeg = jwt.split('.')[0] ?? '';
  return JSON.parse(Buffer.from(headerSeg, 'base64url').toString('utf-8'));
}

describe('createRemoteSigner + issueCredentialAsync（JWT-VC）', () => {
  it('外部署名関数（fake KMS）で発行した JWT-VC が既存検証経路で通る', async () => {
    const signer = createRemoteSigner({
      alg: 'ES256',
      publicKeyJwk: FIXTURES.ES256.jwk,
      sign: fakeKms('ES256'),
    });
    const jwt = await issueCredentialAsync(sampleVc(), signer, { nowSeconds: NOW });
    const result = verifyCredential(jwt, {
      key: { publicKeyJwk: FIXTURES.ES256.jwk },
      nowSeconds: NOW,
    });
    expect(result.header.alg).toBe('ES256');
    expect(result.header.typ).toBe('JWT');
    expect(result.payload.iss).toBe('did:example:issuer');
    expect((result.payload.vc as VerifiableCredential).credentialSubject.name).toBe('Alice');
  });

  it('同期の外部署名関数（Uint8Array を直接返す）も受け付ける', async () => {
    const signer = createRemoteSigner({
      alg: 'ES256',
      publicKeyJwk: FIXTURES.ES256.jwk,
      sign: (message) => rawSign('ES256', sha256(message)),
    });
    const jwt = await issueCredentialAsync(sampleVc(), signer, { nowSeconds: NOW });
    expect(() =>
      verifyCredential(jwt, { key: { publicKeyJwk: FIXTURES.ES256.jwk }, nowSeconds: NOW }),
    ).not.toThrow();
  });

  it.each<EcdsaCredentialAlg>([
    'ES256',
    'ES256K',
  ])('signatureFormat: der の DER 署名を raw へ変換して発行できる（%s）', async (alg) => {
    const signer = createRemoteSigner({
      alg,
      publicKeyJwk: FIXTURES[alg].jwk,
      signatureFormat: 'der',
      sign: fakeKms(alg, { der: true }),
    });
    const jwt = await issueCredentialAsync(sampleVc(), signer, { nowSeconds: NOW });
    const result = verifyCredential(jwt, {
      key: { publicKeyJwk: FIXTURES[alg].jwk },
      nowSeconds: NOW,
    });
    expect(result.header.alg).toBe(alg);
  });

  it('messageFormat: digest では sha256(signing-input) の 32B が外部へ渡る', async () => {
    const received: Uint8Array[] = [];
    const signer = createRemoteSigner({
      alg: 'ES256',
      publicKeyJwk: FIXTURES.ES256.jwk,
      messageFormat: 'digest',
      sign: fakeKms('ES256', { prehashed: true, received }),
    });
    const jwt = await issueCredentialAsync(sampleVc(), signer, { nowSeconds: NOW });
    const parts = jwt.split('.');
    const signingInput = `${parts[0]}.${parts[1]}`;
    const message = received[0];
    expect(message?.length).toBe(32);
    expect(message).toEqual(sha256(new TextEncoder().encode(signingInput)));
    expect(() =>
      verifyCredential(jwt, { key: { publicKeyJwk: FIXTURES.ES256.jwk }, nowSeconds: NOW }),
    ).not.toThrow();
  });

  it('kid 設定時は JWS ヘッダに kid が載る', async () => {
    const signer = createRemoteSigner({
      alg: 'ES256',
      publicKeyJwk: FIXTURES.ES256.jwk,
      kid: 'arn:aws:kms:ap-northeast-1:111122223333:key/abcd#key-1',
      sign: fakeKms('ES256'),
    });
    const jwt = await issueCredentialAsync(sampleVc(), signer, { nowSeconds: NOW });
    expect(decodeHeader(jwt)).toEqual({
      alg: 'ES256',
      kid: 'arn:aws:kms:ap-northeast-1:111122223333:key/abcd#key-1',
      typ: 'JWT',
    });
    expect(() =>
      verifyCredential(jwt, { key: { publicKeyJwk: FIXTURES.ES256.jwk }, nowSeconds: NOW }),
    ).not.toThrow();
  });

  it('kid 未設定なら header は従来どおり { alg, typ } のみ', async () => {
    const signer = createRemoteSigner({
      alg: 'ES256',
      publicKeyJwk: FIXTURES.ES256.jwk,
      sign: fakeKms('ES256'),
    });
    const jwt = await issueCredentialAsync(sampleVc(), signer, { nowSeconds: NOW });
    const headerSeg = jwt.split('.')[0] ?? '';
    expect(Buffer.from(headerSeg, 'base64url').toString('utf-8')).toBe(
      '{"alg":"ES256","typ":"JWT"}',
    );
  });

  it('local signer（同期）を渡すと issueCredential とバイト単位で一致する', async () => {
    const localSigner = createPrivateKeySigner(KMS_P256_KEY, 'ES256');
    const vc = sampleVc();
    expect(await issueCredentialAsync(vc, localSigner, { nowSeconds: NOW })).toBe(
      issueCredential(vc, localSigner, { nowSeconds: NOW }),
    );
  });
});

describe('createRemoteSigner + createSdJwtAsync（SD-JWT VC）', () => {
  const VCT = 'https://example.com/credentials/identity';

  it('外部署名関数で発行した SD-JWT VC が既存検証経路で通る', async () => {
    const signer = createRemoteSigner({
      alg: 'ES256',
      publicKeyJwk: FIXTURES.ES256.jwk,
      kid: 'kms-key-1',
      sign: fakeKms('ES256'),
    });
    const sdJwt = await createSdJwtAsync(signer, {
      vct: VCT,
      issuer: 'did:example:issuer',
      disclosureClaims: ['name', 'age_over_18'],
      claims: { name: 'Alice', age_over_18: true, sub: 'did:example:holder' },
      salts: { name: 'salt-name', age_over_18: 'salt-age' },
    });
    const result = verifySdJwt(sdJwt, { issuerKey: FIXTURES.ES256.jwk, expectedVct: VCT });
    expect(result.vct).toBe(VCT);
    expect(result.claims.name).toBe('Alice');
    expect(result.claims.age_over_18).toBe(true);
    expect(result.claims.sub).toBe('did:example:holder');
    expect(decodeHeader(sdJwt.split('~')[0] ?? '').kid).toBe('kms-key-1');
  });

  it('DER 署名の外部サービスでも SD-JWT VC を発行・検証できる', async () => {
    const signer = createRemoteSigner({
      alg: 'ES256',
      publicKeyJwk: FIXTURES.ES256.jwk,
      messageFormat: 'digest',
      signatureFormat: 'der',
      sign: fakeKms('ES256', { prehashed: true, der: true }),
    });
    const sdJwt = await createSdJwtAsync(signer, {
      vct: VCT,
      disclosureClaims: ['name'],
      claims: { name: 'Alice' },
      salts: { name: 'salt-name' },
    });
    expect(verifySdJwt(sdJwt, { issuerKey: FIXTURES.ES256.jwk }).claims.name).toBe('Alice');
  });
});
