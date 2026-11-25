/**
 * Remote Signer（KMS / HSM 外部署名）の EdDSA（Ed25519）経路のユニットテスト（実鍵・モック禁止）。
 *
 * ECDSA 経路（DER 変換・low-S 正規化を含む）は `remote-signer.test.ts` /
 * `remote-signer.lows.test.ts` が担当し、本ファイルは PureEdDSA 固有の差異のみを検証する。
 *
 * 検証内容:
 * - EdDSA の外部署名で発行した JWT-VC / SD-JWT VC が既存検証経路で通る。
 * - 外部署名関数へは事前ハッシュせず signing-input がそのまま渡る（PureEdDSA）。
 * - local signer（`createPrivateKeySigner`）と同一バイトの JWT-VC を生成する。
 * - ECDSA 専用の `messageFormat: 'digest'` / `signatureFormat: 'der'` は構築時に
 *   UNSUPPORTED_ALGORITHM（1030）で弾かれる（誤設定で検証不能な VC を作らせない）。
 */

import { describe, expect, it } from 'bun:test';
import { ErrorCodes, VericertsError } from '../../../../errors.js';
import type { PublicKeyJwk } from '../../../../identity/did.js';
import { getEd25519PublicKey, signEd25519 } from '../../../../keymanager/ed25519.js';
import { createRemoteSigner } from '../../../../keymanager/jws/remote-signer.js';
import { createSdJwtAsync } from '../../../sdjwt/sdjwt.js';
import { verifySdJwt } from '../../../sdjwt/verify.js';
import { issueCredential, issueCredentialAsync } from '../../issue.js';
import { createPrivateKeySigner } from '../../signer.js';
import type { VerifiableCredential } from '../../vc.js';
import { verifyCredential } from '../../verify.js';

/** テスト用の固定現在時刻・発行日時・有効期限。 */
const NOW = 1_767_225_600;
const ISSUANCE = '2025-12-01T00:00:00Z';
const EXPIRATION = '2027-01-01T00:00:00Z';

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

describe('createRemoteSigner（EdDSA / Ed25519）', () => {
  /** fake KMS が保持する Ed25519 シード（SDK 側へは一切渡さない）。 */
  const KMS_ED_SEED = new Uint8Array(32).fill(37);

  /** Ed25519 公開鍵から OKP 公開鍵 JWK を構築する（RFC 8037。y を持たない）。 */
  const ED_JWK: PublicKeyJwk = {
    kty: 'OKP',
    crv: 'Ed25519',
    x: Buffer.from(getEd25519PublicKey(KMS_ED_SEED)).toString('base64url'),
  };

  /**
   * PureEdDSA の fake KMS。受け取ったメッセージをそのまま Ed25519 署名する
   * （事前ハッシュしない点が ECDSA の fake KMS と異なる）。
   */
  function edKms(received?: Uint8Array[]): (message: Uint8Array) => Promise<Uint8Array> {
    return async (message: Uint8Array): Promise<Uint8Array> => {
      received?.push(message);
      return signEd25519(message, KMS_ED_SEED);
    };
  }

  it('外部署名関数で発行した JWT-VC が既存検証経路で通る', async () => {
    const signer = createRemoteSigner({ alg: 'EdDSA', publicKeyJwk: ED_JWK, sign: edKms() });
    const jwt = await issueCredentialAsync(sampleVc(), signer, { nowSeconds: NOW });
    const result = verifyCredential(jwt, { key: { publicKeyJwk: ED_JWK }, nowSeconds: NOW });
    expect(result.header.alg).toBe('EdDSA');
    expect(result.header.typ).toBe('JWT');
    expect((result.payload.vc as VerifiableCredential).credentialSubject.name).toBe('Alice');
  });

  it('外部署名関数で発行した SD-JWT VC が既存検証経路で通る', async () => {
    const vct = 'https://example.com/credentials/identity';
    const signer = createRemoteSigner({
      alg: 'EdDSA',
      publicKeyJwk: ED_JWK,
      kid: 'kms-ed-1',
      sign: edKms(),
    });
    const sdJwt = await createSdJwtAsync(signer, {
      vct,
      issuer: 'did:example:issuer',
      disclosureClaims: ['name'],
      claims: { name: 'Alice', sub: 'did:example:holder' },
      salts: { name: 'salt-name' },
    });
    const result = verifySdJwt(sdJwt, { issuerKey: ED_JWK, expectedVct: vct });
    expect(result.claims.name).toBe('Alice');
    expect(decodeHeader(sdJwt.split('~')[0] ?? '').kid).toBe('kms-ed-1');
  });

  it('外部署名関数へは事前ハッシュせず signing-input がそのまま渡る（PureEdDSA）', async () => {
    const received: Uint8Array[] = [];
    const signer = createRemoteSigner({
      alg: 'EdDSA',
      publicKeyJwk: ED_JWK,
      sign: edKms(received),
    });
    const jwt = await issueCredentialAsync(sampleVc(), signer, { nowSeconds: NOW });
    const signingInput = jwt.split('.').slice(0, 2).join('.');
    expect(received).toHaveLength(1);
    expect(Buffer.from(received[0] as Uint8Array).toString('utf-8')).toBe(signingInput);
  });

  it('local signer（createPrivateKeySigner）と同一の JWT-VC を生成する', async () => {
    const remote = createRemoteSigner({ alg: 'EdDSA', publicKeyJwk: ED_JWK, sign: edKms() });
    const local = createPrivateKeySigner(KMS_ED_SEED, 'EdDSA');
    const vc = sampleVc();
    expect(await issueCredentialAsync(vc, remote, { nowSeconds: NOW })).toBe(
      issueCredential(vc, local, { nowSeconds: NOW }),
    );
  });

  it('messageFormat: digest は UNSUPPORTED_ALGORITHM（1030）で弾く', () => {
    expect(() =>
      createRemoteSigner({
        alg: 'EdDSA',
        publicKeyJwk: ED_JWK,
        messageFormat: 'digest',
        sign: edKms(),
      }),
    ).toThrow(new VericertsError(ErrorCodes.UNSUPPORTED_ALGORITHM));
  });

  it('signatureFormat: der は UNSUPPORTED_ALGORITHM（1030）で弾く', () => {
    expect(() =>
      createRemoteSigner({
        alg: 'EdDSA',
        publicKeyJwk: ED_JWK,
        signatureFormat: 'der',
        sign: edKms(),
      }),
    ).toThrow(new VericertsError(ErrorCodes.UNSUPPORTED_ALGORITHM));
  });
});
