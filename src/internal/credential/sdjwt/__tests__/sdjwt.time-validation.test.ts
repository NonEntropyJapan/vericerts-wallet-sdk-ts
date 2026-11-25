/**
 * SD-JWT Issuer JWT の exp / nbf 時刻検証ユニットテスト（実鍵・モック禁止）。
 *
 * 検証内容:
 * - exp 切れ（now >= exp）で VC_EXPIRED（3024）。
 * - nbf 未来（now < nbf）で VC_NOT_YET_VALID（3025）。
 * - exp / nbf が有効範囲内なら検証成功。
 * - exp / nbf 型不正（非数値）で VC_SCHEMA_INVALID（3002）。
 * - exp / nbf が無い場合は従来どおり成功。
 *
 * 境界演算子（`>=` / `<`）そのものの回帰テストのため、クロックスキュー導入後も
 * `clockSkewSeconds: 0` を明示して検証する（skew 0 の `exp` / `nbf` 判定は 従来どおり）。
 * - フォーマット間整合: 同一の期限切れ exp を JWT-VC と SD-JWT の双方が 3024 で拒否する。
 */

import { describe, expect, it } from 'bun:test';
import { ErrorCodes, VericertsError } from '../../../errors.js';
import type { PublicKeyJwk } from '../../../identity/did.js';
import { getP256PublicKey } from '../../../keymanager/signer.js';
import { issueCredential } from '../../vc/issue.js';
import { createPrivateKeySigner } from '../../vc/signer.js';
import type { VerifiableCredential } from '../../vc/vc.js';
import { verifyCredential } from '../../vc/verify.js';
import { createSdJwt } from '../sdjwt.js';
import { verifySdJwt } from '../verify.js';

/** テスト用の固定秘密鍵。 */
const ISSUER_KEY = new Uint8Array(32).fill(7);

/** 非圧縮公開鍵（0x04 || x || y）から EC 公開鍵 JWK を構築する。 */
function toJwk(pub: Uint8Array, crv: string): PublicKeyJwk {
  const b64u = (b: Uint8Array): string => Buffer.from(b).toString('base64url');
  return { kty: 'EC', crv, x: b64u(pub.subarray(1, 33)), y: b64u(pub.subarray(33, 65)) };
}

const ISSUER_JWK = toJwk(getP256PublicKey(ISSUER_KEY, false), 'P-256');
const VCT = 'https://example.com/credentials/identity';
const ISSUER_SIGNER = createPrivateKeySigner(ISSUER_KEY, 'ES256');

/** 固定の現在時刻（2026-01-01T00:00:00Z 近傍）。 */
const NOW = 1_767_225_600;

/** exp / nbf を issuer payload に載せた SD-JWT を発行する（exp/nbf は開示対象から外し平文に残す）。 */
function issueWithTime(time: { exp?: unknown; nbf?: unknown }): string {
  return createSdJwt(ISSUER_SIGNER, {
    vct: VCT,
    disclosureClaims: ['name'],
    claims: { name: 'Alice', ...time },
    salts: { name: 'salt-name' },
    nowSeconds: NOW,
  });
}

describe('SD-JWT Issuer JWT の exp / nbf 時刻検証', () => {
  it('exp 切れ（now >= exp）は VC_EXPIRED（3024）', () => {
    const sdJwt = issueWithTime({ exp: NOW - 1 });
    expect(() =>
      verifySdJwt(sdJwt, { issuerKey: ISSUER_JWK, nowSeconds: NOW, clockSkewSeconds: 0 }),
    ).toThrow(new VericertsError(ErrorCodes.VC_EXPIRED));
  });

  it('nbf 未来（now < nbf）は VC_NOT_YET_VALID（3025）', () => {
    const sdJwt = issueWithTime({ nbf: NOW + 1 });
    expect(() =>
      verifySdJwt(sdJwt, { issuerKey: ISSUER_JWK, nowSeconds: NOW, clockSkewSeconds: 0 }),
    ).toThrow(new VericertsError(ErrorCodes.VC_NOT_YET_VALID));
  });

  it('exp / nbf が有効範囲内なら検証成功する', () => {
    const sdJwt = issueWithTime({ nbf: NOW - 100, exp: NOW + 100 });
    const result = verifySdJwt(sdJwt, { issuerKey: ISSUER_JWK, nowSeconds: NOW });
    expect(result.claims.name).toBe('Alice');
  });

  it('exp 型不正（非数値）は VC_SCHEMA_INVALID（3002）', () => {
    const sdJwt = issueWithTime({ exp: 'not-a-number' });
    expect(() => verifySdJwt(sdJwt, { issuerKey: ISSUER_JWK, nowSeconds: NOW })).toThrow(
      new VericertsError(ErrorCodes.VC_SCHEMA_INVALID),
    );
  });

  it('nbf 型不正（非数値）は VC_SCHEMA_INVALID（3002）', () => {
    const sdJwt = issueWithTime({ nbf: 'not-a-number' });
    expect(() => verifySdJwt(sdJwt, { issuerKey: ISSUER_JWK, nowSeconds: NOW })).toThrow(
      new VericertsError(ErrorCodes.VC_SCHEMA_INVALID),
    );
  });

  it('exp / nbf が無い SD-JWT は従来どおり成功する', () => {
    const sdJwt = issueWithTime({});
    const result = verifySdJwt(sdJwt, { issuerKey: ISSUER_JWK, nowSeconds: NOW });
    expect(result.claims.name).toBe('Alice');
  });

  it('フォーマット間整合: 同一の期限切れ exp を JWT-VC と SD-JWT の双方が 3024 で拒否する', () => {
    // 期限切れの exp（NumericDate）。同じ now で双方が VC_EXPIRED になることを確認し bypass を塞ぐ。
    const expiredExp = NOW - 1;

    // JWT-VC 側: expirationDate を期限切れにした VC を発行。
    const vc: VerifiableCredential = {
      '@context': ['https://www.w3.org/ns/credentials/v2'],
      type: ['VerifiableCredential'],
      issuer: 'did:example:issuer',
      credentialSubject: { id: 'did:example:holder' },
      issuanceDate: '2025-12-01T00:00:00Z',
      expirationDate: new Date(expiredExp * 1000).toISOString(),
    };
    const jwtVc = issueCredential(vc, ISSUER_SIGNER, { nowSeconds: NOW });
    expect(() =>
      verifyCredential(jwtVc, {
        key: { publicKeyJwk: ISSUER_JWK },
        nowSeconds: NOW,
        clockSkewSeconds: 0,
      }),
    ).toThrow(new VericertsError(ErrorCodes.VC_EXPIRED));

    // SD-JWT 側: 同一の期限切れ exp を issuer payload に載せて発行。
    const sdJwt = issueWithTime({ exp: expiredExp });
    expect(() =>
      verifySdJwt(sdJwt, { issuerKey: ISSUER_JWK, nowSeconds: NOW, clockSkewSeconds: 0 }),
    ).toThrow(new VericertsError(ErrorCodes.VC_EXPIRED));
  });
});
