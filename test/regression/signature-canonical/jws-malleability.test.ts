/**
 * 回帰テスト: 非正準な署名エンコーディングが JWS 検証経路まで届かないこと。
 *
 * `verifyP256` / `verifySecp256k1` は `ALG_SPECS`（`identity/jwt/jwk-key.ts`）経由で SDK の全 JWS
 * 検証経路（JWT-VC / VP・SD-JWT KB-JWT・SIOPv2・WUA・JAR 等）に共有されている。修正前は、正規に
 * 発行した VC の署名を DER へ再エンコードする / 末尾に 1 バイト付けるだけで**別の有効な JWS 文字列**
 * が作れたため、JWS 文字列を重複判定キーに使う呼び出し側のリプレイ検出を回避できた。
 *
 * ここでは共有レジストリ `ALG_SPECS` と、実際の `issueCredential` → `verifyCredential` 経路の
 * 両方で、非正準表現が拒否され、かつ正規の署名は従来どおり通ることを固定する。
 */

import { describe, expect, it } from 'bun:test';
import { issueCredential } from '../../../src/internal/credential/vc/issue.js';
import type { CredentialAlg } from '../../../src/internal/credential/vc/jws.js';
import { createPrivateKeySigner } from '../../../src/internal/credential/vc/signer.js';
import type { VerifiableCredential } from '../../../src/internal/credential/vc/vc.js';
import { verifyCredential } from '../../../src/internal/credential/vc/verify.js';
import { ErrorCodes, VericertsError } from '../../../src/internal/errors.js';
import type { PublicKeyJwk } from '../../../src/internal/identity/did.js';
import { ALG_SPECS } from '../../../src/internal/identity/jwt/jwk-key.js';
import { derToP1363, p1363ToDer } from '../../../src/internal/keymanager/signer.js';
import { appendByte, FIXTURES, PRIVATE_KEY } from './fixtures.js';

/** ES256 / ES256K それぞれの曲線名。 */
const JWS_ALGS = [
  { alg: 'ES256' as const, curve: 'p256' as const },
  { alg: 'ES256K' as const, curve: 'secp256k1' as const },
];

/** テスト用の最小 VC。 */
function sampleVc(): VerifiableCredential {
  return {
    '@context': ['https://www.w3.org/ns/credentials/v2'],
    type: ['VerifiableCredential'],
    issuer: 'did:example:issuer',
    credentialSubject: { id: 'did:example:subject', name: 'Alice' },
    issuanceDate: '2025-12-01T00:00:00Z',
    expirationDate: '2027-01-01T00:00:00Z',
    id: 'urn:uuid:1234',
  };
}

/** JWT の署名セグメントを差し替える。 */
function withSignature(jwt: string, signature: Uint8Array): string {
  const [header, payload] = jwt.split('.');
  return `${header}.${payload}.${Buffer.from(signature).toString('base64url')}`;
}

/** 現在時刻（VC の有効期間内）。 */
const NOW = 1_767_225_600;

describe.each(JWS_ALGS)('JWS signature malleability ($alg)', ({ alg, curve }) => {
  const signer = createPrivateKeySigner(PRIVATE_KEY, alg satisfies CredentialAlg);
  const jwk: PublicKeyJwk = signer.publicKeyJwk;
  const publicKey = FIXTURES[curve].uncompressedPublicKey;

  it('regression: ALG_SPECS.verify rejects non-canonical encodings but accepts the genuine signature', () => {
    const spec = ALG_SPECS[alg];
    if (spec === undefined) {
      throw new Error(`ALG_SPECS is missing ${alg}`);
    }
    const message = new TextEncoder().encode('signing-input');
    const signature = signer.sign(message);

    // 正常系（非退行）: 正規の 64 バイト署名は通る。
    expect(spec.verify(message, signature, publicKey)).toBe(true);
    // 非正準: DER 再エンコードと末尾バイト付加はいずれも拒否される。
    expect(spec.verify(message, p1363ToDer(signature, curve), publicKey)).toBe(false);
    expect(spec.verify(message, appendByte(signature, 0x00), publicKey)).toBe(false);
  });

  it('regression: verifyCredential accepts the genuine credential', () => {
    const jwt = issueCredential(sampleVc(), signer, { nowSeconds: NOW });
    const result = verifyCredential(jwt, { key: { publicKeyJwk: jwk }, nowSeconds: NOW });
    expect(result.header.alg).toBe(alg);
  });

  it('regression: verifyCredential rejects a DER re-encoding of its own valid signature', () => {
    const jwt = issueCredential(sampleVc(), signer, { nowSeconds: NOW });
    const raw = Buffer.from(jwt.split('.')[2] ?? '', 'base64url');
    const der = p1363ToDer(new Uint8Array(raw), curve);
    // 同一クレームに対する 2 つ目の「有効な」JWS。受理すると jti ベースでない
    // リプレイ検出（JWS 文字列そのものをキーにする実装）を回避できてしまう。
    expect(() =>
      verifyCredential(withSignature(jwt, der), { key: { publicKeyJwk: jwk }, nowSeconds: NOW }),
    ).toThrow(new VericertsError(ErrorCodes.SIG_INVALID));
    // DER は形式変換としては正しく、元の 64 バイトへ戻せる（無効な DER ではないことの確認）。
    expect(derToP1363(der, curve).length).toBe(64);
  });

  it('regression: verifyCredential rejects a signature with an extra trailing byte', () => {
    const jwt = issueCredential(sampleVc(), signer, { nowSeconds: NOW });
    const raw = new Uint8Array(Buffer.from(jwt.split('.')[2] ?? '', 'base64url'));
    expect(() =>
      verifyCredential(withSignature(jwt, appendByte(raw, 0x00)), {
        key: { publicKeyJwk: jwk },
        nowSeconds: NOW,
      }),
    ).toThrow(new VericertsError(ErrorCodes.SIG_INVALID));
  });
});
