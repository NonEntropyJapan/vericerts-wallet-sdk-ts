/**
 * JWT-VC（JWS）発行 → 検証ラウンドトリップのユニットテスト（実鍵・モック禁止）。
 *
 * 検証内容:
 * - ES256（P-256）/ ES256K（secp256k1）/ EdDSA（Ed25519）の発行 → 検証成功
 *   （公開鍵 JWK 注入 / 検証関数注入の両方）。
 * - 改竄署名 → SIG_INVALID（3010）。
 * - alg ↔ 鍵種別の不一致（EdDSA 署名 × EC 鍵 / ES256 署名 × OKP 鍵）→ SIG_INVALID（3010）。
 * - alg=none → ALG_NONE（3011）。
 * - exp 切れ → VC_EXPIRED（3024）/ nbf 前 → VC_NOT_YET_VALID（3025）。
 * - exp / nbf 型不正 → VC_SCHEMA_INVALID（3002）。
 *
 * exp / nbf の境界演算子（`>=` / `<`）の回帰テストは `clockSkewSeconds: 0` を明示する
 * （skew 0 の `exp` / `nbf` 判定は 従来どおり）。
 */

import { describe, expect, it } from 'bun:test';
import { ErrorCodes, VericertsError } from '../../../errors.js';
import type { PublicKeyJwk } from '../../../identity/did.js';
import { getEd25519PublicKey, verifyEd25519 } from '../../../keymanager/ed25519.js';
import {
  getP256PublicKey,
  getSecp256k1PublicKey,
  verifyP256,
  verifySecp256k1,
} from '../../../keymanager/signer.js';
import { issueCredential } from '../issue.js';
import type { CredentialAlg } from '../jws.js';
import { createPrivateKeySigner } from '../signer.js';
import type { VerifiableCredential } from '../vc.js';
import { verifyCredential } from '../verify.js';

/** テスト用の固定秘密鍵。 */
const P256_KEY = new Uint8Array(32).fill(7);
const SECP_KEY = new Uint8Array(32).fill(9);
const ED_KEY = new Uint8Array(32).fill(5);

/** テスト用の固定現在時刻（2026-01-01T00:00:00Z 近傍）。 */
const NOW = 1_767_225_600;
/** 発行日時 ISO（NOW より十分前）。 */
const ISSUANCE = '2025-12-01T00:00:00Z';
/** 有効期限 ISO（NOW より十分後）。 */
const EXPIRATION = '2027-01-01T00:00:00Z';

/** 非圧縮公開鍵（0x04 || x || y）から EC 公開鍵 JWK を構築する。 */
function toJwk(pub: Uint8Array, crv: string): PublicKeyJwk {
  const b64u = (b: Uint8Array): string => Buffer.from(b).toString('base64url');
  return { kty: 'EC', crv, x: b64u(pub.subarray(1, 33)), y: b64u(pub.subarray(33, 65)) };
}

/** Ed25519 公開鍵（32B）から OKP 公開鍵 JWK を構築する（`y` は持たない）。 */
function toOkpJwk(pub: Uint8Array): PublicKeyJwk {
  return { kty: 'OKP', crv: 'Ed25519', x: Buffer.from(pub).toString('base64url') };
}

/**
 * alg ごとの鍵・JWK・検証関数。
 *
 * `verify` は `CredentialVerifierKey.verify`（脱出ハッチ）と同じ契約で、ECDSA は `digest`、
 * EdDSA は `signingInput` を使う。
 */
const FIXTURES: Record<
  CredentialAlg,
  {
    readonly privateKey: Uint8Array;
    readonly jwk: PublicKeyJwk;
    readonly verify: (
      digest: Uint8Array,
      signature: Uint8Array,
      signingInput: Uint8Array,
    ) => boolean;
  }
> = {
  ES256: {
    privateKey: P256_KEY,
    jwk: toJwk(getP256PublicKey(P256_KEY, false), 'P-256'),
    verify: (digest, signature) => verifyP256(digest, signature, getP256PublicKey(P256_KEY, false)),
  },
  ES256K: {
    privateKey: SECP_KEY,
    jwk: toJwk(getSecp256k1PublicKey(SECP_KEY, false), 'secp256k1'),
    verify: (digest, signature) =>
      verifySecp256k1(digest, signature, getSecp256k1PublicKey(SECP_KEY, false)),
  },
  EdDSA: {
    privateKey: ED_KEY,
    jwk: toOkpJwk(getEd25519PublicKey(ED_KEY)),
    // Ed25519 は digest ではなく signing-input を検証する。
    verify: (_digest, signature, signingInput) =>
      verifyEd25519(signingInput, signature, getEd25519PublicKey(ED_KEY)),
  },
};

/** alg ごとの CredentialSigner（生 privateKey 由来）。 */
function signerFor(alg: CredentialAlg) {
  return createPrivateKeySigner(FIXTURES[alg].privateKey, alg);
}

/**
 * 任意の JWT-VC payload を有効署名で組み立てる（時刻型不正テスト用）。
 *
 * 署名検証は時刻評価より前に走るため、不正な exp/nbf を含む payload でも有効署名が必要。
 */
function signJwtWithPayload(alg: CredentialAlg, payload: Record<string, unknown>): string {
  const b64u = (text: string): string => Buffer.from(text).toString('base64url');
  const headerSeg = b64u(JSON.stringify({ alg, typ: 'JWT' }));
  const payloadSeg = b64u(JSON.stringify(payload));
  const signingInput = `${headerSeg}.${payloadSeg}`;
  const signature = signerFor(alg).sign(new TextEncoder().encode(signingInput));
  return `${signingInput}.${Buffer.from(signature).toString('base64url')}`;
}

/** envelope binding を満たす最小の正常 payload（time claim を差し替えて使う）。 */
function basePayload(): Record<string, unknown> {
  const vc = sampleVc();
  return {
    iss: vc.issuer,
    sub: vc.credentialSubject.id,
    jti: vc.id,
    nbf: Math.floor(Date.parse(ISSUANCE) / 1000),
    exp: Math.floor(Date.parse(EXPIRATION) / 1000),
    vc,
  };
}

/** サンプル VC を作る。 */
function sampleVc(overrides: Partial<VerifiableCredential> = {}): VerifiableCredential {
  return {
    '@context': ['https://www.w3.org/ns/credentials/v2'],
    type: ['VerifiableCredential'],
    issuer: 'did:example:issuer',
    credentialSubject: { id: 'did:example:subject', name: 'Alice' },
    issuanceDate: ISSUANCE,
    expirationDate: EXPIRATION,
    id: 'urn:uuid:1234',
    ...overrides,
  };
}

describe.each<CredentialAlg>(['ES256', 'ES256K', 'EdDSA'])('JWT-VC 発行 → 検証（%s）', (alg) => {
  const fx = FIXTURES[alg];

  it('公開鍵 JWK 注入で検証が通る', () => {
    const jwt = issueCredential(sampleVc(), signerFor(alg), { nowSeconds: NOW });
    const result = verifyCredential(jwt, { key: { publicKeyJwk: fx.jwk }, nowSeconds: NOW });
    expect(result.header.alg).toBe(alg);
    expect(result.payload.iss).toBe('did:example:issuer');
    expect(result.payload.sub).toBe('did:example:subject');
    expect(result.payload.jti).toBe('urn:uuid:1234');
    expect((result.payload.vc as VerifiableCredential).credentialSubject.name).toBe('Alice');
  });

  it('検証関数注入で検証が通る', () => {
    const jwt = issueCredential(sampleVc(), signerFor(alg), { nowSeconds: NOW });
    const result = verifyCredential(jwt, { key: { verify: fx.verify }, nowSeconds: NOW });
    expect(result.payload.iss).toBe('did:example:issuer');
  });

  it('改竄署名は SIG_INVALID（3010）', () => {
    const jwt = issueCredential(sampleVc(), signerFor(alg), { nowSeconds: NOW });
    const parts = jwt.split('.');
    // 署名セグメントの 1 文字を反転して無効署名にする。
    const sig = parts[2] ?? '';
    const flipped = (sig[0] === 'A' ? 'B' : 'A') + sig.slice(1);
    const tampered = `${parts[0]}.${parts[1]}.${flipped}`;
    expect(() =>
      verifyCredential(tampered, { key: { publicKeyJwk: fx.jwk }, nowSeconds: NOW }),
    ).toThrow(new VericertsError(ErrorCodes.SIG_INVALID));
  });

  it('exp 切れは VC_EXPIRED（3024）', () => {
    const jwt = issueCredential(sampleVc(), signerFor(alg), { nowSeconds: NOW });
    // EXPIRATION（2027-01-01）を過ぎた時刻で検証する。
    const afterExp = Math.floor(Date.parse(EXPIRATION) / 1000) + 1;
    expect(() =>
      verifyCredential(jwt, {
        key: { publicKeyJwk: fx.jwk },
        nowSeconds: afterExp,
        clockSkewSeconds: 0,
      }),
    ).toThrow(new VericertsError(ErrorCodes.VC_EXPIRED));
  });

  it('nbf 前は VC_NOT_YET_VALID（3025）', () => {
    // ISSUANCE（2025-12-01）より前の時刻で検証する。発行時刻（`iat`）も同時刻に合わせ、
    // 未来 `iat` の 4014 ではなく nbf 判定の 3025 が出ることを確かめる。
    const beforeNbf = Math.floor(Date.parse(ISSUANCE) / 1000) - 1;
    const jwt = issueCredential(sampleVc(), signerFor(alg), { nowSeconds: beforeNbf });
    expect(() =>
      verifyCredential(jwt, {
        key: { publicKeyJwk: fx.jwk },
        nowSeconds: beforeNbf,
        clockSkewSeconds: 0,
      }),
    ).toThrow(new VericertsError(ErrorCodes.VC_NOT_YET_VALID));
  });

  it('exp 型不正（非数値）は VC_SCHEMA_INVALID（3002）', () => {
    // exp を文字列に差し替えた payload を有効署名で組み立てる（時刻評価は署名検証後に走る）。
    const jwt = signJwtWithPayload(alg, { ...basePayload(), exp: 'not-a-number' });
    expect(() => verifyCredential(jwt, { key: { publicKeyJwk: fx.jwk }, nowSeconds: NOW })).toThrow(
      new VericertsError(ErrorCodes.VC_SCHEMA_INVALID),
    );
  });

  it('nbf 型不正（非数値）は VC_SCHEMA_INVALID（3002）', () => {
    const jwt = signJwtWithPayload(alg, { ...basePayload(), nbf: 'not-a-number' });
    expect(() => verifyCredential(jwt, { key: { publicKeyJwk: fx.jwk }, nowSeconds: NOW })).toThrow(
      new VericertsError(ErrorCodes.VC_SCHEMA_INVALID),
    );
  });
});

describe('JWT-VC 検証の異常系', () => {
  it('alg=none は ALG_NONE（3011）', () => {
    const fx = FIXTURES.ES256;
    const jwt = issueCredential(sampleVc(), signerFor('ES256'), { nowSeconds: NOW });
    // ヘッダを alg=none に差し替える（payload / signature はそのまま）。
    const parts = jwt.split('.');
    const noneHeader = Buffer.from(JSON.stringify({ alg: 'none', typ: 'JWT' })).toString(
      'base64url',
    );
    const forged = `${noneHeader}.${parts[1]}.${parts[2]}`;
    expect(() =>
      verifyCredential(forged, { key: { publicKeyJwk: fx.jwk }, nowSeconds: NOW }),
    ).toThrow(new VericertsError(ErrorCodes.ALG_NONE));
  });

  // 回帰: alg ↔ 鍵種別の不一致は鍵解決時に INVALID_DID（2001）を投げていたが、VC 検証 API の
  // 失敗面は 30xx 系で定義されている。署名検証不成立として 3010 へ正規化されることを検証する。
  it('EdDSA 署名を EC（P-256）鍵で検証すると SIG_INVALID（3010）', () => {
    const jwt = issueCredential(sampleVc(), signerFor('EdDSA'), { nowSeconds: NOW });
    expect(() =>
      verifyCredential(jwt, { key: { publicKeyJwk: FIXTURES.ES256.jwk }, nowSeconds: NOW }),
    ).toThrow(new VericertsError(ErrorCodes.SIG_INVALID));
  });

  it('ES256 署名を OKP（Ed25519）鍵で検証すると SIG_INVALID（3010）', () => {
    const jwt = issueCredential(sampleVc(), signerFor('ES256'), { nowSeconds: NOW });
    expect(() =>
      verifyCredential(jwt, { key: { publicKeyJwk: FIXTURES.EdDSA.jwk }, nowSeconds: NOW }),
    ).toThrow(new VericertsError(ErrorCodes.SIG_INVALID));
  });

  // 回帰: 構造不正の JWT に対し `decodeCompactJws` の INVALID_DID（2001）が
  // そのまま漏れていた。2001 は DID 解決失敗を表すコードで、呼び出し側に「DID が悪い」と
  // 誤解させる。VC 検証 API の失敗面（30xx）に合わせ SIG_INVALID（3010）へ正規化する。
  it.each([
    ['セグメントが多い', 'not.a.valid.jwt'],
    ['セグメントが少ない', 'bad.jwt'],
    ['セグメントが空', '..'],
    ['区切りが無い', 'notajwt'],
    ['base64url として不正', 'a!b.c!d.e!f'],
    ['ヘッダが JSON でない', 'bm90LWpzb24.e30.c2ln'],
  ])('構造不正の JWT（%s）は SIG_INVALID（3010）へ正規化される', (_label, jwt) => {
    const fx = FIXTURES.ES256;
    expect(() => verifyCredential(jwt, { key: { publicKeyJwk: fx.jwk }, nowSeconds: NOW })).toThrow(
      new VericertsError(ErrorCodes.SIG_INVALID),
    );
  });

  it('exp / expirationDate なしの VC は時刻評価をスキップして検証成功', () => {
    const fx = FIXTURES.ES256;
    const vc = sampleVc({ expirationDate: undefined });
    const jwt = issueCredential(vc, signerFor('ES256'), { nowSeconds: NOW });
    const result = verifyCredential(jwt, { key: { publicKeyJwk: fx.jwk }, nowSeconds: NOW });
    expect(result.payload.exp).toBeUndefined();
  });

  // 回帰: 不正 issuanceDate は発行時に NaN→JSON null へ倒れ、検証時の時刻評価で誤表面化していた（fail-open）。
  // 発行時点で構造不正（3002）として拒否されることを検証する。
  it('不正な issuanceDate は発行時に VC_SCHEMA_INVALID（3002）', () => {
    const vc = sampleVc({ issuanceDate: 'not-a-date' });
    expect(() => issueCredential(vc, signerFor('ES256'))).toThrow(
      new VericertsError(ErrorCodes.VC_SCHEMA_INVALID),
    );
  });

  it('不正な expirationDate は発行時に VC_SCHEMA_INVALID（3002）', () => {
    const vc = sampleVc({ expirationDate: 'garbage' });
    expect(() => issueCredential(vc, signerFor('ES256'))).toThrow(
      new VericertsError(ErrorCodes.VC_SCHEMA_INVALID),
    );
  });

  // 回帰: SIGNER_SPECS が通常のオブジェクトリテラルだと `alg: "constructor"` 等が
  // Object.prototype にヒットし、未対応 alg ガード（1030）をすり抜けて TypeError になっていた。
  it.each([
    'constructor',
    'toString',
    'valueOf',
    'hasOwnProperty',
  ])('Object.prototype 由来の alg（%s）は TypeError ではなく UNSUPPORTED_ALGORITHM（1030）', (alg) => {
    expect(() => createPrivateKeySigner(P256_KEY, alg as CredentialAlg)).toThrow(
      new VericertsError(ErrorCodes.UNSUPPORTED_ALGORITHM),
    );
  });
});
