/**
 * did:jwt 生成（createDidJwt）のユニットテスト。
 *
 * 実鍵で署名し（モック禁止）、以下を検証する:
 * - ES256（P-256）/ ES256K（secp256k1）/ EdDSA（Ed25519）の生成と `did:jwt:` プレフィックス。
 * - 生成 → `resolveDidJwt` の往復一致（署名検証が通り DID Document を返す）。
 * - EdDSA の署名対象が signing-input そのものであること（PureEdDSA / RFC 8032）。
 * - exp / nbf の妥当性（既定 24h、opts での調整、生成時刻基準の有効性）。
 */

import { describe, expect, it } from 'bun:test';
import { sha256 } from '@noble/hashes/sha2.js';
import { ErrorCodes, VericertsError } from '../../../errors.js';
import { getEd25519PublicKey, verifyEd25519 } from '../../../keymanager/ed25519.js';
import { getP256PublicKey, getSecp256k1PublicKey } from '../../../keymanager/signer.js';
import { createDidJwt } from '../generate.js';
import { resolveDidJwt } from '../method-jwt.js';
import { b64u, uncompressedToXY } from './jwt-fixtures.js';

/** テスト用の固定秘密鍵。 */
const P256_KEY = new Uint8Array(32).fill(7);
const SECP_KEY = new Uint8Array(32).fill(9);
const ED_KEY = new Uint8Array(32).fill(11);

/** テスト用の固定 iat（2026-01-01T00:00:00Z 近傍）。 */
const IAT = 1_767_225_600;

/** 上記固定鍵・固定 iat における移行前実装の署名セグメント（base64url）。 */
const EXPECTED_ES256_SIGNATURE =
  'jWWI2MBnsRG2Al-SlHGvPJeBJ5TMiFjEdR2pYC4bDnoUXzBGhmJPCK7nrowjO8JMLqzsQ76vedCaDlXe_zTgJw';
const EXPECTED_ES256K_SIGNATURE =
  'fR0e6kaCYcbLApuH9UMtEtnqRbhDqsy7_yqcdFG4M1Y6kDyMmUFlgl97VLY4O7xIfAg_kSW1xvdyh5nRdtldxw';

/** did:jwt の base64url(JWT) を JWT 文字列へ戻して payload を取り出す。 */
function decodePayload(did: string): Record<string, unknown> {
  const encodedJwt = did.slice('did:jwt:'.length);
  const jwt = new TextDecoder().decode(b64uToBytes(encodedJwt));
  const payloadSeg = jwt.split('.')[1] ?? '';
  return JSON.parse(new TextDecoder().decode(b64uToBytes(payloadSeg))) as Record<string, unknown>;
}

/** did:jwt から JWT を復元し、signing-input と署名バイト列に分解する。 */
function decodeJwtParts(did: string): { signingInput: string; signature: Uint8Array } {
  const jwt = new TextDecoder().decode(b64uToBytes(did.slice('did:jwt:'.length)));
  const lastDot = jwt.lastIndexOf('.');
  return {
    signingInput: jwt.slice(0, lastDot),
    signature: b64uToBytes(jwt.slice(lastDot + 1)),
  };
}

/** base64url（パディングなし）文字列をバイト列へ戻す。 */
function b64uToBytes(text: string): Uint8Array {
  // b64u（fixtures）の逆変換。テストヘルパとしてのみ使う。
  const pad = text.length % 4 === 0 ? '' : '='.repeat(4 - (text.length % 4));
  const b64 = (text + pad).replace(/-/g, '+').replace(/_/g, '/');
  return Uint8Array.from(atob(b64), (c) => c.charCodeAt(0));
}

describe('createDidJwt 生成', () => {
  it('ES256（P-256）の did:jwt を生成する', () => {
    const did = createDidJwt({ alg: 'ES256', privateKey: P256_KEY, iat: IAT });
    expect(did.startsWith('did:jwt:')).toBe(true);
    const payload = decodePayload(did);
    const vms = payload.verificationMethod as Array<{ publicKeyJwk: Record<string, unknown> }>;
    const { x, y } = uncompressedToXY(getP256PublicKey(P256_KEY, false));
    expect(vms[0]?.publicKeyJwk).toEqual({ kty: 'EC', crv: 'P-256', x, y });
  });

  it('ES256K（secp256k1）の did:jwt を生成する', () => {
    const did = createDidJwt({ alg: 'ES256K', privateKey: SECP_KEY, iat: IAT });
    const payload = decodePayload(did);
    const vms = payload.verificationMethod as Array<{ publicKeyJwk: Record<string, unknown> }>;
    const { x, y } = uncompressedToXY(getSecp256k1PublicKey(SECP_KEY, false));
    expect(vms[0]?.publicKeyJwk).toEqual({ kty: 'EC', crv: 'secp256k1', x, y });
  });

  it('EdDSA（Ed25519）の did:jwt を生成し publicKeyJwk が OKP になる', () => {
    const did = createDidJwt({ alg: 'EdDSA', privateKey: ED_KEY, iat: IAT });
    expect(did.startsWith('did:jwt:')).toBe(true);
    const payload = decodePayload(did);
    const vms = payload.verificationMethod as Array<{ publicKeyJwk: Record<string, unknown> }>;
    expect(vms[0]?.publicKeyJwk).toEqual({
      kty: 'OKP',
      crv: 'Ed25519',
      x: b64u(getEd25519PublicKey(ED_KEY)),
    });
  });
});

describe('createDidJwt → resolveDidJwt 往復', () => {
  it('ES256 の生成物を解決でき署名検証が通る', () => {
    const did = createDidJwt({ alg: 'ES256', privateKey: P256_KEY, iat: IAT });
    const doc = resolveDidJwt(did, IAT + 100);
    expect(doc.id).toBe(did);
    expect(doc.verificationMethod).toHaveLength(1);
    expect(doc.authentication).toEqual(['#key-1']);
    expect(doc.assertionMethod).toEqual(['#key-1']);
  });

  it('ES256K の生成物を解決でき署名検証が通る', () => {
    const did = createDidJwt({ alg: 'ES256K', privateKey: SECP_KEY, iat: IAT });
    const doc = resolveDidJwt(did, IAT + 100);
    expect(doc.id).toBe(did);
    expect(doc.verificationMethod[0]?.type).toBe('JsonWebKey');
  });

  it('EdDSA の生成物を解決でき署名検証が通る', () => {
    const did = createDidJwt({ alg: 'EdDSA', privateKey: ED_KEY, iat: IAT });
    const doc = resolveDidJwt(did, IAT + 100);
    expect(doc.id).toBe(did);
    expect(doc.verificationMethod[0]?.publicKeyJwk?.kty).toBe('OKP');
  });
});

describe('EdDSA の署名対象（PureEdDSA / RFC 8032）', () => {
  /**
   * Ed25519 は事前ハッシュせず signing-input そのものに署名する（RFC 8032 の PureEdDSA）。
   * 検証側 `ALG_SPECS.EdDSA.verify`（jwk-key.ts）も signing-input を直接検証するため、生成側が
   * digest に署名すると「生成できるが永久に検証できない」JWT が静かに作られてしまう。
   * 往復テストだけではこの取り違えを検出できない場合があるため、digest に対する検証が
   * **false になる** ことまで明示的に固定し、契約の非対称化を回帰として検知する。
   */
  it('署名は signing-input に対して有効で、その SHA-256 に対しては無効', () => {
    const did = createDidJwt({ alg: 'EdDSA', privateKey: ED_KEY, iat: IAT });
    const { signingInput, signature } = decodeJwtParts(did);
    const publicKey = getEd25519PublicKey(ED_KEY);
    const message = new TextEncoder().encode(signingInput);
    expect(verifyEd25519(message, signature, publicKey)).toBe(true);
    expect(verifyEd25519(sha256(message), signature, publicKey)).toBe(false);
  });
});

describe('ES256 / ES256K の非回帰（signing-input 契約への移行前と同一出力）', () => {
  /**
   * `assembleDidJwt` を digest 契約から signing-input 契約へ移行しても、ECDSA 側は
   * 生成器内で SHA-256 を適用するため出力は 1 バイトも変わってはならない。期待値は移行前の
   * 実装（HEAD）を固定鍵・固定 iat で実行して採取した署名セグメント。
   */
  it('ES256 の署名バイト列が移行前と一致する', () => {
    const did = createDidJwt({ alg: 'ES256', privateKey: P256_KEY, iat: IAT });
    expect(decodeJwtParts(did).signature).toEqual(b64uToBytes(EXPECTED_ES256_SIGNATURE));
  });

  it('ES256K の署名バイト列が移行前と一致する', () => {
    const did = createDidJwt({ alg: 'ES256K', privateKey: SECP_KEY, iat: IAT });
    expect(decodeJwtParts(did).signature).toEqual(b64uToBytes(EXPECTED_ES256K_SIGNATURE));
  });
});

describe('createDidJwt の時刻クレーム', () => {
  it('既定の exp は iat + 24h、nbf は iat に一致する', () => {
    const did = createDidJwt({ alg: 'ES256', privateKey: P256_KEY, iat: IAT });
    const payload = decodePayload(did);
    expect(payload.iat).toBe(IAT);
    expect(payload.nbf).toBe(IAT);
    expect(payload.exp).toBe(IAT + 24 * 60 * 60);
  });

  it('expiresInSeconds で有効期間を調整できる', () => {
    const did = createDidJwt({
      alg: 'ES256',
      privateKey: P256_KEY,
      iat: IAT,
      expiresInSeconds: 60,
    });
    const payload = decodePayload(did);
    expect(payload.exp).toBe(IAT + 60);
  });

  it('exp 経過後は解決が失敗する（INVALID_DID）', () => {
    const did = createDidJwt({
      alg: 'ES256',
      privateKey: P256_KEY,
      iat: IAT,
      expiresInSeconds: 60,
    });
    expect(() => resolveDidJwt(did, IAT + 61)).toThrow(new VericertsError(ErrorCodes.INVALID_DID));
  });

  it('nbf 前は解決が失敗する（INVALID_DID）', () => {
    const did = createDidJwt({ alg: 'ES256', privateKey: P256_KEY, iat: IAT, nbf: IAT + 100 });
    expect(() => resolveDidJwt(did, IAT + 50)).toThrow(new VericertsError(ErrorCodes.INVALID_DID));
  });
});

describe('createDidJwt の未対応 alg ガード', () => {
  it('型外の alg（実行時不正値）は UNSUPPORTED_ALGORITHM を投げる', () => {
    // JS 呼び出しで型外の alg が渡された場合に素の TypeError ではなく VericertsError へ正規化されること。
    expect(() =>
      createDidJwt({ alg: 'RS256' as unknown as 'ES256', privateKey: P256_KEY }),
    ).toThrow(new VericertsError(ErrorCodes.UNSUPPORTED_ALGORITHM));
  });

  it.each([
    'constructor',
    'toString',
    '__proto__',
  ])('Object.prototype 由来の alg（%s）もガードをすり抜けない', (alg) => {
    // ALG_GENERATORS は Object.create(null) 由来のため、これらは undefined となり
    // `=== undefined` ガードで弾かれる（TypeError にならない）。
    expect(() => createDidJwt({ alg: alg as unknown as 'ES256', privateKey: P256_KEY })).toThrow(
      new VericertsError(ErrorCodes.UNSUPPORTED_ALGORITHM),
    );
  });
});
