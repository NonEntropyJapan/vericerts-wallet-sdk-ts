/**
 * 回帰テスト: 署名検証が非正準エンコーディングを受理しないこと。
 *
 * 修正前は `verifyP256` が「64 バイト以外はすべて DER」として解釈し、`verifySecp256k1` が
 * 65 バイト署名の末尾 1 バイトを無条件に読み捨てていたため、同一メッセージ・同一鍵に対して
 * 有効な署名バイト列が無数に成立していた（JWS の可鍛性 / malleability）。
 *
 * 本テストは以下を固定する:
 * - 既定（`encoding: 'p1363'`）では厳密 64 バイトのみ受理する
 * - DER 再エンコード / 末尾バイト付加は既定で拒否される
 * - `encoding` を明示した非 JWS 用途（DER / recovered）は従来どおり動く（正常系の非退行）
 * - `'recovered'` では recovery バイトの正しさまで検証する
 */

import { describe, expect, it } from 'bun:test';
import type { EcdsaCurve } from '../../../src/internal/keymanager/signer.js';
import {
  p1363ToDer,
  signSecp256k1Recoverable,
  verifyP256,
  verifySecp256k1,
} from '../../../src/internal/keymanager/signer.js';
import { appendByte, DIGEST, FIXTURES, PRIVATE_KEY } from './fixtures.js';

/** 曲線ごとの検証関数（オプション引数の型が曲線で異なるため個別に束ねる）。 */
const VERIFIERS: Record<
  EcdsaCurve,
  (signature: Uint8Array, publicKey: Uint8Array, encoding?: 'p1363' | 'der') => boolean
> = {
  secp256k1: (signature, publicKey, encoding) =>
    verifySecp256k1(DIGEST, signature, publicKey, encoding === undefined ? {} : { encoding }),
  p256: (signature, publicKey, encoding) =>
    verifyP256(DIGEST, signature, publicKey, encoding === undefined ? {} : { encoding }),
};

describe.each<EcdsaCurve>(['secp256k1', 'p256'])('canonical signature encoding (%s)', (curve) => {
  const { raw, publicKey, uncompressedPublicKey } = FIXTURES[curve];
  const verify = VERIFIERS[curve];

  it('regression: accepts the canonical 64-byte P1363 signature', () => {
    expect(verify(raw, publicKey)).toBe(true);
    expect(verify(raw, uncompressedPublicKey)).toBe(true);
  });

  it('regression: rejects a DER re-encoding of the same valid signature by default', () => {
    // 正規の 64B 署名を DER へ再エンコードしただけの、数学的には有効な署名。
    // 受理すると同一クレームに対する有効な JWS が 2 通り成立してしまう。
    const der = p1363ToDer(raw, curve);
    expect(der.length).not.toBe(64);
    expect(verify(der, publicKey)).toBe(false);
  });

  it('regression: still verifies DER when the caller opts in explicitly', () => {
    // DER を返す HSM / KMS 向けの非 JWS 経路は明示 opt-in で従来どおり動く。
    const der = p1363ToDer(raw, curve);
    expect(verify(der, publicKey, 'der')).toBe(true);
  });

  it('regression: rejects a P1363 signature with an extra trailing byte', () => {
    for (const trailing of [0x00, 0x01, 0xff]) {
      expect(verify(appendByte(raw, trailing), publicKey)).toBe(false);
    }
  });

  it('regression: rejects a truncated P1363 signature', () => {
    expect(verify(raw.subarray(0, 63), publicKey)).toBe(false);
  });

  it('regression: rejects an empty signature', () => {
    expect(verify(new Uint8Array(0), publicKey)).toBe(false);
  });
});

describe('verifySecp256k1 recovered encoding', () => {
  const { publicKey, uncompressedPublicKey } = FIXTURES.secp256k1;
  const { signature, recovery } = signSecp256k1Recoverable(DIGEST, PRIVATE_KEY);

  it('regression: accepts the genuine 65-byte recoverable signature when opted in', () => {
    expect(verifySecp256k1(DIGEST, signature, publicKey, { encoding: 'recovered' })).toBe(true);
    expect(
      verifySecp256k1(DIGEST, signature, uncompressedPublicKey, { encoding: 'recovered' }),
    ).toBe(true);
  });

  it('regression: rejects a 65-byte signature whose recovery byte does not recover the key', () => {
    // 修正前は末尾 1 バイトを読み捨てていたため 0x00 / 0x01 / 0xff のいずれも通過した。
    // recovery バイトを実際に使って公開鍵を復元し、一致まで要求することで表現が一意に定まる。
    const compact = signature.subarray(0, 64);
    for (const trailing of [0x00, 0x01, 0x02, 0x7f, 0xff]) {
      if (trailing === recovery) {
        continue;
      }
      const tampered = appendByte(compact, trailing);
      expect(verifySecp256k1(DIGEST, tampered, publicKey, { encoding: 'recovered' })).toBe(false);
    }
  });

  it('regression: rejects the 65-byte recoverable signature under the default (JWS) encoding', () => {
    // 既定は RFC 7515 §3.1 の厳密 64 バイト。recovery 付き 65 バイトは非正準として拒否する。
    expect(verifySecp256k1(DIGEST, signature, publicKey)).toBe(false);
  });

  it('regression: rejects a 64-byte signature under the recovered encoding', () => {
    const compact = signature.subarray(0, 64);
    expect(verifySecp256k1(DIGEST, compact, publicKey, { encoding: 'recovered' })).toBe(false);
  });

  it('regression: rejects a valid signature paired with a different key', () => {
    const other = FIXTURES.secp256k1.ec.getPublicKey(new Uint8Array(32).fill(9), true);
    expect(verifySecp256k1(DIGEST, signature, other, { encoding: 'recovered' })).toBe(false);
  });
});

describe("verifyP256 rejects the secp256k1-only 'recovered' encoding at runtime", () => {
  it('regression: returns false when a JS-level caller bypasses the type exclusion', () => {
    // `VerifyP256Options` は `'recovered'` を型で除外するが、型検査を持たない JS 呼び出しは
    // ここへ到達し得る。曲線に束縛されない recovery 検証（secp256k1 固定）へ落ちないよう、
    // ランタイムでも fail-closed で拒否することを固定する。
    const { raw, publicKey } = FIXTURES.p256;
    const verifyUnsafe = verifyP256 as unknown as (
      digest: Uint8Array,
      signature: Uint8Array,
      publicKey: Uint8Array,
      options: { encoding: string },
    ) => boolean;

    // 正準な 64 バイト署名（既定では受理される）を 65 バイト化しても受理してはならない。
    expect(verifyP256(DIGEST, raw, publicKey)).toBe(true);
    for (const trailing of [0x00, 0x01, 0xff]) {
      expect(
        verifyUnsafe(DIGEST, appendByte(raw, trailing), publicKey, { encoding: 'recovered' }),
      ).toBe(false);
    }
    expect(verifyUnsafe(DIGEST, raw, publicKey, { encoding: 'recovered' })).toBe(false);
  });
});
