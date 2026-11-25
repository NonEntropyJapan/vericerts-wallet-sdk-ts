/**
 * 回帰テスト: high-S 署名の相互運用性と low-S 正規化の一貫性。
 *
 * `@noble/curves` の `verify()` は既定で low-S を強制する（署名の可鍛性対策として正しい）。しかし
 * AWS KMS / PKCS#11 トークン等の HSM や第三者 Issuer は high-S の ECDSA 署名を**仕様上正当に**返す。
 * 修正前は `verifyP256` / `verifySecp256k1` に opt-out が無く、そうした署名を一切検証できなかった。
 * また `derToP1363` / `p1363ToDer` は low-S 正規化を行わない一方でその旨が明示されておらず、
 * 正規化ロジックは `remote-signer.ts` に閉じて重複していた。
 *
 * 本テストは以下を固定する:
 * - high-S 署名は既定で拒否される（malleability 対策の既定は据え置き）
 * - `allowHighS: true` で第三者発行の high-S 署名を検証できる
 * - `derToP1363` / `p1363ToDer` は `s` を正規化しない（往復でバイト列が保存される）
 * - 共有 `normalizeLowS` が high-S を low-S へ揃え、low-S には冪等に働く
 */

import { describe, expect, it } from 'bun:test';
import { ErrorCodes, VericertsError } from '../../../src/internal/errors.js';
import type { EcdsaCurve } from '../../../src/internal/keymanager/signer.js';
import {
  derToP1363,
  normalizeLowS,
  p1363ToDer,
  verifyP256,
  verifySecp256k1,
} from '../../../src/internal/keymanager/signer.js';
import { DIGEST, FIXTURES, toHex, toHighS } from './fixtures.js';

/** 曲線ごとの検証関数（`allowHighS` を指定できる形に束ねる）。 */
const VERIFIERS: Record<
  EcdsaCurve,
  (signature: Uint8Array, publicKey: Uint8Array, allowHighS?: boolean) => boolean
> = {
  secp256k1: (signature, publicKey, allowHighS) =>
    verifySecp256k1(DIGEST, signature, publicKey, allowHighS === undefined ? {} : { allowHighS }),
  p256: (signature, publicKey, allowHighS) =>
    verifyP256(DIGEST, signature, publicKey, allowHighS === undefined ? {} : { allowHighS }),
};

describe.each<EcdsaCurve>(['secp256k1', 'p256'])('high-S interoperability (%s)', (curve) => {
  const { raw, publicKey, ec } = FIXTURES[curve];
  const verify = VERIFIERS[curve];
  const highS = toHighS(raw, curve);

  it('regression: the fixture is a genuinely valid high-S signature', () => {
    // s を n-s に置き換えた署名は同一鍵・同一 digest に対して数学的に有効。
    expect(ec.Signature.fromBytes(highS, 'compact').hasHighS()).toBe(true);
    expect(ec.verify(highS, DIGEST, publicKey, { prehash: false, lowS: false })).toBe(true);
  });

  it('regression: rejects the high-S signature by default (malleability guard stays on)', () => {
    expect(verify(highS, publicKey)).toBe(false);
    expect(verify(highS, publicKey, false)).toBe(false);
  });

  it('regression: verifies the high-S signature when allowHighS is opted in', () => {
    // 第三者 Issuer / KMS が発行した high-S 署名を検証できる経路。
    expect(verify(highS, publicKey, true)).toBe(true);
  });

  it('regression: still verifies the low-S signature under allowHighS', () => {
    expect(verify(raw, publicKey, true)).toBe(true);
    expect(verify(raw, publicKey)).toBe(true);
  });

  it('regression: rejects a genuinely invalid signature even with allowHighS', () => {
    // allowHighS は「s の範囲」だけを緩める。無効な署名は依然として拒否される。
    const bogus = new Uint8Array(highS);
    bogus[0] = (bogus[0] ?? 0) ^ 0xff;
    expect(verify(bogus, publicKey, true)).toBe(false);
  });
});

describe.each<EcdsaCurve>(['secp256k1', 'p256'])('normalizeLowS (%s)', (curve) => {
  const { raw, publicKey, ec } = FIXTURES[curve];
  const verify = VERIFIERS[curve];
  const highS = toHighS(raw, curve);

  it('regression: normalizes a high-S signature to low-S', () => {
    const normalized = normalizeLowS(highS, curve);
    expect(ec.Signature.fromBytes(normalized, 'compact').hasHighS()).toBe(false);
    // 正規化後は既定（low-S 強制）の検証を通る = 発行側で揃えれば相互運用できる。
    expect(verify(normalized, publicKey)).toBe(true);
  });

  it('regression: preserves r and yields the original low-S signature', () => {
    // high-S は元の low-S 署名の s を反転したものなので、正規化で元へ戻る。
    expect(toHex(normalizeLowS(highS, curve))).toBe(toHex(raw));
  });

  it('regression: is idempotent on an already low-S signature', () => {
    expect(toHex(normalizeLowS(raw, curve))).toBe(toHex(raw));
    expect(toHex(normalizeLowS(normalizeLowS(highS, curve), curve))).toBe(toHex(raw));
  });

  it('regression: throws SIGN_FAILED (1020) for a malformed signature', () => {
    expect(() => normalizeLowS(raw.subarray(0, 32), curve)).toThrow(
      new VericertsError(ErrorCodes.SIGN_FAILED),
    );
  });

  it('regression: throws UNSUPPORTED_ALGORITHM (1030) for an out-of-type curve', () => {
    expect(() => normalizeLowS(raw, 'ed25519' as unknown as EcdsaCurve)).toThrow(
      new VericertsError(ErrorCodes.UNSUPPORTED_ALGORITHM),
    );
  });
});

describe.each<EcdsaCurve>([
  'secp256k1',
  'p256',
])('format conversion keeps s as-is (%s)', (curve) => {
  const { raw } = FIXTURES[curve];
  const highS = toHighS(raw, curve);

  it('regression: p1363ToDer does not normalize s', () => {
    // 形式変換のみという契約（JSDoc 記載）を固定する。暗黙の正規化を入れると
    // derToP1363(p1363ToDer(x)) !== x になり、往復の可逆性が壊れる。
    const der = p1363ToDer(highS, curve);
    expect(toHex(derToP1363(der, curve))).toBe(toHex(highS));
  });

  it('regression: derToP1363 does not normalize s', () => {
    const der = p1363ToDer(highS, curve);
    const back = derToP1363(der, curve);
    expect(FIXTURES[curve].ec.Signature.fromBytes(back, 'compact').hasHighS()).toBe(true);
  });

  it('regression: composing derToP1363 with normalizeLowS yields a verifiable low-S signature', () => {
    // DER を返す KMS 経路の推奨手順: 形式変換 → 明示的な正規化。
    const der = p1363ToDer(highS, curve);
    const normalized = normalizeLowS(derToP1363(der, curve), curve);
    expect(VERIFIERS[curve](normalized, FIXTURES[curve].publicKey)).toBe(true);
  });
});
