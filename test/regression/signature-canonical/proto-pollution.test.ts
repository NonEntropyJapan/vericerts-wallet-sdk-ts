/**
 * `Object.prototype` 汚染下でも ECDSA 検証の既定（low-S 強制・厳密 64 バイト）が緩まないことの
 * 回帰テスト。
 *
 * 欠陥時の挙動: `options.allowHighS ?? false` / `options.encoding ?? 'p1363'` はプロトタイプ鎖を
 * 辿るため、`Object.prototype.allowHighS = true` の汚染下では **オプションを渡していない
 * 正当な検証でも high-S 署名が受理される**。署名の可鍛性が復活し、同一の (r, s) に対して
 * 有効なバイト列が 2 通り成立するため、署名バイト列を重複判定キーに使う経路の
 * リプレイ検知が壊れる。`encoding` の汚染も受理する表現を厳密 64 バイト以外へ広げる。
 */

import { describe, expect, it } from 'bun:test';
import { withPollutedPrototype } from '../../../src/internal/__tests__/prototype-pollution.fixtures.js';
import type { EcdsaCurve } from '../../../src/internal/keymanager/signer.js';
import {
  p1363ToDer,
  verifyP256,
  verifySecp256k1,
} from '../../../src/internal/keymanager/signer.js';
import { DIGEST, FIXTURES, toHighS } from './fixtures.js';

/** 曲線ごとの検証関数。`options` を省略した既定の呼び出しも試せる形にする。 */
const VERIFIERS: Record<
  EcdsaCurve,
  (signature: Uint8Array, publicKey: Uint8Array, options?: Record<string, unknown>) => boolean
> = {
  secp256k1: (signature, publicKey, options) =>
    options === undefined
      ? verifySecp256k1(DIGEST, signature, publicKey)
      : verifySecp256k1(DIGEST, signature, publicKey, options),
  p256: (signature, publicKey, options) =>
    options === undefined
      ? verifyP256(DIGEST, signature, publicKey)
      : verifyP256(DIGEST, signature, publicKey, options),
};

describe.each<EcdsaCurve>([
  'secp256k1',
  'p256',
])('ECDSA 検証の Object.prototype 汚染（%s）', (curve) => {
  const { raw, publicKey } = FIXTURES[curve];
  const verify = VERIFIERS[curve];
  const highS = toHighS(raw, curve);

  it('regression: allowHighS の汚染で high-S 署名が受理されない（options 省略）', () => {
    expect(withPollutedPrototype({ allowHighS: true }, () => verify(highS, publicKey))).toBe(false);
  });

  it('regression: allowHighS の汚染で high-S 署名が受理されない（options: {}）', () => {
    expect(withPollutedPrototype({ allowHighS: true }, () => verify(highS, publicKey, {}))).toBe(
      false,
    );
  });

  it('regression: encoding の汚染で DER 表現が受理されない', () => {
    // 既定は厳密 64 バイト（p1363）のみ。汚染値で 'der' に化けると非正準表現が通る。
    const der = p1363ToDer(raw, curve);
    expect(withPollutedPrototype({ encoding: 'der' }, () => verify(der, publicKey))).toBe(false);
  });

  it('regression: 正常系: 汚染下でも正当な low-S / p1363 署名は従来どおり受理される', () => {
    // 受理集合を狭める変更のため、正当な署名が拒否されていないことを確認する。
    expect(
      withPollutedPrototype({ allowHighS: true, encoding: 'der' }, () =>
        verify(raw, publicKey, {}),
      ),
    ).toBe(true);
  });

  it('regression: 正常系: allowHighS / encoding を明示した検証は従来どおり opt-in が効く', () => {
    expect(verify(highS, publicKey, { allowHighS: true })).toBe(true);
    expect(verify(p1363ToDer(raw, curve), publicKey, { encoding: 'der' })).toBe(true);
  });
});
