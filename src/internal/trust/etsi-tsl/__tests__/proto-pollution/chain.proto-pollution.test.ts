/**
 * 証明書チェーン検証の時刻・深さオプションの `Object.prototype` 汚染耐性テスト
 *
 * `options.now` をプロトタイプ鎖で読むと、`now` を**省略した**正当な検証でも汚染値が
 * 基準時刻として使われ、**期限切れ（notAfter 超過）の証明書チェーンが信頼される**。
 * `options.maxDepth` の継承値はチェーン長の上限を緩め、想定より深い経路を通す。
 */

import { describe, expect, test } from 'bun:test';
import { withPollutedPrototypeAsync } from '../../../../__tests__/prototype-pollution.fixtures.js';
import { verifyCertificateChain } from '../../chain.js';
import { makeCertificate } from '../fixtures.js';

/** 有効期間が既に過ぎている（notAfter が過去の）リーフと、その発行 Anchor を作る。 */
function expiredChain() {
  const past = new Date(Date.now() - 30 * 86_400_000);
  const alsoPast = new Date(Date.now() - 10 * 86_400_000);
  // Anchor はリーフの有効期間と実時刻の双方を覆う広い有効期間にする（Anchor 側の期間切れで
  // 判定が変わると、リーフの期限切れを見ているのか区別できなくなるため）。
  const root = makeCertificate({
    cn: 'Root CA',
    kind: 'ec',
    notBefore: new Date(Date.now() - 60 * 86_400_000),
    notAfter: new Date(Date.now() + 365 * 86_400_000),
  });
  const leaf = makeCertificate({
    cn: 'Expired Issuer',
    kind: 'ec',
    notBefore: past,
    notAfter: alsoPast,
    issuer: { name: root.subjectName, privateKey: root.privateKey, kind: 'ec' },
  });
  // 汚染値として仕込む「証明書がまだ有効だった頃」の時刻（エポック秒）。
  const whenValid = Math.floor((past.getTime() + alsoPast.getTime()) / 2000);
  return { root, leaf, whenValid };
}

describe('verifyCertificateChain の時刻オプション汚染耐性', () => {
  test('継承した now では期限切れ証明書チェーンを信頼しない', async () => {
    const { root, leaf, whenValid } = expiredChain();
    const result = await withPollutedPrototypeAsync({ now: whenValid }, () =>
      // now は渡していない。汚染値を拾えば「まだ有効」と判定され信頼されてしまう。
      verifyCertificateChain(leaf.der, [], { trustAnchorsDer: [root.der] }),
    );
    expect(result.trusted).toBe(false);
  });

  test('継承した maxDepth はチェーン深さの上限を緩めない', async () => {
    const root = makeCertificate({ cn: 'Root CA', kind: 'ec' });
    const leaf = makeCertificate({
      cn: 'Issuer',
      kind: 'ec',
      issuer: { name: root.subjectName, privateKey: root.privateKey, kind: 'ec' },
    });
    // maxDepth の継承値を拾っても、既定 5 の範囲内の正当なチェーンは従来どおり信頼される
    // （＝汚染で挙動が変わらないこと）。
    const result = await withPollutedPrototypeAsync({ maxDepth: 0 }, () =>
      verifyCertificateChain(leaf.der, [], { trustAnchorsDer: [root.der] }),
    );
    expect(result.trusted).toBe(true);
  });

  test('明示的に渡した now は従来どおり基準時刻になる（正常系）', async () => {
    const { root, leaf, whenValid } = expiredChain();
    const result = await verifyCertificateChain(leaf.der, [], {
      trustAnchorsDer: [root.der],
      now: whenValid,
    });
    expect(result.trusted).toBe(true);
  });

  test('有効期間内の証明書は従来どおり信頼される（正常系）', async () => {
    const root = makeCertificate({ cn: 'Root CA', kind: 'ec' });
    const leaf = makeCertificate({
      cn: 'Issuer',
      kind: 'ec',
      issuer: { name: root.subjectName, privateKey: root.privateKey, kind: 'ec' },
    });
    const result = await verifyCertificateChain(leaf.der, [], { trustAnchorsDer: [root.der] });
    expect(result.trusted).toBe(true);
  });
});
