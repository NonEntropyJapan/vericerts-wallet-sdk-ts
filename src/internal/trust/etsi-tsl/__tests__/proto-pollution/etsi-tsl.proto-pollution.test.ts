/**
 * `loadTrustedList` の種別オプション（`kind`）の `Object.prototype` 汚染耐性
 *
 * 同関数は `fetcher` を `ownProperty` で own 限定に読む一方、`kind` だけをプロトタイプ鎖で
 * 読んでいた。鎖読みだと `kind` を**省略した**正当な呼び出し（＝自動判定を期待する呼び出し）でも
 * `Object.prototype.kind` の汚染値が種別として採用され、`detectKind(xml)` が丸ごと迂回される。
 * 汚染値が `'lotl'` なら、`OtherTSLPointer` を持たない本物の国別 TSL でも LOTL 分岐へ入り、
 * `extractQtspCertificates` が走らないまま `serviceCertificates` が空配列で返る。例外は出ないため
 * 「その国に QTSP が居ない」と区別が付かず、Trust Anchor が無言で欠落する。
 *
 * ここでは `kind` が own 限定で読まれること（データ汚染 / アクセサ汚染の両方）と、明示指定した
 * `kind` が従来どおり尊重されること（ポジティブコントロール）を固定する。汚染耐性テストを親の
 * `__tests__/` 直下ではなく `proto-pollution/` に置くのは、同ディレクトリの
 * `chain.proto-pollution.test.ts` と同じ方針（汚染耐性テストを独立配置する）に揃えるため。
 */

import { describe, expect, test } from 'bun:test';
import { base64 } from '@scure/base';
import {
  withPollutedPrototypeAccessorAsync,
  withPollutedPrototypeAsync,
} from '../../../../__tests__/prototype-pollution.fixtures.js';
import { loadTrustedList } from '../../etsi-tsl.js';
import { makeCertificate } from '../fixtures.js';
import { signEnvelopedXml } from '../xml/xml-fixtures.js';

const GRANTED = 'http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/granted';

const TSL_URL = 'https://de.example/tsl.xml';

/** 攻撃者が `Object.prototype.kind` へ仕込む種別（自動判定を迂回させる値）。 */
const ATTACKER_KIND = 'lotl';

/** granted な QTSP CA を 1 件持つ `TSPService`（署名前）。 */
function grantedService(): string {
  const ca = makeCertificate({ cn: 'DE QTSP CA', kind: 'rsa' });
  return (
    `<TSPService><ServiceTypeIdentifier>http://uri.etsi.org/TrstSvc/Svctype/CA/QC</ServiceTypeIdentifier><ServiceStatus>${GRANTED}</ServiceStatus>` +
    `<X509Certificate>${base64.encode(ca.der)}</X509Certificate></TSPService>`
  );
}

/** 加盟国 TSL への `OtherTSLPointer`（署名前）。これがあると `detectKind` は lotl を返す。 */
function tslPointer(): string {
  return (
    `<OtherTSLPointer><TSLLocation>${TSL_URL}</TSLLocation>` +
    `<SchemeTerritory>DE</SchemeTerritory></OtherTSLPointer>`
  );
}

/** 本体要素を包んで enveloped XMLDSig 署名を施す（署名者は EC 鍵）。 */
function signBody(bodyInner: string): string {
  const signer = makeCertificate({ cn: 'DE TSL Signer', kind: 'ec' });
  return signEnvelopedXml({
    bodyOpen: '<TrustServiceStatusList>',
    bodyInner,
    bodyClose: '</TrustServiceStatusList>',
    privateKey: signer.privateKey,
    certDer: signer.der,
    kind: 'ec',
  });
}

describe('loadTrustedList の kind オプション汚染耐性', () => {
  // 汚染は共有フィクスチャで**非列挙**に仕込む（`prototype-pollution.fixtures.ts` の方針）。
  // `fetcher` を跨いで `await` するため `*Async` 版を使う（同期版だと Promise の解決前に汚染が
  // 戻り、検証したい経路が汚染下で走らずトートロジーになる）。
  test('継承した kind（データ汚染）は自動判定を迂回しない', async () => {
    // `OtherTSLPointer` を持たない＝ `detectKind` が tsl を返す本物の国別 TSL。
    const xml = signBody(grantedService());

    // kind は渡していない（自動判定を期待する正当な呼び出し）。汚染値を拾うと LOTL 分岐へ入り、
    // QTSP 証明書の抽出が丸ごと飛ぶ。
    const result = await withPollutedPrototypeAsync({ kind: ATTACKER_KIND }, () =>
      loadTrustedList(TSL_URL, { fetcher: async () => xml }),
    );

    expect(result.serviceCertificates.length).toBe(1);
    expect(result.serviceCertificates[0]?.granted).toBe(true);
  });

  // getter は呼ばれるたびに新しい値を返せるため、汚染値との同一性比較では弾けない。
  test('継承した kind（アクセサ汚染）も自動判定を迂回しない', async () => {
    const xml = signBody(grantedService());

    const result = await withPollutedPrototypeAccessorAsync({ kind: () => ATTACKER_KIND }, () =>
      loadTrustedList(TSL_URL, { fetcher: async () => xml }),
    );

    expect(result.serviceCertificates.length).toBe(1);
    expect(result.serviceCertificates[0]?.granted).toBe(true);
  });

  // ポジティブコントロール。own 限定読みを「常に undefined を返す」実装に退行させても上 2 件は
  // 通ってしまい、過剰に弾いた場合と区別が付かない。そこで**自動判定の結果と明示値が食い違う**
  // XML（`OtherTSLPointer` と granted な `TSPService` の両方を持つ）を使い、明示した `tsl` が
  // 自動判定の `lotl` に優先することを固定する。
  test('汚染下でも明示的に渡した kind は従来どおり尊重される（正常系）', async () => {
    const xml = signBody(`${tslPointer()}${grantedService()}`);

    const result = await withPollutedPrototypeAsync({ kind: ATTACKER_KIND }, () =>
      loadTrustedList(TSL_URL, { fetcher: async () => xml, kind: 'tsl' }),
    );

    expect(result.serviceCertificates.length).toBe(1);
    expect(result.pointers).toEqual([]);
  });
});

/**
 * `signingTrustAnchorsDer`の汚染耐性。継承値を拾うと、攻撃者が
 * `Object.prototype` へ置いた証明書が LOTL / TSL 署名者の信頼の起点になる。own 限定に読むので、
 * 汚染値は「未設定」＝ `signatureAnchored: false` に倒れる（汚染アンカーで `true` にならない）。
 */
describe('loadTrustedList の signingTrustAnchorsDer 汚染耐性', () => {
  test('継承した signingTrustAnchorsDer（データ汚染）はアンカーにならない', async () => {
    const attackerAnchor = makeCertificate({ cn: 'Attacker Root', kind: 'rsa', ca: true });
    const xml = signBody(grantedService());

    const result = await withPollutedPrototypeAsync(
      { signingTrustAnchorsDer: [attackerAnchor.der] },
      () => loadTrustedList(TSL_URL, { fetcher: async () => xml }),
    );

    expect(result.signatureAnchored).toBe(false);
  });

  test('継承した signingTrustAnchorsDer（アクセサ汚染）もアンカーにならない', async () => {
    const attackerAnchor = makeCertificate({ cn: 'Attacker Root', kind: 'rsa', ca: true });
    const xml = signBody(grantedService());

    const result = await withPollutedPrototypeAccessorAsync(
      { signingTrustAnchorsDer: () => [attackerAnchor.der] },
      () => loadTrustedList(TSL_URL, { fetcher: async () => xml }),
    );

    expect(result.signatureAnchored).toBe(false);
  });

  // ポジティブコントロール。own 限定読みを「常に undefined を返す」実装に退行させても上 2 件は
  // 通ってしまうため、汚染下でも明示的に渡したアンカーが尊重されることを併せて固定する。
  test('汚染下でも明示的に渡した signingTrustAnchorsDer は尊重される（正常系）', async () => {
    const attackerAnchor = makeCertificate({ cn: 'Attacker Root', kind: 'rsa', ca: true });
    const signer = makeCertificate({ cn: 'DE TSL Signer', kind: 'ec' });
    const xml = signEnvelopedXml({
      bodyOpen: '<TrustServiceStatusList>',
      bodyInner: grantedService(),
      bodyClose: '</TrustServiceStatusList>',
      privateKey: signer.privateKey,
      certDer: signer.der,
      kind: 'ec',
    });

    const result = await withPollutedPrototypeAsync(
      { signingTrustAnchorsDer: [attackerAnchor.der] },
      () =>
        loadTrustedList(TSL_URL, {
          fetcher: async () => xml,
          signingTrustAnchorsDer: [signer.der],
        }),
    );

    expect(result.signatureAnchored).toBe(true);
  });
});
