/**
 * `verifyCertificateChain` の候補選択と critical 拡張の検査。
 *
 * ここで固定するのは 2 つある。
 *
 * 1. **同じ subject DN を名乗るおとり証明書で正当なチェーンが落ちないこと。** subject DN は
 *    攻撃者が自由に名乗れるので、DN 一致の最初の 1 通だけを試す実装は、おとりを候補集合へ
 *    混ぜるだけで正当なチェーンを `trusted:false` にできる（DoS）。署名検証まで候補ごとの
 *    述語に含め、通った候補を採用する必要がある。
 * 2. **解釈しない critical 拡張を持つ証明書を使わないこと**（RFC 5280 §6.1.4 (f)）。critical は
 *    CA が「この制限を解釈できないなら使うな」と書くフラグで、読み捨てると SDK が知らない
 *    拡張で絞られた証明書を「制限が無いもの」として通してしまう。
 *
 * `chain.test.ts` と分けてあるのは 1 ファイル 300 行の上限に収めるためで、対象関数は同じである。
 */

import { describe, expect, test } from 'bun:test';
import { verifyCertificateChain } from '../../chain.js';
import { type CertExtensionOptions, type CertFixture, makeCertificate } from '../fixtures.js';

/** `makeIntermediate` に渡せる追加オプション（拡張 + 有効期間 + subject 鍵の再利用）。 */
type IntermediateOptions = CertExtensionOptions & {
  notBefore?: Date;
  notAfter?: Date;
  subjectKey?: CertFixture['privateKey'];
};

/** extendedKeyUsage の OID（チェーン検証が値を解釈しない拡張の代表）。 */
const OID_EXTENDED_KEY_USAGE = '2.5.29.37';

/** ec 鍵で署名する発行者情報。 */
function issuerOf(cert: CertFixture): {
  name: number[];
  privateKey: CertFixture['privateKey'];
  kind: 'ec';
} {
  return { name: cert.subjectName, privateKey: cert.privateKey, kind: 'ec' };
}

/** 中間 CA として使える証明書を作る（`extra` で拡張を足す）。 */
function makeIntermediate(root: CertFixture, extra: IntermediateOptions = {}): CertFixture {
  return makeCertificate({
    cn: 'Intermediate CA',
    kind: 'ec',
    ca: true,
    keyUsage: ['keyCertSign'],
    issuer: issuerOf(root),
    ...extra,
  });
}

describe('verifyCertificateChain（同一 DN のおとり証明書）', () => {
  test('同じ subject DN の中間証明書を混ぜても正当なチェーンは信頼される', async () => {
    const root = makeCertificate({ cn: 'Root CA', kind: 'ec', ca: true });
    const real = makeIntermediate(root);
    // 同じ DN・同じ拡張だが鍵が違う（leaf を署名していない）中間証明書。
    const decoy = makeIntermediate(root);
    const leaf = makeCertificate({ cn: 'QTSP Issuer', kind: 'ec', issuer: issuerOf(real) });

    // おとりを先に置く（DN 一致の最初の 1 通で打ち切る実装はここで落ちる）。
    const result = await verifyCertificateChain(leaf.der, [decoy.der, real.der], {
      trustAnchorsDer: [root.der],
    });
    expect(result.trusted).toBe(true);
  });

  test('同じ subject DN の Trust Anchor を混ぜても正当なチェーンは信頼される', async () => {
    const real = makeCertificate({ cn: 'Root CA', kind: 'ec', ca: true });
    const decoy = makeCertificate({ cn: 'Root CA', kind: 'ec', ca: true });
    const inter = makeIntermediate(real);
    const leaf = makeCertificate({ cn: 'QTSP Issuer', kind: 'ec', issuer: issuerOf(inter) });

    const result = await verifyCertificateChain(leaf.der, [inter.der], {
      trustAnchorsDer: [decoy.der, real.der],
    });
    // `anchorSubjectDer` ではどちらの Anchor を採ったか区別できない（おとりと本物は subject DN が
    // バイト同一で、結果に serial / SPKI は載らない）。断言は回帰を担う 1 点に限る。
    expect(result.trusted).toBe(true);
  });

  test('DN が一致するだけで署名していない中間証明書しか無ければ信頼しない', async () => {
    const root = makeCertificate({ cn: 'Root CA', kind: 'ec', ca: true });
    const real = makeIntermediate(root);
    const decoy = makeIntermediate(root);
    const leaf = makeCertificate({ cn: 'QTSP Issuer', kind: 'ec', issuer: issuerOf(real) });

    const result = await verifyCertificateChain(leaf.der, [decoy.der], {
      trustAnchorsDer: [root.der],
    });
    expect(result.trusted).toBe(false);
  });
});

describe('verifyCertificateChain（CA 証明書の更新・候補数の上限）', () => {
  test('期限切れの旧 CA 証明書が同じバンドルに入っていても更新後の証明書で信頼される', async () => {
    // CA 証明書の更新期には旧新 2 通が同じ `x5c` に入る（鍵は同じなので両方が leaf の署名検証を
    // 通る）。有効期間の検査が候補ごとの述語の外にあると、期限切れが先に採用されてチェーン全体が
    // 落ちる = 通常運用で `trusted:false` になる。
    const root = makeCertificate({ cn: 'Root CA', kind: 'ec', ca: true });
    const renewed = makeIntermediate(root);
    const expired = makeIntermediate(root, {
      subjectKey: renewed.privateKey,
      notBefore: new Date(Date.now() - 400 * 86_400_000),
      notAfter: new Date(Date.now() - 86_400_000),
    });
    const leaf = makeCertificate({ cn: 'QTSP Issuer', kind: 'ec', issuer: issuerOf(renewed) });

    // 期限切れを先に置く（有効期間を述語の外に出した実装はここで落ちる）。
    const result = await verifyCertificateChain(leaf.der, [expired.der, renewed.der], {
      trustAnchorsDer: [root.der],
    });
    expect(result.trusted).toBe(true);
  });

  test('中間証明書が上限枚数を超えるバンドルは信頼しない', async () => {
    // 候補ごとに公開鍵検証を行うので試行回数は候補数に比例する。`x5c` 由来＝攻撃者が長さを
    // 決められるため、パース前に枚数で落とす。
    const root = makeCertificate({ cn: 'Root CA', kind: 'ec', ca: true });
    const real = makeIntermediate(root);
    const leaf = makeCertificate({ cn: 'QTSP Issuer', kind: 'ec', issuer: issuerOf(real) });
    const padding = Array.from({ length: 10 }, () => makeIntermediate(root).der);

    const trusts = (ders: readonly Uint8Array[]): Promise<{ trusted: boolean }> =>
      verifyCertificateChain(leaf.der, ders, { trustAnchorsDer: [root.der] });

    expect((await trusts([real.der, ...padding])).trusted).toBe(false);
    // 上限ちょうど（10 枚）は通る。
    expect((await trusts([real.der, ...padding.slice(0, 9)])).trusted).toBe(true);
  });
});

describe('verifyCertificateChain（解釈しない critical 拡張）', () => {
  test('leaf が解釈しない critical 拡張を持つチェーンは信頼しない', async () => {
    const root = makeCertificate({ cn: 'Root CA', kind: 'ec', ca: true });
    const inter = makeIntermediate(root);
    const leaf = makeCertificate({
      cn: 'QTSP Issuer',
      kind: 'ec',
      criticalExtensionOid: OID_EXTENDED_KEY_USAGE,
      issuer: issuerOf(inter),
    });
    const result = await verifyCertificateChain(leaf.der, [inter.der], {
      trustAnchorsDer: [root.der],
    });
    expect(result.trusted).toBe(false);
  });

  test('同じ拡張が critical でなければチェーンは信頼される', async () => {
    const root = makeCertificate({ cn: 'Root CA', kind: 'ec', ca: true });
    const inter = makeIntermediate(root);
    const leaf = makeCertificate({
      cn: 'QTSP Issuer',
      kind: 'ec',
      nonCriticalExtensionOid: OID_EXTENDED_KEY_USAGE,
      issuer: issuerOf(inter),
    });
    const result = await verifyCertificateChain(leaf.der, [inter.der], {
      trustAnchorsDer: [root.der],
    });
    expect(result.trusted).toBe(true);
  });

  test('中間証明書が解釈しない critical 拡張を持つチェーンは信頼しない', async () => {
    const root = makeCertificate({ cn: 'Root CA', kind: 'ec', ca: true });
    const inter = makeIntermediate(root, { criticalExtensionOid: OID_EXTENDED_KEY_USAGE });
    const leaf = makeCertificate({ cn: 'QTSP Issuer', kind: 'ec', issuer: issuerOf(inter) });
    const result = await verifyCertificateChain(leaf.der, [inter.der], {
      trustAnchorsDer: [root.der],
    });
    expect(result.trusted).toBe(false);
  });

  test('Trust Anchor の critical 拡張は検査しない', async () => {
    // Anchor は呼び出し側が TSL から取り出して設定した信頼の起点であり、攻撃者が差し込める
    // `intermediatesDer` とは前提が違う。RFC 5280 §6.1 も path validation の入力には拡張検査を
    // 課さない。`ca:true` を付けないこと・解釈しない critical 拡張を持つことの両方を許す。
    const root = makeCertificate({
      cn: 'Root CA',
      kind: 'ec',
      criticalExtensionOid: OID_EXTENDED_KEY_USAGE,
    });
    const inter = makeIntermediate(root);
    const leaf = makeCertificate({ cn: 'QTSP Issuer', kind: 'ec', issuer: issuerOf(inter) });
    const result = await verifyCertificateChain(leaf.der, [inter.der], {
      trustAnchorsDer: [root.der],
    });
    expect(result.trusted).toBe(true);
  });
});

describe('verifyCertificateChain（拡張の重複）', () => {
  test('同一 OID の拡張を 2 つ持つ中間証明書は中間として採らない', async () => {
    // RFC 5280 §4.2 は拡張 OID の重複を禁じる。後勝ちで黙って上書きすると、検査対象の拡張を
    // 無害な複製で押し流せてしまうので、走査ごと失敗扱い（= CA 制約を読めない）に倒す。
    const root = makeCertificate({ cn: 'Root CA', kind: 'ec', ca: true });
    const inter = makeIntermediate(root, { duplicateBasicConstraints: true });
    const leaf = makeCertificate({ cn: 'QTSP Issuer', kind: 'ec', issuer: issuerOf(inter) });
    const result = await verifyCertificateChain(leaf.der, [inter.der], {
      trustAnchorsDer: [root.der],
    });
    expect(result.trusted).toBe(false);
  });
});

describe('verifyCertificateChain（trustAnchorsDer の型）', () => {
  test('trustAnchorsDer が配列でなければ信頼しない', async () => {
    const root = makeCertificate({ cn: 'Root CA', kind: 'ec', ca: true });
    const leaf = makeCertificate({ cn: 'QTSP Issuer', kind: 'ec', issuer: issuerOf(root) });
    const result = await verifyCertificateChain(leaf.der, [], {
      trustAnchorsDer: 'not-an-array',
    } as unknown as { trustAnchorsDer: readonly Uint8Array[] });
    expect(result.trusted).toBe(false);
  });
});
