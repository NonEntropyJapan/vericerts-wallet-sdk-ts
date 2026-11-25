import { describe, expect, test } from 'bun:test';
import { base64 } from '@scure/base';
import { VericertsError } from '../../../errors.js';
import { loadTrustedList, verifyQualifiedCertificate } from '../etsi-tsl.js';
import { extractQtspCertificates } from '../tsl.js';
import { makeCertificate } from './fixtures.js';
import { signEnvelopedXml } from './xml/xml-fixtures.js';

const GRANTED = 'http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/granted';

/** LOTL 本体（署名前）。OtherTSLPointer を含み auto 判定で lotl になる。 */
function lotlBody(): { open: string; inner: string; close: string } {
  return {
    open: '<TrustServiceStatusList>',
    inner:
      '<OtherTSLPointer><TSLLocation>https://de.example/tsl.xml</TSLLocation>' +
      '<SchemeTerritory>DE</SchemeTerritory></OtherTSLPointer>',
    close: '</TrustServiceStatusList>',
  };
}

/** granted な QTSP CA を 1 件持つ TSL 本体（署名前）。 */
function tslBody(caDer: Uint8Array): { open: string; inner: string; close: string } {
  return {
    open: '<TrustServiceStatusList>',
    inner:
      '<TSPService><ServiceTypeIdentifier>http://uri.etsi.org/TrstSvc/Svctype/CA/QC</ServiceTypeIdentifier><ServiceStatus>' +
      GRANTED +
      '</ServiceStatus><X509Certificate>' +
      base64.encode(caDer) +
      '</X509Certificate></TSPService>',
    close: '</TrustServiceStatusList>',
  };
}

describe('loadTrustedList（統合）', () => {
  test('署名済み LOTL を取得・検証し国一覧を返す', async () => {
    const signer = makeCertificate({ cn: 'EU LOTL Signer', kind: 'rsa' });
    const b = lotlBody();
    const xml = signEnvelopedXml({
      bodyOpen: b.open,
      bodyInner: b.inner,
      bodyClose: b.close,
      privateKey: signer.privateKey,
      certDer: signer.der,
      kind: 'rsa',
    });
    const result = await loadTrustedList('https://ec.europa.eu/lotl.xml', {
      fetcher: async () => xml,
    });
    expect(result.signatureValid).toBe(true);
    expect(result.countries).toEqual(['DE']);
    expect(result.pointers[0]?.location).toBe('https://de.example/tsl.xml');
  });

  test('署名済み TSL を取得・検証しサービス証明書を返す', async () => {
    const ca = makeCertificate({ cn: 'DE QTSP CA', kind: 'rsa' });
    const signer = makeCertificate({ cn: 'DE TSL Signer', kind: 'ec' });
    const b = tslBody(ca.der);
    const xml = signEnvelopedXml({
      bodyOpen: b.open,
      bodyInner: b.inner,
      bodyClose: b.close,
      privateKey: signer.privateKey,
      certDer: signer.der,
      kind: 'ec',
    });
    const result = await loadTrustedList('https://de.example/tsl.xml', {
      fetcher: async () => xml,
      kind: 'tsl',
    });
    expect(result.signatureValid).toBe(true);
    expect(result.serviceCertificates.length).toBe(1);
    expect(result.serviceCertificates[0]?.granted).toBe(true);
  });

  test('取得失敗は LOTL_FETCH_FAILED(10301)', async () => {
    await expect(
      loadTrustedList('https://ec.europa.eu/lotl.xml', {
        fetcher: async () => {
          throw new Error('network');
        },
      }),
    ).rejects.toMatchObject({ code: '10301' });
  });

  test('TSL 取得失敗は TSL_FETCH_FAILED(5001)', async () => {
    await expect(
      loadTrustedList('https://de.example/tsl.xml', {
        kind: 'tsl',
        fetcher: async () => {
          throw new Error('network');
        },
      }),
    ).rejects.toMatchObject({ code: '5001' });
  });

  // `fetcher` 未注入（`typeof fetcher !== 'function'`）は設定ミスであり、ネットワーク障害
  // （上の「TSL 取得失敗」テスト）と区別してエラーコードを固定する回帰テスト。
  test('fetcher 未注入は TSL_FETCH_FAILED(5001)（kind: tsl 明示時）', async () => {
    await expect(
      loadTrustedList('https://de.example/tsl.xml', {
        kind: 'tsl',
        fetcher: undefined as never,
      }),
    ).rejects.toMatchObject({ code: '5001' });
  });

  test('fetcher 未注入は TSL_FETCH_FAILED(5001)（kind 省略時も同じコード）', async () => {
    await expect(
      loadTrustedList('https://ec.europa.eu/lotl.xml', {
        fetcher: undefined as never,
      }),
    ).rejects.toMatchObject({ code: '5001' });
  });

  // `options.kind` がユニオン（'lotl' | 'tsl' | 'auto'）外の値の場合、`validKindHint`
  // （`kind-hint.ts`）が `auto` にフォールバックし、XML 内容から正しく種別判定されることを
  // 固定する回帰テスト。
  //
  // 入力は LOTL XML（`OtherTSLPointer` を含む）を使う。TSL XML を入力にすると
  // `extractResult` は `kind === 'lotl'` 以外を一律 TSL 解析（else 節）に落とすため、`kindHint`
  // が `'not-a-real-kind'`（無検証のまま TSL 扱い＝偶然 else 節に入る）でも `'auto'`（正しく
  // フォールバックし `detectKind` が `'tsl'` を返す）でも結果が一致してしまい、fix 前後を判別
  // できない非識別テストになっていた。LOTL XML なら、`kindHint`
  // が無検証のまま採用された場合は `'not-a-real-kind' !== 'lotl'` で else 節（TSL 解析）に落ちて
  // `pointers` / `countries` が空になり、`'auto'` へ正しくフォールバックした場合は `detectKind`
  // が `OtherTSLPointer` を検出して `'lotl'` 分岐に入り `pointers` / `countries` が非空になる、と
  // 判定可能な差が生じる。
  test('不正な kind は auto 扱いになり、LOTL の内容から正しく判定される', async () => {
    const signer = makeCertificate({ cn: 'EU LOTL Signer', kind: 'rsa' });
    const b = lotlBody();
    const xml = signEnvelopedXml({
      bodyOpen: b.open,
      bodyInner: b.inner,
      bodyClose: b.close,
      privateKey: signer.privateKey,
      certDer: signer.der,
      kind: 'rsa',
    });
    const result = await loadTrustedList('https://ec.europa.eu/lotl.xml', {
      fetcher: async () => xml,
      kind: 'not-a-real-kind' as never,
    });
    expect(result.signatureValid).toBe(true);
    expect(result.countries).toEqual(['DE']);
    expect(result.pointers[0]?.location).toBe('https://de.example/tsl.xml');
  });

  test('署名検証失敗（改ざん）は XMLDSIG_VERIFICATION_FAILED(10302)', async () => {
    const signer = makeCertificate({ cn: 'Signer', kind: 'rsa' });
    const b = lotlBody();
    const xml = signEnvelopedXml({
      bodyOpen: b.open,
      bodyInner: b.inner,
      bodyClose: b.close,
      privateKey: signer.privateKey,
      certDer: signer.der,
      kind: 'rsa',
    });
    const tampered = xml.replace('https://de.example/tsl.xml', 'https://evil.example/tsl.xml');
    await expect(
      loadTrustedList('https://ec.europa.eu/lotl.xml', { fetcher: async () => tampered }),
    ).rejects.toMatchObject({ code: '10302' });
  });
});

describe('verifyQualifiedCertificate（統合: TSL Anchor に対するチェーン検証）', () => {
  test('TSL の granted CA が発行した Issuer 証明書を信頼する', async () => {
    const ca = makeCertificate({ cn: 'QTSP CA', kind: 'rsa' });
    const issuer = makeCertificate({
      cn: 'PID Issuer',
      kind: 'ec',
      issuer: { name: ca.subjectName, privateKey: ca.privateKey, kind: 'rsa' },
    });
    // TSL 本体から Anchor を抽出（extractQtspCertificates 経由の実データ）。
    const b = tslBody(ca.der);
    const anchors = extractQtspCertificates(`${b.open}${b.inner}${b.close}`);
    const result = await verifyQualifiedCertificate({
      certDer: issuer.der,
      trustAnchors: anchors,
    });
    expect(result.trusted).toBe(true);
  });

  test('Trust Anchor に連結しない証明書は QUALIFIED_CERT_INVALID(10303)', async () => {
    const ca = makeCertificate({ cn: 'QTSP CA', kind: 'rsa' });
    const rogue = makeCertificate({ cn: 'Rogue Issuer', kind: 'ec' });
    const b = tslBody(ca.der);
    const anchors = extractQtspCertificates(`${b.open}${b.inner}${b.close}`);
    await expect(
      verifyQualifiedCertificate({ certDer: rogue.der, trustAnchors: anchors }),
    ).rejects.toMatchObject({ code: '10303' });
  });

  test('Trust Anchor が空なら QUALIFIED_CERT_INVALID(10303)', async () => {
    const issuer = makeCertificate({ cn: 'Issuer', kind: 'ec' });
    const err = await verifyQualifiedCertificate({
      certDer: issuer.der,
      trustAnchors: [],
    }).catch((e) => e);
    expect(err).toBeInstanceOf(VericertsError);
    expect((err as VericertsError).code).toBe('10303');
  });
});
