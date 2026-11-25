/**
 * `loadTrustedList` の署名者アンカリング。
 *
 * `verifyXmlDsig` は検証対象の XML 自身の `ds:KeyInfo/ds:X509Certificate` を署名鍵として使うため、
 * それだけでは**自己署名の LOTL / TSL がそのまま通る**。その結果の `serviceCertificates` は
 * `createWallet({ rpTrustAnchors })` / `{ issuerTrustAnchors }` の出どころであり、アンカリングが
 * 無いままだと RP / Issuer の信頼の起点全体が取得元 URL への TLS だけに依存する。
 *
 * ここでは (1) `signingTrustAnchorsDer` を渡した場合に署名者証明書のチェーン検証が課され、連結
 * しない署名者が署名検証失敗（10302 / 5002）で拒否されること、(2) 渡さない場合は従来どおり通すが
 * `signatureAnchored: false` としてギャップが公開境界に現れること、(3) チェーン検証の基準時刻に
 * `nowSeconds` が使われること、(4) 明示指定が不正な型なら「未設定」に畳まず拒否すること
 * （fail-closed）を固定する。
 */

import { describe, expect, test } from 'bun:test';
import { base64 } from '@scure/base';
import { loadTrustedList } from '../../etsi-tsl.js';
import { type CertFixture, makeCertificate } from '../fixtures.js';
import { signEnvelopedXml } from '../xml/xml-fixtures.js';

const GRANTED = 'http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/granted';
const LOTL_URL = 'https://ec.europa.eu/lotl.xml';
const TSL_URL = 'https://de.example/tsl.xml';

/** `OtherTSLPointer` を持つ LOTL 本体（`detectKind` が lotl を返す）。 */
function lotlInner(): string {
  return (
    `<OtherTSLPointer><TSLLocation>${TSL_URL}</TSLLocation>` +
    `<SchemeTerritory>DE</SchemeTerritory></OtherTSLPointer>`
  );
}

/** granted な QTSP CA を 1 件持つ TSL 本体。 */
function tslInner(caDer: Uint8Array): string {
  return (
    `<TSPService><ServiceTypeIdentifier>http://uri.etsi.org/TrstSvc/Svctype/CA/QC</ServiceTypeIdentifier><ServiceStatus>${GRANTED}</ServiceStatus>` +
    `<X509Certificate>${base64.encode(caDer)}</X509Certificate></TSPService>`
  );
}

/** 本体要素を包んで enveloped XMLDSig 署名を施す。 */
function signBody(bodyInner: string, signer: CertFixture, kind: 'rsa' | 'ec'): string {
  return signEnvelopedXml({
    bodyOpen: '<TrustServiceStatusList>',
    bodyInner,
    bodyClose: '</TrustServiceStatusList>',
    privateKey: signer.privateKey,
    certDer: signer.der,
    kind,
  });
}

describe('loadTrustedList の署名者アンカリング', () => {
  test('アンカー未設定なら通るが signatureAnchored は false（ギャップを沈黙させない）', async () => {
    const signer = makeCertificate({ cn: 'Self-signed LOTL Signer', kind: 'rsa' });
    const xml = signBody(lotlInner(), signer, 'rsa');

    const result = await loadTrustedList(LOTL_URL, { fetcher: async () => xml });

    expect(result.signatureValid).toBe(true);
    expect(result.signatureAnchored).toBe(false);
  });

  test('空配列のアンカーも未設定と同じ扱い（signatureAnchored は false）', async () => {
    const signer = makeCertificate({ cn: 'Self-signed LOTL Signer', kind: 'rsa' });
    const xml = signBody(lotlInner(), signer, 'rsa');

    const result = await loadTrustedList(LOTL_URL, {
      fetcher: async () => xml,
      signingTrustAnchorsDer: [],
    });

    expect(result.signatureAnchored).toBe(false);
  });

  test('署名者証明書そのものをアンカーに設定すると signatureAnchored が true', async () => {
    const signer = makeCertificate({ cn: 'EU LOTL Signer', kind: 'rsa' });
    const xml = signBody(lotlInner(), signer, 'rsa');

    const result = await loadTrustedList(LOTL_URL, {
      fetcher: async () => xml,
      signingTrustAnchorsDer: [signer.der],
    });

    expect(result.signatureValid).toBe(true);
    expect(result.signatureAnchored).toBe(true);
    expect(result.countries).toEqual(['DE']);
  });

  test('アンカー CA が直接発行した署名者証明書も連結する', async () => {
    const anchor = makeCertificate({ cn: 'EU LOTL Root', kind: 'rsa', ca: true });
    const signer = makeCertificate({
      cn: 'EU LOTL Signer',
      kind: 'ec',
      issuer: { name: anchor.subjectName, privateKey: anchor.privateKey, kind: 'rsa' },
    });
    const xml = signBody(lotlInner(), signer, 'ec');

    const result = await loadTrustedList(LOTL_URL, {
      fetcher: async () => xml,
      signingTrustAnchorsDer: [anchor.der],
    });

    expect(result.signatureAnchored).toBe(true);
  });

  test('CA 発行（自己署名でない）署名者証明書をそのままピン留めできる', async () => {
    // 実在の EU LOTL 署名証明書は QTSP CA が発行したもので自己署名ではない。DER 完全一致を
    // 受理しないと、運用者は発行 CA 全体（＝要求より広い信頼）をピン留めするしかなくなる。
    const ca = makeCertificate({ cn: 'QTSP Issuing CA', kind: 'rsa', ca: true });
    const signer = makeCertificate({
      cn: 'EU LOTL Signer',
      kind: 'ec',
      issuer: { name: ca.subjectName, privateKey: ca.privateKey, kind: 'rsa' },
    });
    const xml = signBody(lotlInner(), signer, 'ec');

    const result = await loadTrustedList(LOTL_URL, {
      fetcher: async () => xml,
      signingTrustAnchorsDer: [signer.der],
    });

    expect(result.signatureAnchored).toBe(true);
  });

  test('同じ CA が発行した別証明書の署名は、ピン留めした 1 通と一致せず拒否する', async () => {
    const ca = makeCertificate({ cn: 'QTSP Issuing CA', kind: 'rsa', ca: true });
    const issuedBy = (cn: string) =>
      makeCertificate({
        cn,
        kind: 'ec',
        issuer: { name: ca.subjectName, privateKey: ca.privateKey, kind: 'rsa' },
      });
    const pinned = issuedBy('EU LOTL Signer');
    const xml = signBody(lotlInner(), issuedBy('Other Signer'), 'ec');

    await expect(
      loadTrustedList(LOTL_URL, {
        fetcher: async () => xml,
        signingTrustAnchorsDer: [pinned.der],
      }),
    ).rejects.toMatchObject({ code: '10302' });
  });

  test('ピン留めした署名者証明書が期限切れなら拒否する（有効期間は一致しても課す）', async () => {
    const dayMs = 86_400_000;
    const ca = makeCertificate({ cn: 'QTSP Issuing CA', kind: 'rsa', ca: true });
    const signer = makeCertificate({
      cn: 'Expired LOTL Signer',
      kind: 'ec',
      notBefore: new Date(Date.now() - 2 * dayMs),
      notAfter: new Date(Date.now() - dayMs),
      issuer: { name: ca.subjectName, privateKey: ca.privateKey, kind: 'rsa' },
    });
    const xml = signBody(lotlInner(), signer, 'ec');

    await expect(
      loadTrustedList(LOTL_URL, {
        fetcher: async () => xml,
        signingTrustAnchorsDer: [signer.der],
      }),
    ).rejects.toMatchObject({ code: '10302' });
  });

  test('アンカーへ連結しない自己署名 LOTL は XMLDSIG_VERIFICATION_FAILED(10302)', async () => {
    const rogue = makeCertificate({ cn: 'Rogue LOTL Signer', kind: 'rsa' });
    const anchor = makeCertificate({ cn: 'EU LOTL Root', kind: 'rsa', ca: true });
    const xml = signBody(lotlInner(), rogue, 'rsa');

    await expect(
      loadTrustedList(LOTL_URL, {
        fetcher: async () => xml,
        signingTrustAnchorsDer: [anchor.der],
      }),
    ).rejects.toMatchObject({ code: '10302' });
  });

  test('アンカーへ連結しない自己署名 TSL は TSL_SIG_INVALID(5002)', async () => {
    const ca = makeCertificate({ cn: 'DE QTSP CA', kind: 'rsa' });
    const rogue = makeCertificate({ cn: 'Rogue TSL Signer', kind: 'ec' });
    const anchor = makeCertificate({ cn: 'DE TSL Root', kind: 'rsa', ca: true });
    const xml = signBody(tslInner(ca.der), rogue, 'ec');

    await expect(
      loadTrustedList(TSL_URL, {
        fetcher: async () => xml,
        kind: 'tsl',
        signingTrustAnchorsDer: [anchor.der],
      }),
    ).rejects.toMatchObject({ code: '5002' });
  });

  test('連結する TSL 署名者なら serviceCertificates は従来どおり返る', async () => {
    const ca = makeCertificate({ cn: 'DE QTSP CA', kind: 'rsa' });
    const signer = makeCertificate({ cn: 'DE TSL Signer', kind: 'ec' });
    const xml = signBody(tslInner(ca.der), signer, 'ec');

    const result = await loadTrustedList(TSL_URL, {
      fetcher: async () => xml,
      kind: 'tsl',
      signingTrustAnchorsDer: [signer.der],
    });

    expect(result.signatureAnchored).toBe(true);
    expect(result.serviceCertificates.length).toBe(1);
  });

  test('チェーン検証の基準時刻に nowSeconds を使う', async () => {
    const dayMs = 86_400_000;
    const notBefore = new Date(Date.now() + dayMs);
    const notAfter = new Date(Date.now() + 2 * dayMs);
    const signer = makeCertificate({ cn: 'Future LOTL Signer', kind: 'rsa', notBefore, notAfter });
    const xml = signBody(lotlInner(), signer, 'rsa');
    const options = { fetcher: async () => xml, signingTrustAnchorsDer: [signer.der] };

    // 実時計では notBefore 前なので連結しない。
    await expect(loadTrustedList(LOTL_URL, options)).rejects.toMatchObject({ code: '10302' });

    const inWindow = Math.floor((notBefore.getTime() + dayMs / 2) / 1000);
    const result = await loadTrustedList(LOTL_URL, { ...options, nowSeconds: inWindow });
    expect(result.signatureAnchored).toBe(true);
  });
});

/**
 * 不正な型の `signingTrustAnchorsDer` を「未設定」に畳むと fail-open になる。
 *
 * 畳んだ場合、呼び出し側はピン留めしたつもりのまま `signatureAnchored: false` の Trusted List を
 * 受理してしまう。`loadTrustedList` の `kind` が「明示指定はあったが妥当でなかった」を未指定と
 * 区別するのと同じ規律で、ここでも拒否（10302 / 5002）に倒す。
 */
describe('loadTrustedList の signingTrustAnchorsDer 型検証（fail-closed）', () => {
  /** 型として渡せない値を明示指定するためのヘルパ（テスト専用）。 */
  function asAnchors(value: unknown): readonly Uint8Array[] {
    return value as readonly Uint8Array[];
  }

  test.each([
    ['素の Uint8Array（配列で包み忘れ）', (der: Uint8Array) => der],
    ['Set（配列ではない反復可能値）', (der: Uint8Array) => new Set([der])],
    ['JSON 往復で配列性を失ったオブジェクト', (der: Uint8Array) => ({ 0: der, length: 1 })],
    ['配列だが要素が DER でない', (der: Uint8Array) => [[...der]]],
  ])('%s は未設定に畳まず 10302 で拒否する', async (_label, build) => {
    const signer = makeCertificate({ cn: 'EU LOTL Signer', kind: 'rsa' });
    const xml = signBody(lotlInner(), signer, 'rsa');

    await expect(
      loadTrustedList(LOTL_URL, {
        fetcher: async () => xml,
        signingTrustAnchorsDer: asAnchors(build(signer.der)),
      }),
    ).rejects.toMatchObject({ code: '10302' });
  });

  test('正しいアンカーに 1 つでも不正要素が混ざれば拒否する', async () => {
    const signer = makeCertificate({ cn: 'EU LOTL Signer', kind: 'rsa' });
    const xml = signBody(lotlInner(), signer, 'rsa');

    await expect(
      loadTrustedList(LOTL_URL, {
        fetcher: async () => xml,
        signingTrustAnchorsDer: asAnchors([signer.der, 'not-a-der']),
      }),
    ).rejects.toMatchObject({ code: '10302' });
  });
});
