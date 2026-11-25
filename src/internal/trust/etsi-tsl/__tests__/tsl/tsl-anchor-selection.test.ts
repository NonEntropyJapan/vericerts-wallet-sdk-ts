/**
 * Trust Anchor の選別（ServiceTypeIdentifier・国内レベル承認）と NextUpdate 期限の回帰テスト。
 */

import { describe, expect, test } from 'bun:test';
import { base64 } from '@scure/base';
import { ErrorCodes } from '../../../../errors.js';
import { loadTrustedList } from '../../etsi-tsl.js';
import { extractQtspCertificates, grantedTrustAnchors } from '../../tsl.js';
import { makeCertificate } from '../fixtures.js';
import { signEnvelopedXml } from '../xml/xml-fixtures.js';

const ST = 'http://uri.etsi.org/TrstSvc/Svctype';
const SS = 'http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus';
const ca = makeCertificate({ cn: 'Some CA', kind: 'rsa' });

function tslWith(typeId: string | undefined, status: string): string {
  const type =
    typeId === undefined ? '' : `<ServiceTypeIdentifier>${typeId}</ServiceTypeIdentifier>`;
  return (
    '<TrustServiceStatusList><TSPService><ServiceInformation>' +
    `${type}<ServiceStatus>${status}</ServiceStatus><ServiceDigitalIdentity><DigitalId>` +
    `<X509Certificate>${base64.encode(ca.der)}</X509Certificate></DigitalId></ServiceDigitalIdentity>` +
    '</ServiceInformation></TSPService></TrustServiceStatusList>'
  );
}

const anchorCount = (
  xml: string,
  options?: Parameters<typeof extractQtspCertificates>[1],
): number => grantedTrustAnchors(extractQtspCertificates(xml, options)).length;

describe('ServiceTypeIdentifier による Trust Anchor 選別', () => {
  test.each([
    ['CA/QC', `${ST}/CA/QC`, `${SS}/granted`, 1],
    ['NationalRootCA-QC', `${ST}/NationalRootCA-QC`, `${SS}/granted`, 1],
    ['TSA', `${ST}/TSA`, `${SS}/granted`, 0],
    ['Certstatus/OCSP', `${ST}/Certstatus/OCSP`, `${SS}/granted`, 0],
    ['CA/PKC（非 Qualified CA）', `${ST}/CA/PKC`, `${SS}/granted`, 0],
    ['EDS', `${ST}/EDS`, `${SS}/granted`, 0],
    ['CA/QC + recognisedatnationallevel', `${ST}/CA/QC`, `${SS}/recognisedatnationallevel`, 0],
    ['CA/PKC + recognisedatnationallevel', `${ST}/CA/PKC`, `${SS}/recognisedatnationallevel`, 0],
    ['CA/QC + withdrawn', `${ST}/CA/QC`, `${SS}/withdrawn`, 0],
  ])('%s は anchor %d 件', (_label, typeId, status, expected) => {
    expect(anchorCount(tslWith(typeId, status))).toBe(expected);
  });

  test('ServiceTypeIdentifier が無いサービスは anchor にしない（fail-closed）', () => {
    expect(anchorCount(tslWith(undefined, `${SS}/granted`))).toBe(0);
  });

  test('証明書自体は granted: false として返る（呼び出し側が区別できる）', () => {
    const certs = extractQtspCertificates(tslWith(`${ST}/TSA`, `${SS}/granted`));
    expect(certs.length).toBe(1);
    expect(certs[0]?.granted).toBe(false);
  });

  test('includeRecognisedAtNationalLevel を明示すると国内レベル承認の CA/QC を採る', () => {
    const xml = tslWith(`${ST}/CA/QC`, `${SS}/recognisedatnationallevel`);
    expect(anchorCount(xml, { includeRecognisedAtNationalLevel: true })).toBe(1);
    // 種別の許可リストは国内レベルを許しても外れない。
    const tsa = tslWith(`${ST}/TSA`, `${SS}/recognisedatnationallevel`);
    expect(anchorCount(tsa, { includeRecognisedAtNationalLevel: true })).toBe(0);
  });

  test('serviceTypes で許可リストを差し替えられる', () => {
    const xml = tslWith(`${ST}/CA/PKC`, `${SS}/granted`);
    expect(anchorCount(xml, { serviceTypes: [`${ST}/CA/PKC`] })).toBe(1);
    expect(anchorCount(tslWith(`${ST}/CA/QC`, `${SS}/granted`), { serviceTypes: [] })).toBe(0);
  });

  test('継承（プロトタイプ汚染）した serviceTypes / includeRecognisedAtNationalLevel は読まない', () => {
    const polluted = Object.create({
      serviceTypes: [`${ST}/TSA`],
      includeRecognisedAtNationalLevel: true,
    });
    expect(anchorCount(tslWith(`${ST}/TSA`, `${SS}/granted`), polluted)).toBe(0);
    expect(anchorCount(tslWith(`${ST}/CA/QC`, `${SS}/recognisedatnationallevel`), polluted)).toBe(
      0,
    );
  });
});

describe('取得した TSL / LOTL の NextUpdate を評価する', () => {
  const signer = makeCertificate({ cn: 'TSL Signer', kind: 'ec' });
  const NOW = 1_800_000_000;
  const iso = (seconds: number): string => new Date(seconds * 1000).toISOString();

  function signed(inner: string, omitNextUpdate = false): string {
    return signEnvelopedXml({
      bodyOpen: '<TrustServiceStatusList>',
      bodyInner: inner,
      bodyClose: '</TrustServiceStatusList>',
      privateKey: signer.privateKey,
      certDer: signer.der,
      kind: 'ec',
      omitNextUpdate,
    });
  }
  const nextUpdate = (text: string): string =>
    `<SchemeInformation><NextUpdate><dateTime>${text}</dateTime></NextUpdate></SchemeInformation>`;
  const svc =
    `<TSPService><ServiceTypeIdentifier>${ST}/CA/QC</ServiceTypeIdentifier>` +
    `<ServiceStatus>${SS}/granted</ServiceStatus><X509Certificate>${base64.encode(ca.der)}</X509Certificate></TSPService>`;
  const ptr =
    '<OtherTSLPointer><TSLLocation>https://de.example/tsl.xml</TSLLocation></OtherTSLPointer>';

  const load = (xml: string, kind: 'tsl' | 'lotl') =>
    loadTrustedList('https://x.example/list.xml', {
      fetcher: async () => xml,
      kind,
      nowSeconds: NOW,
    });

  test('NextUpdate が未来の TSL は受理する', async () => {
    const result = await load(signed(nextUpdate(iso(NOW + 1)) + svc), 'tsl');
    expect(result.signatureValid).toBe(true);
    expect(result.serviceCertificates.length).toBe(1);
  });

  test.each([
    ['過去', iso(NOW - 3600)],
    ['境界（ちょうど今）', iso(NOW)],
    ['パース不能', 'not-a-date'],
    ['空', ''],
  ])('NextUpdate が %s の TSL は署名が有効でも拒否する', async (_label, text) => {
    await expect(load(signed(nextUpdate(text) + svc), 'tsl')).rejects.toMatchObject({
      code: ErrorCodes.TSL_SIG_INVALID,
    });
  });

  test('NextUpdate が欠落した TSL は拒否する', async () => {
    await expect(load(signed(svc, true), 'tsl')).rejects.toMatchObject({
      code: ErrorCodes.TSL_SIG_INVALID,
    });
  });

  test('期限切れの LOTL も拒否する', async () => {
    await expect(load(signed(nextUpdate(iso(NOW - 1)) + ptr), 'lotl')).rejects.toMatchObject({
      code: ErrorCodes.XMLDSIG_VERIFICATION_FAILED,
    });
    expect((await load(signed(nextUpdate(iso(NOW + 60)) + ptr), 'lotl')).countries).toBeDefined();
  });
});
