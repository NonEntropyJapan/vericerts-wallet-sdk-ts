import { describe, expect, test } from 'bun:test';
import { base64 } from '@scure/base';
import {
  extractNextUpdate,
  extractQtspCertificates,
  extractQualifiedTspEntries,
  extractTslPointers,
  grantedTrustAnchors,
} from '../../tsl.js';
import { makeCertificate } from '../fixtures.js';

const GRANTED = 'http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/granted';
const WITHDRAWN = 'http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/withdrawn';

function lotlXml(pointers: { location: string; territory: string }[]): string {
  const ptr = pointers
    .map(
      (p) =>
        `<OtherTSLPointer><TSLLocation>${p.location}</TSLLocation>` +
        `<AdditionalInformation><SchemeTerritory>${p.territory}</SchemeTerritory></AdditionalInformation>` +
        `</OtherTSLPointer>`,
    )
    .join('');
  return `<TrustServiceStatusList><SchemeInformation><PointersToOtherTSL>${ptr}</PointersToOtherTSL></SchemeInformation></TrustServiceStatusList>`;
}

function tslXml(services: { status: string; certDer: Uint8Array }[]): string {
  const svc = services
    .map(
      (s) =>
        `<TSPService><ServiceInformation><ServiceTypeIdentifier>http://uri.etsi.org/TrstSvc/Svctype/CA/QC</ServiceTypeIdentifier><ServiceStatus>${s.status}</ServiceStatus>` +
        `<ServiceDigitalIdentity><DigitalId><X509Certificate>${base64.encode(s.certDer)}</X509Certificate></DigitalId></ServiceDigitalIdentity>` +
        `</ServiceInformation></TSPService>`,
    )
    .join('');
  return `<TrustServiceStatusList><TrustServiceProviderList><TrustServiceProvider>${svc}</TrustServiceProvider></TrustServiceProviderList></TrustServiceStatusList>`;
}

describe('extractTslPointers', () => {
  test('LOTL から国別 TSL ポインタを抽出する', () => {
    const xml = lotlXml([
      { location: 'https://de.example/tsl.xml', territory: 'DE' },
      { location: 'https://fr.example/tsl.xml', territory: 'FR' },
    ]);
    const pointers = extractTslPointers(xml);
    expect(pointers.length).toBe(2);
    expect(pointers[0]?.location).toBe('https://de.example/tsl.xml');
    expect(pointers[0]?.territory).toBe('DE');
    expect(pointers[1]?.territory).toBe('FR');
  });

  test('TSLLocation の無いポインタは無視する', () => {
    const xml =
      '<TrustServiceStatusList><OtherTSLPointer><SchemeTerritory>DE</SchemeTerritory></OtherTSLPointer></TrustServiceStatusList>';
    expect(extractTslPointers(xml).length).toBe(0);
  });
});

describe('extractQtspCertificates / grantedTrustAnchors', () => {
  test('granted サービスの証明書のみ Trust Anchor になる', () => {
    const grantedCert = makeCertificate({ cn: 'Granted CA', kind: 'rsa' });
    const withdrawnCert = makeCertificate({ cn: 'Withdrawn CA', kind: 'rsa' });
    const xml = tslXml([
      { status: GRANTED, certDer: grantedCert.der },
      { status: WITHDRAWN, certDer: withdrawnCert.der },
    ]);
    const certs = extractQtspCertificates(xml);
    expect(certs.length).toBe(2);
    expect(certs.filter((c) => c.granted).length).toBe(1);
    const anchors = grantedTrustAnchors(certs);
    expect(anchors.length).toBe(1);
  });

  test('ServiceHistory の旧証明書には現行ステータスを適用せず Trust Anchor にしない', () => {
    const currentCert = makeCertificate({ cn: 'Current CA', kind: 'rsa' });
    const oldCert = makeCertificate({ cn: 'Old CA', kind: 'rsa' });
    const digitalId = (der: Uint8Array): string =>
      `<ServiceDigitalIdentity><DigitalId><X509Certificate>${base64.encode(der)}</X509Certificate></DigitalId></ServiceDigitalIdentity>`;
    const xml =
      '<TrustServiceStatusList><TrustServiceProviderList><TrustServiceProvider><TSPName><Name>TSP</Name></TSPName><TSPService>' +
      `<ServiceInformation><ServiceTypeIdentifier>http://uri.etsi.org/TrstSvc/Svctype/CA/QC</ServiceTypeIdentifier><ServiceStatus>${GRANTED}</ServiceStatus>${digitalId(currentCert.der)}</ServiceInformation>` +
      '<ServiceHistory><ServiceHistoryInstance>' +
      `<ServiceStatus>${WITHDRAWN}</ServiceStatus>${digitalId(oldCert.der)}` +
      '</ServiceHistoryInstance></ServiceHistory>' +
      '</TSPService></TrustServiceProvider></TrustServiceProviderList></TrustServiceStatusList>';
    const certs = extractQtspCertificates(xml);
    expect(certs.length).toBe(1);
    expect(grantedTrustAnchors(certs)).toEqual([currentCert.der]);
    expect(extractQualifiedTspEntries(xml, 'DE')[0]?.certificates.length).toBe(1);
  });

  test('不正な base64 証明書は黙って除外する', () => {
    const xml =
      '<TrustServiceStatusList><TSPService><ServiceInformation><ServiceTypeIdentifier>http://uri.etsi.org/TrstSvc/Svctype/CA/QC</ServiceTypeIdentifier><ServiceStatus>' +
      GRANTED +
      '</ServiceStatus><X509Certificate>not-base64!!!</X509Certificate></ServiceInformation></TSPService></TrustServiceStatusList>';
    // 例外を投げず、デコード不能証明書は除外される。
    expect(extractQtspCertificates(xml).length).toBe(0);
  });
});

/** 1 プロバイダ分の TrustServiceProvider XML 断片を組み立てる。 */
function providerXml(opts: {
  tspName?: string;
  services: { typeId?: string; status: string; certDer: Uint8Array }[];
}): string {
  const svc = opts.services
    .map(
      (s) =>
        `<TSPService><ServiceInformation>` +
        (s.typeId !== undefined
          ? `<ServiceTypeIdentifier>${s.typeId}</ServiceTypeIdentifier>`
          : '') +
        `<ServiceStatus>${s.status}</ServiceStatus>` +
        `<ServiceDigitalIdentity><DigitalId><X509Certificate>${base64.encode(s.certDer)}</X509Certificate></DigitalId></ServiceDigitalIdentity>` +
        `</ServiceInformation></TSPService>`,
    )
    .join('');
  const name =
    opts.tspName !== undefined
      ? `<TSPInformation><TSPName><Name xml:lang="en">${opts.tspName}</Name></TSPName></TSPInformation>`
      : '';
  return `<TrustServiceProvider>${name}<TSPServices>${svc}</TSPServices></TrustServiceProvider>`;
}

describe('extractQualifiedTspEntries', () => {
  test('TrustServiceProvider ごとに tspId・services・certificates(PEM)・status を集約する', () => {
    const cert = makeCertificate({ cn: 'QTSP CA', kind: 'rsa' });
    const xml = `<TrustServiceStatusList><TrustServiceProviderList>${providerXml({
      tspName: 'Example QTSP',
      services: [
        { typeId: 'http://uri.etsi.org/TrstSvc/Svctype/CA/QC', status: GRANTED, certDer: cert.der },
      ],
    })}</TrustServiceProviderList></TrustServiceStatusList>`;

    const entries = extractQualifiedTspEntries(xml, 'DE');
    expect(entries.length).toBe(1);
    expect(entries[0]?.tspId).toBe('Example QTSP');
    expect(entries[0]?.country).toBe('DE');
    expect(entries[0]?.services).toEqual(['http://uri.etsi.org/TrstSvc/Svctype/CA/QC']);
    expect(entries[0]?.certificates.length).toBe(1);
    expect(entries[0]?.certificates[0]).toContain('-----BEGIN CERTIFICATE-----');
    expect(entries[0]?.status).toBe('granted');
  });

  test('配下のいずれかのサービスが非 granted なら status は withdrawn になる', () => {
    const grantedCert = makeCertificate({ cn: 'Granted', kind: 'rsa' });
    const withdrawnCert = makeCertificate({ cn: 'Withdrawn', kind: 'rsa' });
    const xml = `<TrustServiceStatusList><TrustServiceProviderList>${providerXml({
      tspName: 'Mixed QTSP',
      services: [
        { status: GRANTED, certDer: grantedCert.der },
        { status: WITHDRAWN, certDer: withdrawnCert.der },
      ],
    })}</TrustServiceProviderList></TrustServiceStatusList>`;

    const entries = extractQualifiedTspEntries(xml, 'FR');
    expect(entries[0]?.status).toBe('withdrawn');
    expect(entries[0]?.certificates.length).toBe(2);
  });

  test('証明書が 1 件も無い TSP は withdrawn 扱いになる（fail-closed）', () => {
    const xml = `<TrustServiceStatusList><TrustServiceProviderList>${providerXml({
      tspName: 'No Cert QTSP',
      services: [],
    })}</TrustServiceProviderList></TrustServiceStatusList>`;

    const entries = extractQualifiedTspEntries(xml, 'FR');
    expect(entries[0]?.status).toBe('withdrawn');
    expect(entries[0]?.certificates.length).toBe(0);
  });

  test('TSPName が無い TSP は除外する', () => {
    const cert = makeCertificate({ cn: 'No Name', kind: 'rsa' });
    const xml = `<TrustServiceStatusList><TrustServiceProviderList>${providerXml({
      services: [{ status: GRANTED, certDer: cert.der }],
    })}</TrustServiceProviderList></TrustServiceStatusList>`;

    expect(extractQualifiedTspEntries(xml, 'FR').length).toBe(0);
  });
});

describe('extractNextUpdate', () => {
  test('SchemeInformation/NextUpdate/dateTime を抽出する', () => {
    const xml =
      '<TrustServiceStatusList><SchemeInformation><NextUpdate>' +
      '<dateTime>2027-01-01T00:00:00Z</dateTime>' +
      '</NextUpdate></SchemeInformation></TrustServiceStatusList>';
    expect(extractNextUpdate(xml)).toBe('2027-01-01T00:00:00Z');
  });

  test('NextUpdate が無ければ undefined を返す', () => {
    const xml =
      '<TrustServiceStatusList><SchemeInformation></SchemeInformation></TrustServiceStatusList>';
    expect(extractNextUpdate(xml)).toBeUndefined();
  });
});
