/**
 * TSL / LOTL 構造抽出の入れ子拒否と総量上限。
 *
 * 以前は `TSPService` を子孫から全件拾い、外側のサービスごとに配下の `X509Certificate` を重ねて
 * 拾っていたため、深さ d の入れ子が証明書 N 件を d×N 件の Trust Anchor に増幅した（60 段・8 MB で 115 万件）。
 * 実時間ではなく、拒否の種別（`TSL_SIG_INVALID` と `context.reason`）と上限ちょうどの境界で pin する。
 * 少数の巨大要素 / 多数の極小要素 / 入れ子 / 深い非入れ子の各形状を確認する。
 */

import { describe, expect, test } from 'bun:test';
import { base64 } from '@scure/base';
import { ErrorCodes, VericertsError } from '../../../../errors.js';
import { loadTrustedList } from '../../etsi-tsl.js';
import {
  extractQtspCertificates,
  extractQualifiedTspEntries,
  extractTslPointers,
  grantedTrustAnchors,
} from '../../tsl.js';
import {
  MAX_LOTL_POINTERS,
  MAX_TSL_CERTIFICATES,
  MAX_TSL_ELEMENT_DEPTH,
  MAX_TSL_PROVIDERS,
  MAX_TSL_SERVICES,
  MAX_TSL_TRUST_ANCHORS,
} from '../../tsl-extract/limits.js';
import { makeCertificate } from '../fixtures.js';
import { signEnvelopedXml } from '../xml/xml-fixtures.js';

const GRANTED = 'http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/granted';
const WITHDRAWN = 'http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/withdrawn';
const CA_QC = 'http://uri.etsi.org/TrstSvc/Svctype/CA/QC';

/** 証明書として解釈しない小さな base64（抽出は DER を検証しない）。 */
const TINY_CERT = base64.encode(new Uint8Array([0x30, 0x03, 0x02, 0x01, 0x01]));
const certEl = (b64 = TINY_CERT): string => `<X509Certificate>${b64}</X509Certificate>`;

const serviceInfo = (status = GRANTED): string =>
  `<ServiceStatus>${status}</ServiceStatus><ServiceTypeIdentifier>${CA_QC}</ServiceTypeIdentifier>`;

const service = (certs: string, status = GRANTED): string =>
  `<TSPService>${serviceInfo(status)}${certs}</TSPService>`;

const tsl = (providers: string): string =>
  `<TrustServiceStatusList><TrustServiceProviderList>${providers}</TrustServiceProviderList></TrustServiceStatusList>`;

const provider = (services: string, name = 'TSP'): string =>
  `<TrustServiceProvider><TSPInformation><TSPName><Name>${name}</Name></TSPName></TSPInformation><TSPServices>${services}</TSPServices></TrustServiceProvider>`;

function expectRejected(fn: () => unknown, reason: string): void {
  let caught: unknown;
  try {
    fn();
  } catch (error) {
    caught = error;
  }
  expect(caught).toBeInstanceOf(VericertsError);
  expect((caught as VericertsError).code).toBe(ErrorCodes.TSL_SIG_INVALID);
  expect((caught as VericertsError).context).toMatchObject({ reason });
}

describe('入れ子の TSPService は拒否する（Trust Anchor の増幅）', () => {
  test.each([
    ['少数段（2 段）× 1 件', 2, 1],
    ['55 段 × 少数の証明書', 55, 3],
    ['55 段 × 多数の極小証明書', 55, 2_000],
  ])('%s', (_shape, depth, certs) => {
    const xml = tsl(
      provider(
        `${'<TSPService>'.repeat(depth)}${serviceInfo()}${certEl().repeat(certs)}${'</TSPService>'.repeat(depth)}`,
      ),
    );
    expectRejected(() => extractQtspCertificates(xml), 'tsl_nested_element');
    expectRejected(() => extractQualifiedTspEntries(xml, 'XX'), 'tsl_nested_element');
  });

  test('入れ子でない兄弟のサービスは件数どおり（増幅しない）', () => {
    const xml = tsl(provider(service(certEl().repeat(3)).repeat(50)));
    const certs = extractQtspCertificates(xml);
    expect(certs.length).toBe(150);
    expect(grantedTrustAnchors(certs).length).toBe(150);
  });

  test('少数の巨大な証明書要素は件数 1 のまま（サイズでは増幅しない）', () => {
    const huge = base64.encode(new Uint8Array(1_500_000));
    const xml = tsl(provider(service(certEl(huge)).repeat(2)));
    const certs = extractQtspCertificates(xml);
    expect(certs.length).toBe(2);
    expect(certs[0]?.certDer.length).toBe(1_500_000);
  });

  test('入れ子の TrustServiceProvider / OtherTSLPointer も拒否する', () => {
    const nestedProvider = tsl(
      `<TrustServiceProvider>${provider(service(certEl()))}</TrustServiceProvider>`,
    );
    expectRejected(() => extractQualifiedTspEntries(nestedProvider, 'XX'), 'tsl_nested_element');
    const nestedPointer = `<TrustServiceStatusList>${'<OtherTSLPointer>'.repeat(40)}<TSLLocation>https://x/tsl.xml</TSLLocation>${'</OtherTSLPointer>'.repeat(40)}</TrustServiceStatusList>`;
    expectRejected(() => extractTslPointers(nestedPointer), 'tsl_nested_element');
  });

  test('非入れ子でも期待される深さを超えた TSPService は拒否する', () => {
    const wrappers = MAX_TSL_ELEMENT_DEPTH; // サービスの深さが上限を超える
    const xml = `<TrustServiceStatusList>${'<W>'.repeat(wrappers)}${service(certEl())}${'</W>'.repeat(wrappers)}</TrustServiceStatusList>`;
    expectRejected(() => extractQtspCertificates(xml), 'tsl_element_too_deep');
  });

  test('標準の深さ（TrustServiceProvider/TSPServices/TSPService）は通る', () => {
    expect(extractQtspCertificates(tsl(provider(service(certEl())))).length).toBe(1);
    expect(extractQualifiedTspEntries(tsl(provider(service(certEl()))), 'XX').length).toBe(1);
  });
});

describe('総量の上限（上限ちょうどは通り、1 つ超えると拒否）', () => {
  test('Trust Anchor 数: 多数の極小サービス', () => {
    const atLimit = tsl(provider(service(certEl().repeat(MAX_TSL_TRUST_ANCHORS))));
    expect(grantedTrustAnchors(extractQtspCertificates(atLimit)).length).toBe(
      MAX_TSL_TRUST_ANCHORS,
    );
    const over = tsl(provider(service(certEl().repeat(MAX_TSL_TRUST_ANCHORS + 1))));
    expectRejected(() => extractQtspCertificates(over), 'tsl_too_many_trust_anchors');
  });

  test('証明書総数: granted でない証明書も数える', () => {
    const over = tsl(provider(service(certEl().repeat(MAX_TSL_CERTIFICATES + 1), WITHDRAWN)));
    expectRejected(() => extractQtspCertificates(over), 'tsl_too_many_certificates');
    const atLimit = tsl(provider(service(certEl().repeat(MAX_TSL_CERTIFICATES), WITHDRAWN)));
    expect(extractQtspCertificates(atLimit).length).toBe(MAX_TSL_CERTIFICATES);
  });

  test('証明書総数: サービスをまたいで累計される', () => {
    const per = MAX_TSL_CERTIFICATES / 2;
    const three = tsl(
      provider(service(certEl().repeat(per), WITHDRAWN).repeat(2) + service(certEl(), WITHDRAWN)),
    );
    expectRejected(() => extractQtspCertificates(three), 'tsl_too_many_certificates');
  });

  test('サービス総数', () => {
    const over = tsl(provider(service('').repeat(MAX_TSL_SERVICES + 1)));
    expectRejected(() => extractQtspCertificates(over), 'tsl_too_many_services');
    expectRejected(() => extractQualifiedTspEntries(over, 'XX'), 'tsl_too_many_services');
  });

  test('サービス総数は provider をまたいで累計される', () => {
    const half = Math.floor(MAX_TSL_SERVICES / 2) + 1;
    const xml = tsl(
      provider(service('').repeat(half), 'A') + provider(service('').repeat(half), 'B'),
    );
    expectRejected(() => extractQualifiedTspEntries(xml, 'XX'), 'tsl_too_many_services');
  });

  test('TrustServiceProvider 総数', () => {
    const over = tsl(provider('').repeat(MAX_TSL_PROVIDERS + 1));
    expectRejected(() => extractQualifiedTspEntries(over, 'XX'), 'tsl_too_many_providers');
  });

  test('LOTL の OtherTSLPointer 総数', () => {
    const ptr = '<OtherTSLPointer><TSLLocation>https://x/tsl.xml</TSLLocation></OtherTSLPointer>';
    const wrap = (n: number): string =>
      `<TrustServiceStatusList>${ptr.repeat(n)}</TrustServiceStatusList>`;
    expect(extractTslPointers(wrap(MAX_LOTL_POINTERS)).length).toBe(MAX_LOTL_POINTERS);
    expectRejected(() => extractTslPointers(wrap(MAX_LOTL_POINTERS + 1)), 'tsl_too_many_pointers');
  });
});

describe('署名済みの入れ子 TSL は loadTrustedList で拒否される（5002）', () => {
  test('署名が正しくても Trust Anchor を増幅する構造は受理しない', async () => {
    const signer = makeCertificate({ cn: 'tsl-signer', kind: 'ec' });
    const depth = 60;
    const body =
      '<TSPService>'.repeat(depth) +
      serviceInfo() +
      certEl().repeat(200) +
      '</TSPService>'.repeat(depth);
    const xml = signEnvelopedXml({
      bodyOpen: '<TrustServiceStatusList xmlns:ds="http://www.w3.org/2000/09/xmldsig#">',
      bodyInner: body,
      bodyClose: '</TrustServiceStatusList>',
      privateKey: signer.privateKey,
      certDer: signer.der,
      kind: 'ec',
    });
    let caught: unknown;
    try {
      await loadTrustedList('https://example.eu/tsl.xml', {
        fetcher: async () => xml,
        kind: 'tsl',
        signingTrustAnchorsDer: [signer.der],
      });
    } catch (error) {
      caught = error;
    }
    expect(caught).toBeInstanceOf(VericertsError);
    expect((caught as VericertsError).code).toBe(ErrorCodes.TSL_SIG_INVALID);
  });
});
