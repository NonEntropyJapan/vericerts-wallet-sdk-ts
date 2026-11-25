/**
 * TSL / LOTL XMLDSig の署名者 RSA 鍵長検査。
 *
 * 署名自体は正しくても、署名者証明書の RSA 鍵が 2048bit 未満なら `verifySignature` が拒否し、
 * `verifyXmlDsig` は `valid: false`、`loadTrustedList` は既存コード（LOTL: 10302 / TSL: 5002）で
 * 失敗する。新しいエラーコードは無い。2048bit の署名者は従来どおり通ることを併置する。
 */

import { describe, expect, test } from 'bun:test';
import { generateKeyPairSync } from 'node:crypto';
import { base64 } from '@scure/base';
import { loadTrustedList } from '../../etsi-tsl.js';
import { verifyXmlDsig } from '../../xml/xmldsig.js';
import { type CertFixture, makeCertificate } from '../fixtures.js';
import { signEnvelopedXml } from './xml-fixtures.js';

const GRANTED = 'http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/granted';
const LOTL_URL = 'https://ec.europa.eu/lotl.xml';
const TSL_URL = 'https://de.example/tsl.xml';

const LOTL_INNER =
  `<OtherTSLPointer><TSLLocation>${TSL_URL}</TSLLocation>` +
  `<SchemeTerritory>DE</SchemeTerritory></OtherTSLPointer>`;

function tslInner(caDer: Uint8Array): string {
  return (
    `<TSPService><ServiceTypeIdentifier>http://uri.etsi.org/TrstSvc/Svctype/CA/QC</ServiceTypeIdentifier><ServiceStatus>${GRANTED}</ServiceStatus>` +
    `<X509Certificate>${base64.encode(caDer)}</X509Certificate></TSPService>`
  );
}

/** 指定ビット長の RSA 鍵を署名者とする自己署名証明書。 */
function rsaSigner(modulusLength: number): CertFixture {
  const { privateKey } = generateKeyPairSync('rsa', { modulusLength });
  return makeCertificate({ cn: `Signer ${modulusLength}`, kind: 'rsa', subjectKey: privateKey });
}

function sign(bodyInner: string, signer: CertFixture): string {
  return signEnvelopedXml({
    bodyOpen: '<TrustServiceStatusList>',
    bodyInner,
    bodyClose: '</TrustServiceStatusList>',
    privateKey: signer.privateKey,
    certDer: signer.der,
    kind: 'rsa',
  });
}

describe('verifyXmlDsig: 署名者 RSA 鍵長', () => {
  test('2048bit の署名者は受理する（対照）', async () => {
    const result = await verifyXmlDsig(sign('<SchemeName>EU</SchemeName>', rsaSigner(2048)));
    expect(result.valid).toBe(true);
  });

  test('1024bit の署名者は署名が正しくても valid:false', async () => {
    const result = await verifyXmlDsig(sign('<SchemeName>EU</SchemeName>', rsaSigner(1024)));
    expect(result.valid).toBe(false);
  });
});

describe('loadTrustedList: 署名者 RSA 鍵長', () => {
  test('2048bit の署名者の LOTL は受理する（対照）', async () => {
    const xml = sign(LOTL_INNER, rsaSigner(2048));
    const result = await loadTrustedList(LOTL_URL, { fetcher: async () => xml });
    expect(result.signatureValid).toBe(true);
  });

  test('1024bit の署名者の LOTL は XMLDSIG_VERIFICATION_FAILED(10302)', async () => {
    const xml = sign(LOTL_INNER, rsaSigner(1024));
    await expect(loadTrustedList(LOTL_URL, { fetcher: async () => xml })).rejects.toMatchObject({
      code: '10302',
    });
  });

  test('2048bit の署名者の TSL は受理する（対照）', async () => {
    const ca = makeCertificate({ cn: 'DE QTSP CA', kind: 'rsa' });
    const xml = sign(tslInner(ca.der), rsaSigner(2048));
    const result = await loadTrustedList(TSL_URL, { fetcher: async () => xml, kind: 'tsl' });
    expect(result.signatureValid).toBe(true);
  });

  test('1024bit の署名者の TSL は TSL_SIG_INVALID(5002)', async () => {
    const ca = makeCertificate({ cn: 'DE QTSP CA', kind: 'rsa' });
    const xml = sign(tslInner(ca.der), rsaSigner(1024));
    await expect(
      loadTrustedList(TSL_URL, { fetcher: async () => xml, kind: 'tsl' }),
    ).rejects.toMatchObject({ code: '5002' });
  });
});
