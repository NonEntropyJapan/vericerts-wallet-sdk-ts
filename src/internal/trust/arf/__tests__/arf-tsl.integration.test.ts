import { describe, expect, test } from 'bun:test';
import { base64 } from '@scure/base';
import { makeCertificate } from '../../etsi-tsl/__tests__/fixtures.js';
import { extractQtspCertificates } from '../../etsi-tsl/tsl.js';
import { parseCertificate } from '../../etsi-tsl/x509.js';
import { loadArfTrustAnchor } from '../catalogue.js';
import { mapArfToTsl } from '../mapping.js';
import { makeKeyPair, signedCatalogue, spkiToBase64 } from './arf-fixtures.js';

const GRANTED = 'http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/granted';
const KEY = makeKeyPair(5);

/** granted な QTSP サービス証明書を並べた TSL XML を作る。 */
function tslXml(certs: Uint8Array[]): string {
  const services = certs
    .map(
      (der) =>
        `<TSPService><ServiceTypeIdentifier>http://uri.etsi.org/TrstSvc/Svctype/CA/QC</ServiceTypeIdentifier><ServiceStatus>${GRANTED}</ServiceStatus>` +
        `<X509Certificate>${base64.encode(der)}</X509Certificate></TSPService>`,
    )
    .join('');
  return `<TrustServiceStatusList>${services}</TrustServiceStatusList>`;
}

describe('ARF Trust Anchor ⇔ ETSI TSL 統合', () => {
  test('署名済み ARF Catalogue と TSL 抽出結果を SPKI で突き合わせる', async () => {
    // ETSI TSL 側: granted な QTSP CA を 2 件抽出する。
    const qtspA = makeCertificate({ cn: 'QTSP CA A', kind: 'rsa' });
    const qtspB = makeCertificate({ cn: 'QTSP CA B', kind: 'ec' });
    const tslCerts = extractQtspCertificates(tslXml([qtspA.der, qtspB.der]));
    expect(tslCerts.length).toBe(2);

    // ARF 側: A は TSL と同一鍵、C は ARF のみ。
    const arfOnlyCert = makeCertificate({ cn: 'ARF Only Issuer', kind: 'ec' });
    const catalogue = signedCatalogue(
      {
        version: '2026-07',
        entries: [
          {
            id: 'did:web:qtsp-a.example.eu',
            role: 'issuer',
            spki: spkiToBase64(parseCertificate(qtspA.der).spki),
          },
          {
            id: 'did:web:arf-only.example.eu',
            role: 'issuer',
            spki: spkiToBase64(parseCertificate(arfOnlyCert.der).spki),
          },
        ],
      },
      KEY,
    );

    const anchors = await loadArfTrustAnchor('https://arf.example/anchor.json', {
      fetcher: async () => catalogue,
      trustAnchorPublicKey: KEY.publicKey,
    });

    const mapping = mapArfToTsl(anchors.entries, tslCerts);

    // A は両層に載る。C は ARF のみ。B は TSL のみ。
    expect(mapping.matched.map((m) => m.entry.id)).toEqual(['did:web:qtsp-a.example.eu']);
    expect(mapping.arfOnly.map((e) => e.id)).toEqual(['did:web:arf-only.example.eu']);
    expect(mapping.tslOnly.length).toBe(1);
    expect(mapping.tslOnly[0]).toEqual(qtspB.der);
  });
});
