/**
 * 公開エントリ（`src/index.ts`）の trust 面の pin。
 *
 * `loadTrustedList({ cache })` の TSL 世代ロールバック拒否を、公開パッケージの利用者が
 * 内部モジュールに触れずに有効化できること（`createTrustedListCache` / `TrustedListCache`）。
 */

import { describe, expect, it } from 'bun:test';
import { base64 } from '@scure/base';
import {
  createTrustedListCache,
  loadTrustedList,
  TRUSTED_LIST_CACHE_MAX_TTL_SECONDS,
  VericertsError,
} from '../../index.js';
import { makeCertificate } from '../../internal/trust/etsi-tsl/__tests__/fixtures.js';
import { signEnvelopedXml } from '../../internal/trust/etsi-tsl/__tests__/xml/xml-fixtures.js';

const URL = 'https://tsl.example/DE.xml';
const NOW = 1_700_000_000;
const GRANTED = 'http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/granted';
const ca = makeCertificate({ cn: 'DE QTSP CA', kind: 'rsa' });
const signer = makeCertificate({ cn: 'DE TSL Signer', kind: 'ec' });

function signedTsl(sequence: number): string {
  const nextUpdate = new Date((NOW + 86_400) * 1000).toISOString();
  return signEnvelopedXml({
    bodyOpen: '<TrustServiceStatusList>',
    bodyInner:
      `<SchemeInformation><TSLSequenceNumber>${sequence}</TSLSequenceNumber>` +
      `<NextUpdate><dateTime>${nextUpdate}</dateTime></NextUpdate></SchemeInformation>` +
      `<TSPService><ServiceTypeIdentifier>http://uri.etsi.org/TrstSvc/Svctype/CA/QC</ServiceTypeIdentifier><ServiceStatus>${GRANTED}</ServiceStatus>` +
      `<X509Certificate>${base64.encode(ca.der)}</X509Certificate></TSPService>`,
    bodyClose: '</TrustServiceStatusList>',
    privateKey: signer.privateKey,
    certDer: signer.der,
    kind: 'ec',
  });
}

describe('公開エントリの trust 面', () => {
  it('createTrustedListCache を loadTrustedList に渡すと旧世代の再生が TSL_SIG_INVALID(5002) で拒否される', async () => {
    const cache = createTrustedListCache(() => NOW);
    const load = (xml: string) =>
      loadTrustedList(URL, { kind: 'tsl', cache, nowSeconds: NOW, fetcher: async () => xml });
    await load(signedTsl(7));

    const error = await load(signedTsl(6)).catch((e: unknown) => e);

    expect(error).toBeInstanceOf(VericertsError);
    expect((error as VericertsError).code).toBe('5002');
  });

  it('キャッシュ上限 TTL（30 日）が公開される', () => {
    expect(TRUSTED_LIST_CACHE_MAX_TTL_SECONDS).toBe(30 * 24 * 60 * 60);
  });
});
