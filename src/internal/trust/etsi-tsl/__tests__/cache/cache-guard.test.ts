/**
 * 不正な形状の `options.cache` に対する防御的検証の回帰テスト。
 *
 * `failOpenWindow` には `validFailOpenWindow`（`fail-open.ts`）相当の形状検証があるが、
 * `options.cache` には無かった。検証せずに使うと:
 * - 成功パス: `storeTrustedListCache` の `cache.set` 呼び出しが生の `TypeError` を投げ、
 *   TSL の取得に成功した正常系そのものをクラッシュさせる。
 * - 失敗パス: `resolveWithFailOpen` 経由の `readTrustedListCache` の `cache.get` 呼び出しが
 *   生の `TypeError` を投げ、本来の `TSL_FETCH_FAILED`(5001) / `LOTL_FETCH_FAILED`(10301) に
 *   正規化されないまま伝播する。
 *
 * `cache.ts` の `isValidTrustedListCache` による形状検証（`window-guard.test.ts` と同じ規律）で、
 * いずれの経路も「キャッシュを使わない」fail-closed にフォールバックすることを確認する。
 *
 * 不正な形状のケースしか無いと、`isValidTrustedListCache` が誤って常に `false` を返す実装に
 * 退行しても（＝正当なキャッシュまで一律に「キャッシュ無し」として扱っても）このファイル単体では
 * 検知できない。`createTrustedListCache()` による正当な形状のポジティブコントロールを別途置く
 */

import { describe, expect, it } from 'bun:test';
import { base64 } from '@scure/base';
import { VericertsError } from '../../../../errors.js';
import { createTrustedListCache } from '../../cache.js';
import { loadTrustedList } from '../../etsi-tsl.js';
import { makeCertificate } from '../fixtures.js';
import { signEnvelopedXml } from '../xml/xml-fixtures.js';

/** `get` / `set` を関数として持たない不正な形状。 */
const MALFORMED_CACHES: ReadonlyArray<[string, unknown]> = [
  ['null', null],
  ['空オブジェクト', {}],
  ['get はあるが set が関数でない', { get: () => undefined, set: 'not-a-function' }],
];

/** granted な QTSP CA を 1 件持つ TSL を署名して返す。 */
function signedTslXml(): string {
  const ca = makeCertificate({ cn: 'DE QTSP CA', kind: 'rsa' });
  const signer = makeCertificate({ cn: 'DE TSL Signer', kind: 'ec' });
  const GRANTED = 'http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/granted';
  const bodyInner =
    `<TSPService><ServiceTypeIdentifier>http://uri.etsi.org/TrstSvc/Svctype/CA/QC</ServiceTypeIdentifier><ServiceStatus>${GRANTED}</ServiceStatus>` +
    '<X509Certificate>' +
    base64.encode(ca.der) +
    '</X509Certificate></TSPService>';
  return signEnvelopedXml({
    bodyOpen: '<TrustServiceStatusList>',
    bodyInner,
    bodyClose: '</TrustServiceStatusList>',
    privateKey: signer.privateKey,
    certDer: signer.der,
    kind: 'ec',
  });
}

/**
 * granted な QTSP CA を 1 件持つ TSL を、`NextUpdate` 付きで署名して返す。
 *
 * `signedTslXml` は `NextUpdate` を含まないため `buildTrustedListCacheEntry` が `fetchedAt` を
 * 採用し、TTL 0（即時失効）で格納されない（`cache.ts` の fail-closed 仕様）。キャッシュへの
 * 格納そのものを検証するポジティブコントロールにはこちらを使う。
 */
function signedTslXmlWithNextUpdate(nextUpdateSeconds: number): string {
  const ca = makeCertificate({ cn: 'DE QTSP CA', kind: 'rsa' });
  const signer = makeCertificate({ cn: 'DE TSL Signer', kind: 'ec' });
  const GRANTED = 'http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/granted';
  const nextUpdateIso = new Date(nextUpdateSeconds * 1000).toISOString();
  const bodyInner =
    `<SchemeInformation><NextUpdate><dateTime>${nextUpdateIso}</dateTime></NextUpdate></SchemeInformation>` +
    `<TSPService><ServiceTypeIdentifier>http://uri.etsi.org/TrstSvc/Svctype/CA/QC</ServiceTypeIdentifier><ServiceStatus>${GRANTED}</ServiceStatus>` +
    '<X509Certificate>' +
    base64.encode(ca.der) +
    '</X509Certificate></TSPService>';
  return signEnvelopedXml({
    bodyOpen: '<TrustServiceStatusList>',
    bodyInner,
    bodyClose: '</TrustServiceStatusList>',
    privateKey: signer.privateKey,
    certDer: signer.der,
    kind: 'ec',
  });
}

describe('loadTrustedList — 不正な形状の options.cache による成功パスのクラッシュ防止', () => {
  it.each(
    MALFORMED_CACHES,
  )('不正な cache(%s)を渡しても、取得成功は例外にならない', async (_label, cache) => {
    const xml = signedTslXml();
    const result = await loadTrustedList('https://tsl.example/DE.xml', {
      kind: 'tsl',
      fetcher: async () => xml,
      cache: cache as never,
    });
    expect(result.serviceCertificates.length).toBe(1);
  });
});

describe('loadTrustedList — 正当な形状の options.cache は従来どおり機能する（ポジティブコントロール）', () => {
  it('createTrustedListCache() の結果は取得成功時に正しく格納される', async () => {
    const nowSeconds = 1_700_000_000;
    const xml = signedTslXmlWithNextUpdate(nowSeconds + 3600);
    const cache = createTrustedListCache(() => nowSeconds);

    const result = await loadTrustedList('https://tsl.example/DE.xml', {
      kind: 'tsl',
      cache,
      nowSeconds,
      fetcher: async () => xml,
    });
    expect(result.serviceCertificates.length).toBe(1);

    // `isValidTrustedListCache` が誤って常に false を返すと、ここで未格納扱い(`undefined`)になる。
    const cached = cache.get('https://tsl.example/DE.xml', nowSeconds);
    expect(cached?.expired).toBe(false);
  });
});

describe('loadTrustedList — 不正な形状の options.cache による失敗パスのクラッシュ防止', () => {
  it.each(
    MALFORMED_CACHES,
  )('不正な cache(%s)を渡した取得失敗は、生の TypeError ではなく TSL_FETCH_FAILED(5001) になる', async (_label, cache) => {
    let caught: unknown;
    try {
      await loadTrustedList('https://tsl.example/DE.xml', {
        kind: 'tsl',
        fetcher: async () => {
          throw new Error('network');
        },
        cache: cache as never,
      });
    } catch (error) {
      caught = error;
    }
    expect(caught).toBeInstanceOf(VericertsError);
    expect((caught as VericertsError).code).toBe('5001');
  });
});
