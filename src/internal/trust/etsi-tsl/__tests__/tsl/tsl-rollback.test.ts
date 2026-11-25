/**
 * TSL/LOTL の世代ロールバック拒否（TSLSequenceNumber / ListIssueDateTime の単調性）。
 *
 * `NextUpdate` 内の旧世代（CA が withdrawn になる前の署名済み TSL）の再生を、キャッシュにある
 * 直前世代との比較で拒否する。署名者・CA は固定し、世代情報だけを変えた署名済み TSL を作る。
 */

import { describe, expect, it } from 'bun:test';
import { base64 } from '@scure/base';
import { VericertsError } from '../../../../errors.js';
import { createTrustedListCache } from '../../cache.js';
import { loadTrustedList } from '../../etsi-tsl.js';
import { extractTrustedListGeneration, isTrustedListGenerationMonotonic } from '../../rollback.js';
import { makeCertificate } from '../fixtures.js';
import { signEnvelopedXml } from '../xml/xml-fixtures.js';

const URL = 'https://tsl.example/DE.xml';
const NOW = 1_700_000_000;
const GRANTED = 'http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/granted';
const ca = makeCertificate({ cn: 'DE QTSP CA', kind: 'rsa' });
const signer = makeCertificate({ cn: 'DE TSL Signer', kind: 'ec' });

interface Generation {
  readonly sequence?: string;
  readonly issued?: string;
  /** `NextUpdate`（エポック秒）。省略時は `NOW` の 1 日後。 */
  readonly nextUpdateSeconds?: number;
}

/** 世代情報を持つ署名済み TSL。`NextUpdate` は常に現在より先。 */
function signedTsl({ sequence, issued, nextUpdateSeconds = NOW + 86_400 }: Generation): string {
  const nextUpdate = new Date(nextUpdateSeconds * 1000).toISOString();
  const bodyInner =
    '<SchemeInformation>' +
    (sequence === undefined ? '' : `<TSLSequenceNumber>${sequence}</TSLSequenceNumber>`) +
    (issued === undefined ? '' : `<ListIssueDateTime>${issued}</ListIssueDateTime>`) +
    `<NextUpdate><dateTime>${nextUpdate}</dateTime></NextUpdate></SchemeInformation>` +
    `<TSPService><ServiceTypeIdentifier>http://uri.etsi.org/TrstSvc/Svctype/CA/QC</ServiceTypeIdentifier><ServiceStatus>${GRANTED}</ServiceStatus>` +
    `<X509Certificate>${base64.encode(ca.der)}</X509Certificate></TSPService>`;
  return signEnvelopedXml({
    bodyOpen: '<TrustServiceStatusList>',
    bodyInner,
    bodyClose: '</TrustServiceStatusList>',
    privateKey: signer.privateKey,
    certDer: signer.der,
    kind: 'ec',
  });
}

/** 同じキャッシュに対して世代を順に取得する。 */
async function fetchSequence(cache: ReturnType<typeof createTrustedListCache>, xml: string) {
  return loadTrustedList(URL, { kind: 'tsl', cache, nowSeconds: NOW, fetcher: async () => xml });
}

describe('extractTrustedListGeneration', () => {
  it('SchemeInformation 直下の TSLSequenceNumber / ListIssueDateTime を読む', () => {
    const generation = extractTrustedListGeneration(
      signedTsl({ sequence: '42', issued: '2026-01-01T00:00:00Z' }),
    );
    expect(generation.sequenceNumber).toBe(42n);
    expect(generation.issueDateTimeMs).toBe(Date.parse('2026-01-01T00:00:00Z'));
  });

  it('無い・不正な値は undefined（例外にしない）', () => {
    expect(extractTrustedListGeneration(signedTsl({}))).toEqual({});
    expect(
      extractTrustedListGeneration(signedTsl({ sequence: '-1', issued: 'yesterday' })),
    ).toEqual({});
    expect(extractTrustedListGeneration('<not-xml')).toEqual({});
  });
});

describe('isTrustedListGenerationMonotonic', () => {
  const at = (sequence?: string, issued?: string) => signedTsl({ sequence, issued });

  it.each([
    ['番号が増えた', at('5'), at('6'), true],
    [
      '同一番号・同一日時（再取得）',
      at('5', '2026-01-01T00:00:00Z'),
      at('5', '2026-01-01T00:00:00Z'),
      true,
    ],
    ['番号が戻った', at('6'), at('5'), false],
    [
      '番号が戻った（日時は進んでいても拒否）',
      at('6', '2026-01-01T00:00:00Z'),
      at('5', '2026-06-01T00:00:00Z'),
      false,
    ],
    [
      '番号が増えれば日時比較は不要',
      at('6', '2026-06-01T00:00:00Z'),
      at('7', '2026-01-01T00:00:00Z'),
      true,
    ],
    [
      '同一番号で日時が戻った',
      at('5', '2026-06-01T00:00:00Z'),
      at('5', '2026-01-01T00:00:00Z'),
      false,
    ],
    [
      '番号が無い世代同士は日時で比較（戻る）',
      at(undefined, '2026-06-01T00:00:00Z'),
      at(undefined, '2026-01-01T00:00:00Z'),
      false,
    ],
    [
      '番号が無い世代同士は日時で比較（進む）',
      at(undefined, '2026-01-01T00:00:00Z'),
      at(undefined, '2026-06-01T00:00:00Z'),
      true,
    ],
    [
      '直前に番号があったのに新世代から消えた',
      at('5'),
      at(undefined, '2026-06-01T00:00:00Z'),
      false,
    ],
    ['直前に日時があったのに新世代から消えた', at(undefined, '2026-06-01T00:00:00Z'), at(), false],
    ['直前に世代情報が無ければ比較しない', at(), at('1'), true],
    [
      '桁数の大きい番号も正しく比較する',
      at('9999999999999999999'),
      at('10000000000000000000'),
      true,
    ],
  ])('%s', (_label, previous, current, expected) => {
    expect(isTrustedListGenerationMonotonic(previous, current)).toBe(expected);
  });
});

describe('loadTrustedList — 旧世代の再生を拒否する', () => {
  it('新しい世代を受理した後に、署名の有効な旧世代を返されると TSL_SIG_INVALID(5002)', async () => {
    const cache = createTrustedListCache(() => NOW);
    await fetchSequence(cache, signedTsl({ sequence: '7' }));

    let caught: unknown;
    try {
      await fetchSequence(cache, signedTsl({ sequence: '6' }));
    } catch (error) {
      caught = error;
    }
    expect(caught).toBeInstanceOf(VericertsError);
    expect((caught as VericertsError).code).toBe('5002');
  });

  it('拒否した旧世代でキャッシュを上書きしない（以降も新しい世代が基準のまま）', async () => {
    const cache = createTrustedListCache(() => NOW);
    await fetchSequence(cache, signedTsl({ sequence: '7' }));
    await expect(fetchSequence(cache, signedTsl({ sequence: '6' }))).rejects.toBeInstanceOf(
      VericertsError,
    );
    await expect(fetchSequence(cache, signedTsl({ sequence: '5' }))).rejects.toBeInstanceOf(
      VericertsError,
    );
    expect(extractTrustedListGeneration(cache.get(URL, NOW)?.value.xml ?? '').sequenceNumber).toBe(
      7n,
    );
  });

  it('同一世代の再取得と、より新しい世代は受理する', async () => {
    const cache = createTrustedListCache(() => NOW);
    await fetchSequence(cache, signedTsl({ sequence: '7' }));
    expect(
      (await fetchSequence(cache, signedTsl({ sequence: '7' }))).serviceCertificates,
    ).toHaveLength(1);
    expect(
      (await fetchSequence(cache, signedTsl({ sequence: '8' }))).serviceCertificates,
    ).toHaveLength(1);
  });

  it('直前世代のキャッシュ TTL(30 日上限)が切れても、NextUpdate 内の旧世代の再生は拒否する', async () => {
    const day = 86_400;
    const cache = createTrustedListCache(() => NOW);
    const load = (xml: string, atDays: number) =>
      loadTrustedList(URL, {
        kind: 'tsl',
        cache,
        nowSeconds: NOW + atDays * day,
        fetcher: async () => xml,
      });
    const g1 = signedTsl({ sequence: '1', nextUpdateSeconds: NOW + 180 * day });
    const g2 = signedTsl({ sequence: '2', nextUpdateSeconds: NOW + 200 * day });
    await load(g2, 10);
    // day20: キャッシュ有効
    await expect(load(g1, 20)).rejects.toMatchObject({ code: '5002' });
    // day50: G2 の TTL(30 日上限)は失効済みだが、世代の高水位は残る
    await expect(load(g1, 50)).rejects.toMatchObject({ code: '5002' });
    // day170: 最新世代 G2 自体は受理できる
    expect((await load(g2, 170)).serviceCertificates).toHaveLength(1);
  });

  it('LOTL でも同様に、旧世代は XMLDSIG_VERIFICATION_FAILED(10302)', async () => {
    const lotl = (sequence: string) =>
      signEnvelopedXml({
        bodyOpen: '<TrustServiceStatusList>',
        bodyInner:
          `<SchemeInformation><TSLSequenceNumber>${sequence}</TSLSequenceNumber>` +
          `<NextUpdate><dateTime>${new Date((NOW + 86_400) * 1000).toISOString()}</dateTime></NextUpdate></SchemeInformation>` +
          '<PointersToOtherTSL><OtherTSLPointer><TSLLocation>https://tsl.example/DE.xml</TSLLocation></OtherTSLPointer></PointersToOtherTSL>',
        bodyClose: '</TrustServiceStatusList>',
        privateKey: signer.privateKey,
        certDer: signer.der,
        kind: 'ec',
      });
    const cache = createTrustedListCache(() => NOW);
    await loadTrustedList(URL, { cache, nowSeconds: NOW, fetcher: async () => lotl('3') });
    let caught: unknown;
    try {
      await loadTrustedList(URL, { cache, nowSeconds: NOW, fetcher: async () => lotl('2') });
    } catch (error) {
      caught = error;
    }
    expect((caught as VericertsError).code).toBe('10302');
  });

  it('cache を渡さない呼び出しは従来どおり（世代比較なし）', async () => {
    await loadTrustedList(URL, {
      kind: 'tsl',
      nowSeconds: NOW,
      fetcher: async () => signedTsl({ sequence: '7' }),
    });
    const result = await loadTrustedList(URL, {
      kind: 'tsl',
      nowSeconds: NOW,
      fetcher: async () => signedTsl({ sequence: '6' }),
    });
    expect(result.serviceCertificates).toHaveLength(1);
  });
});
