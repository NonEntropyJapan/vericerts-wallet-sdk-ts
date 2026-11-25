/**
 * FO-5 の fail-open 経路が `options.kind`（kindHint）を無視していた欠陥の回帰テスト
 *
 * `resolveWithFailOpen` は `verifyAndExtract(cached.type, cached.xml)` を呼ぶだけで、呼び出し側が
 * 指定した `kindHint` とキャッシュ済みエントリの実際の種別を照合していなかった。同一 URL に対して
 * 過去の呼び出しが `kind: 'auto'` で `lotl` と判定していた場合、`kind: 'tsl'` を明示する今回の
 * 呼び出しがそのキャッシュを無言で受理すると、TSL として扱われるべきものが LOTL 分岐に入り
 * `serviceCertificates`（常に空）を返す ＝ Trust Anchor が無言で欠落する。
 *
 * 検証内容:
 * - `kindHint` がキャッシュ済みエントリの実際の種別と食い違う場合は FO-5 を成立させず fail-closed
 *   に倒す（監査記録も残らない。種別確認は監査記録より前に行うため）。
 * - `kindHint: 'auto'`（未指定）なら従来どおりキャッシュ済みの種別をそのまま使い、FO-5 が成立する
 *   （ポジティブコントロール）。
 * - `options.kind` にユニオン外の値（型を無視した不正な注入）を明示した場合も、種別不一致と
 *   同じ扱いで FO-5 を成立させず fail-closed に倒す。
 *   `validKindHint` がユニオン外の値を成功パス用に `'auto'` へフォールバックする実装のままだと、
 *   この `kindHint` を FO-5 の一致判定にも使い回した場合に `kindHint !== 'auto'` が false になり、
 *   種別不一致ガード自体が丸ごと迂回されて、明示指定と食い違うキャッシュが警告付きで受理されて
 *   しまう。
 */

import { describe, expect, it } from 'bun:test';
import { ErrorCodes } from '../../../../errors.js';
import {
  createFailOpenWindow,
  type FailSafeAuditRecord,
} from '../../../../failsafe-policy/index.js';
import { createTrustedListCache } from '../../cache.js';
import { type LoadTrustedListOptions, loadTrustedList } from '../../etsi-tsl.js';
import { makeCertificate } from '../fixtures.js';
import { signEnvelopedXml } from '../xml/xml-fixtures.js';
import { CACHE_TTL_SECONDS, expectRejectCode, NOW_SECONDS, TSL_URL } from './harness.js';

/** 取得は常に失敗させる（有効期限内のキャッシュだけが判断材料として残る状況を作る）。 */
const OFFLINE_FETCHER = async (): Promise<string> => {
  throw new Error('network');
};

/** 署名付き LOTL 本体（ポインタなし）。`verifyAndExtract` の再検証を通すために必要。 */
function signedLotlXml(nextUpdateSeconds: number): string {
  const signer = makeCertificate({ cn: 'EU LOTL Signer', kind: 'ec' });
  const nextUpdateIso = new Date(nextUpdateSeconds * 1000).toISOString();
  const bodyInner = `<SchemeInformation><NextUpdate><dateTime>${nextUpdateIso}</dateTime></NextUpdate></SchemeInformation>`;
  return signEnvelopedXml({
    bodyOpen: '<TrustServiceStatusList>',
    bodyInner,
    bodyClose: '</TrustServiceStatusList>',
    privateKey: signer.privateKey,
    certDer: signer.der,
    kind: 'ec',
  });
}

/** `kind: 'auto'` で過去に `lotl` と判定されたエントリを 1 件持つ依存注入を組み立てる。 */
function depsWithCachedLotl(kind: LoadTrustedListOptions['kind']): LoadTrustedListOptions {
  const cache = createTrustedListCache(() => NOW_SECONDS);
  const nextUpdateSeconds = NOW_SECONDS + CACHE_TTL_SECONDS;
  const nextUpdate = new Date(nextUpdateSeconds * 1000).toISOString();
  cache.set(
    TSL_URL,
    {
      url: TSL_URL,
      type: 'lotl',
      xml: signedLotlXml(nextUpdateSeconds),
      signatureValid: true,
      nextUpdate,
      fetchedAt: new Date(NOW_SECONDS * 1000).toISOString(),
    },
    CACHE_TTL_SECONDS,
    NOW_SECONDS,
  );
  return {
    kind,
    cache,
    fetcher: OFFLINE_FETCHER,
    nowSeconds: NOW_SECONDS,
    failOpenWindow: createFailOpenWindow(),
    requestConsent: (): boolean => true,
  };
}

describe('FO-5 と kindHint の不一致', () => {
  it('kind: "tsl" を明示すると、auto 判定で lotl と判定済みのキャッシュを無言で受理しない', async () => {
    const records: FailSafeAuditRecord[] = [];
    const deps: LoadTrustedListOptions = {
      ...depsWithCachedLotl('tsl'),
      onPolicyEvent: (record: FailSafeAuditRecord): void => {
        records.push(record);
      },
    };
    await expectRejectCode(loadTrustedList(TSL_URL, deps), ErrorCodes.TSL_FETCH_FAILED);
    // 種別不一致は監査記録より前に弾くため、記録は一切残らない。
    expect(records).toEqual([]);
  });

  it('kind: "auto"（未指定）なら従来どおりキャッシュ済みの種別で FO-5 が成立する（正常系）', async () => {
    const records: FailSafeAuditRecord[] = [];
    const deps: LoadTrustedListOptions = {
      ...depsWithCachedLotl('auto'),
      onPolicyEvent: (record: FailSafeAuditRecord): void => {
        records.push(record);
      },
    };
    const result = await loadTrustedList(TSL_URL, deps);
    expect(result.warnings).toBeDefined();
    expect(result.pointers).toEqual([]);
    expect(records).toHaveLength(1);
  });

  it('kind にユニオン外の値を明示すると、auto へのフォールバックに畳まれず不一致として fail-closed に倒す', async () => {
    const records: FailSafeAuditRecord[] = [];
    const deps: LoadTrustedListOptions = {
      ...depsWithCachedLotl('not-a-real-kind' as never),
      onPolicyEvent: (record: FailSafeAuditRecord): void => {
        records.push(record);
      },
    };
    // ユニオン外の値は `validKindHint` により成功パス用に `kindHint: 'auto'` へフォールバック
    // するため、取得失敗コードの正規化（`kindHint === 'tsl' ? TSL_FETCH_FAILED : …`）も
    // `LOTL_FETCH_FAILED`(10301) 側になる。ここで検証したいのはコードの値そのものではなく、
    // 種別不一致ガードが迂回されず fail-closed に倒れること（監査記録が残らないこと）。
    await expectRejectCode(loadTrustedList(TSL_URL, deps), ErrorCodes.LOTL_FETCH_FAILED);
    expect(records).toEqual([]);
  });
});
