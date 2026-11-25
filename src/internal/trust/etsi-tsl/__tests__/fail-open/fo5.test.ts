/**
 * FO-5（ETSI TSL / LOTL 取得失敗時、有効期限内のキャッシュで警告通過）の回帰テスト。
 *
 * 検証内容:
 * - 有効期限内（`NextUpdate` を過ぎていない）のキャッシュがあり、ウィンドウ・監査シンク・同意が
 *   揃っていれば警告付きで通過する。返る結果は stale なキャッシュ由来の実データ。
 * - キャッシュが無い / 期限切れ（`NextUpdate` を過ぎた）場合は常に fail-closed（`resolveFailOpen`
 *   すら呼ばない ＝ 監査記録も残らない）。
 * - `failOpenWindow` 未注入なら FO-5 は完全に不活性（従来と同じ挙動）。
 * - `escalate: ['FO-5']` / 同意拒否 / 時間上限超過はいずれも fail-closed。
 */

import { describe, expect, it } from 'bun:test';
import { ErrorCodes } from '../../../../errors.js';
import { createFailOpenWindow } from '../../../../failsafe-policy/index.js';
import { readTrustedListCache } from '../../cache.js';
import { loadTrustedList } from '../../etsi-tsl.js';
import {
  CACHE_TTL_SECONDS,
  EXPIRED_AFTER_SECONDS,
  expectRejectCode,
  FO5_WARNING,
  failOpenHarness,
  NOW_SECONDS,
  primedAndOffline,
  TSL_URL,
} from './harness.js';

describe('FO-5 成立（有効期限内のキャッシュ + ウィンドウ + 監査 + 同意）', () => {
  it('警告付きで通過し、キャッシュ由来の実データ（サービス証明書）を返す', async () => {
    const h = await primedAndOffline(loadTrustedList);
    h.advance(100); // NextUpdate（+3600秒）内に留まる。
    const result = await loadTrustedList(TSL_URL, {
      ...h.base,
      nowSeconds: h.now(),
      failOpenWindow: createFailOpenWindow(),
      onPolicyEvent: h.onPolicyEvent,
      requestConsent: h.requestConsent,
    });
    expect(result.warnings).toEqual([FO5_WARNING]);
    expect(result.serviceCertificates.length).toBe(1);
    expect(result.serviceCertificates[0]?.granted).toBe(true);
    expect(h.records).toHaveLength(1);
    expect(h.records[0]?.policy_event).toBe('FO-5');
    expect(h.records[0]?.user_consent).toBe('accepted');
    expect(h.consents).toHaveLength(1);
  });

  it('連続した取得失敗でも時間上限内であれば通過し続ける', async () => {
    const h = await primedAndOffline(loadTrustedList);
    const deps = {
      ...h.base,
      failOpenWindow: createFailOpenWindow(),
      onPolicyEvent: h.onPolicyEvent,
      requestConsent: h.requestConsent,
    };
    h.advance(10);
    expect((await loadTrustedList(TSL_URL, { ...deps, nowSeconds: h.now() })).warnings).toEqual([
      FO5_WARNING,
    ]);
    h.advance(10);
    expect((await loadTrustedList(TSL_URL, { ...deps, nowSeconds: h.now() })).warnings).toEqual([
      FO5_WARNING,
    ]);
    expect(h.records).toHaveLength(2);
  });

  it('時間上限（既定 60 秒）を超えた継続失敗は fail-closed に戻る', async () => {
    const h = await primedAndOffline(loadTrustedList);
    const deps = {
      ...h.base,
      failOpenWindow: createFailOpenWindow(),
      onPolicyEvent: h.onPolicyEvent,
      requestConsent: h.requestConsent,
    };
    await loadTrustedList(TSL_URL, { ...deps, nowSeconds: h.now() });
    h.advance(61); // まだ NextUpdate（+3600秒）内だが、ウィンドウの 60 秒上限は超える。
    await expectRejectCode(
      loadTrustedList(TSL_URL, { ...deps, nowSeconds: h.now() }),
      ErrorCodes.TSL_FETCH_FAILED,
    );
  });
});

describe('FO-5 不成立（いずれも元の TSL_FETCH_FAILED を伝播する）', () => {
  it('キャッシュが一切無ければ resolveFailOpen を呼ばない（監査記録も残らない）', async () => {
    const h = failOpenHarness();
    h.goOffline();
    await expectRejectCode(
      loadTrustedList(TSL_URL, {
        ...h.base,
        nowSeconds: h.now(),
        failOpenWindow: createFailOpenWindow(),
        onPolicyEvent: h.onPolicyEvent,
        requestConsent: h.requestConsent,
      }),
      ErrorCodes.TSL_FETCH_FAILED,
    );
    expect(h.records).toEqual([]);
    expect(h.consents).toEqual([]);
  });

  it('NextUpdate を過ぎたキャッシュ（期限切れ）は対象外で fail-closed', async () => {
    const h = await primedAndOffline(loadTrustedList);
    h.advance(EXPIRED_AFTER_SECONDS);
    expect(readTrustedListCache(h.cache, TSL_URL, h.now())).toBeUndefined();
    await expectRejectCode(
      loadTrustedList(TSL_URL, {
        ...h.base,
        nowSeconds: h.now(),
        failOpenWindow: createFailOpenWindow(),
        onPolicyEvent: h.onPolicyEvent,
        requestConsent: h.requestConsent,
      }),
      ErrorCodes.TSL_FETCH_FAILED,
    );
    expect(h.records).toEqual([]);
  });

  it('failOpenWindow 未注入なら有効期限内キャッシュがあっても発動しない（既定の挙動）', async () => {
    const h = await primedAndOffline(loadTrustedList);
    h.advance(100);
    await expectRejectCode(
      loadTrustedList(TSL_URL, {
        ...h.base,
        nowSeconds: h.now(),
        onPolicyEvent: h.onPolicyEvent,
        requestConsent: h.requestConsent,
      }),
      ErrorCodes.TSL_FETCH_FAILED,
    );
    expect(h.records).toEqual([]);
  });

  it('escalate: ["FO-5"] は監査シンクと同意が揃っていても fail-closed', async () => {
    const h = await primedAndOffline(loadTrustedList);
    h.advance(100);
    await expectRejectCode(
      loadTrustedList(TSL_URL, {
        ...h.base,
        nowSeconds: h.now(),
        failSafePolicy: { escalate: ['FO-5'] },
        failOpenWindow: createFailOpenWindow(),
        onPolicyEvent: h.onPolicyEvent,
        requestConsent: h.requestConsent,
      }),
      ErrorCodes.TSL_FETCH_FAILED,
    );
    // deny は Fail-open を選択していないため監査記録の対象ではない。
    expect(h.records).toEqual([]);
  });

  it('監査シンク未指定は fail-closed', async () => {
    const h = await primedAndOffline(loadTrustedList);
    h.advance(100);
    await expectRejectCode(
      loadTrustedList(TSL_URL, {
        ...h.base,
        nowSeconds: h.now(),
        failOpenWindow: createFailOpenWindow(),
        requestConsent: h.requestConsent,
      }),
      ErrorCodes.TSL_FETCH_FAILED,
    );
  });

  it('同意が得られなければ fail-closed（rejected として監査記録する）', async () => {
    const h = await primedAndOffline(loadTrustedList);
    h.advance(100);
    await expectRejectCode(
      loadTrustedList(TSL_URL, {
        ...h.base,
        nowSeconds: h.now(),
        failOpenWindow: createFailOpenWindow(),
        onPolicyEvent: h.onPolicyEvent,
        requestConsent: () => false,
      }),
      ErrorCodes.TSL_FETCH_FAILED,
    );
    expect(h.records).toHaveLength(1);
    expect(h.records[0]?.user_consent).toBe('rejected');
  });
});

// CACHE_TTL_SECONDS を直接参照し、フィクスチャの NextUpdate 前提が変わっても壊れないことを示す。
describe('キャッシュ格納（正常系）', () => {
  it('取得成功時にキャッシュへ NextUpdate 由来の TTL で格納する', async () => {
    const h = failOpenHarness();
    await loadTrustedList(TSL_URL, { ...h.base, nowSeconds: h.now() });
    h.advance(CACHE_TTL_SECONDS - 1);
    expect(readTrustedListCache(h.cache, TSL_URL, h.now())).toBeDefined();
    h.advance(2);
    expect(readTrustedListCache(h.cache, TSL_URL, h.now())).toBeUndefined();
  });
});

describe('署名の再検証失敗は監査記録より前に伝播する', () => {
  it('キャッシュされた XML が改ざんされていれば、監査記録を残さず署名検証失敗を伝播する', async () => {
    const h = await primedAndOffline(loadTrustedList);
    const cached = readTrustedListCache(h.cache, TSL_URL, NOW_SECONDS);
    if (cached === undefined) {
      throw new Error('test setup failed: no cache entry after priming');
    }
    // 本体を改ざんし、DigestValue と一致しなくする(署名検証が必ず失敗する状態を作る)。
    h.cache.set(
      TSL_URL,
      { ...cached, xml: cached.xml.replace('TSPService', 'Tampered') },
      CACHE_TTL_SECONDS,
      NOW_SECONDS,
    );
    h.advance(100); // NextUpdate 内に留まる(TTL 切れとの混同を避ける)。
    await expectRejectCode(
      loadTrustedList(TSL_URL, {
        ...h.base,
        nowSeconds: h.now(),
        failOpenWindow: createFailOpenWindow(),
        onPolicyEvent: h.onPolicyEvent,
        requestConsent: h.requestConsent,
      }),
      ErrorCodes.TSL_SIG_INVALID,
    );
    // 署名検証を監査記録より先に行うため、「fail-open を許可した」という記録は一切残らない。
    expect(h.records).toEqual([]);
  });
});
