/**
 * VC リフレッシュの「必須欄・応答欄」の `Object.prototype` 汚染耐性テスト。
 *
 * 既存の `refresh.proto-pollution.test.ts` が `opts` の任意プロパティを対象とするのに対し、
 * 本ファイルは読み方が非対称に残っていた `policy` / VC 本文 / `refreshService` / 応答 JSON を扱う。
 * いずれも「そのプロパティを**省略した**入力」で検証する（明示指定は汚染と無関係に通るため無価値）。
 */

import { describe, expect, it } from 'bun:test';
import {
  withPollutedPrototype,
  withPollutedPrototypeAccessor,
  withPollutedPrototypeAccessorAsync,
  withPollutedPrototypeAsync,
} from '../../../../__tests__/prototype-pollution.fixtures.js';
import type { FetchLike } from '../../../../auth/oid4vci/oid4vci.js';
import { ErrorCodes } from '../../../../errors.js';
import type { RefreshServiceConfig, VerifiableCredential } from '../../../vc/vc.js';
import {
  type RefreshDependencies,
  type RefreshPolicy,
  refreshCredential,
  shouldRefresh,
} from '../../refresh.js';

const MS_PER_DAY = 24 * 60 * 60 * 1000;
const NOW = Date.parse('2026-07-01T00:00:00Z');

const SERVICE: RefreshServiceConfig = {
  id: 'refresh-1',
  type: 'OID4VCIRefreshService2025',
  url: 'https://issuer.example/refresh',
};

/** 新 VC（`derivedFrom` は持たない ＝ Issuer 未設定）。 */
const NEW_VC: VerifiableCredential = {
  '@context': ['https://www.w3.org/ns/credentials/v2'],
  type: ['VerifiableCredential', 'IdentityCredential'],
  issuer: 'did:example:issuer',
  credentialSubject: { id: 'did:example:holder' },
  issuanceDate: '2026-07-01T00:00:00Z',
  id: 'urn:vc:new',
};

/** しきい値内（exp まで 5 日）の旧 VC。 */
function makeVc(overrides: Partial<VerifiableCredential> = {}): VerifiableCredential {
  return {
    '@context': ['https://www.w3.org/ns/credentials/v2'],
    type: ['VerifiableCredential', 'IdentityCredential'],
    issuer: 'did:example:issuer',
    credentialSubject: { id: 'did:example:holder' },
    issuanceDate: '2026-01-01T00:00:00Z',
    expirationDate: new Date(NOW + 5 * MS_PER_DAY).toISOString(),
    id: 'urn:vc:old',
    refreshService: SERVICE,
    ...overrides,
  };
}

/** 指定 JSON 本文を 200 で返しつつ、要求 URL と body を記録する FetchLike。 */
function recordingFetch(responseBody: string): {
  readonly fetchImpl: FetchLike;
  readonly calls: Array<{ url: string; body: string }>;
} {
  const calls: Array<{ url: string; body: string }> = [];
  const fetchImpl: FetchLike = async (url, init) => {
    calls.push({ url, body: init.body });
    return new Response(responseBody, { status: 200 });
  };
  return { fetchImpl, calls };
}

/** 受領した生 VC（JSON）をそのままパースして返す検証スタブ。 */
const verifyOk: RefreshDependencies['verifyRefreshed'] = async (raw) =>
  JSON.parse(raw) as VerifiableCredential;

describe('shouldRefresh の Object.prototype 汚染耐性', () => {
  const vc = makeVc();

  it('autoRefresh を宣言していない policy は自動更新 ON に化けない', () => {
    // `autoRefresh` を省略した policy。鎖読みなら汚染値 true を拾い、対象外の VC が更新対象になる。
    const policy = { vcType: 'IdentityCredential' } as RefreshPolicy;
    const result = withPollutedPrototype({ autoRefresh: true }, () =>
      shouldRefresh(vc, policy, NOW),
    );
    expect(result).toBe(false);
  });

  it('アクセサ汚染の autoRefresh でも自動更新 ON に化けない', () => {
    const policy = { vcType: 'IdentityCredential' } as RefreshPolicy;
    const result = withPollutedPrototypeAccessor({ autoRefresh: () => true }, () =>
      shouldRefresh(vc, policy, NOW),
    );
    expect(result).toBe(false);
  });

  it('vcType を宣言していない policy は VC 種別に一致しない', () => {
    const policy = { autoRefresh: true } as RefreshPolicy;
    const result = withPollutedPrototype({ vcType: 'IdentityCredential' }, () =>
      shouldRefresh(vc, policy, NOW),
    );
    expect(result).toBe(false);
  });

  it('thresholdDays を宣言していない policy のしきい値は既定 7 日のまま', () => {
    // exp まで 30 日 ＝ 既定しきい値の外。汚染値 365 を拾うと対象になってしまう。
    const far = makeVc({ expirationDate: new Date(NOW + 30 * MS_PER_DAY).toISOString() });
    const policy: RefreshPolicy = { vcType: 'IdentityCredential', autoRefresh: true };
    const result = withPollutedPrototype({ thresholdDays: 365 }, () =>
      shouldRefresh(far, policy, NOW),
    );
    expect(result).toBe(false);
  });

  it('type を持たない VC は継承した type で種別一致しない', () => {
    const { type: _omitted, ...withoutType } = makeVc();
    const typeless = withoutType as unknown as VerifiableCredential;
    const policy: RefreshPolicy = { vcType: 'IdentityCredential', autoRefresh: true };
    const result = withPollutedPrototype({ type: ['IdentityCredential'] }, () =>
      shouldRefresh(typeless, policy, NOW),
    );
    expect(result).toBe(false);
  });

  it('expirationDate を持たない（無期限）VC は継承した期限で対象化されない', () => {
    // `{ expirationDate: undefined }` では own キーが生えて汚染値が届かない（＝トートロジー）。
    // キーそのものを持たせないため分割代入で落とす。
    const { expirationDate: _omitted, ...withoutExp } = makeVc();
    const endless = withoutExp as VerifiableCredential;
    const policy: RefreshPolicy = { vcType: 'IdentityCredential', autoRefresh: true };
    const result = withPollutedPrototype(
      { expirationDate: new Date(NOW - MS_PER_DAY).toISOString() },
      () => shouldRefresh(endless, policy, NOW),
    );
    expect(result).toBe(false);
  });

  it('明示的に渡した policy / VC は従来どおり判定される（正常系）', () => {
    expect(shouldRefresh(vc, { vcType: 'IdentityCredential', autoRefresh: true }, NOW)).toBe(true);
    const far = makeVc({ expirationDate: new Date(NOW + 20 * MS_PER_DAY).toISOString() });
    const policy: RefreshPolicy = {
      vcType: 'IdentityCredential',
      autoRefresh: true,
      thresholdDays: 30,
    };
    expect(shouldRefresh(far, policy, NOW)).toBe(true);
  });
});

describe('refreshService エンドポイント呼び出しの汚染耐性', () => {
  it('url を持たない refreshService は継承した URL へ要求を飛ばさない', async () => {
    const { url: _omitted, ...withoutUrl } = SERVICE;
    const vc = makeVc({ refreshService: withoutUrl as RefreshServiceConfig });
    const recorder = recordingFetch(JSON.stringify({ credential: JSON.stringify(NEW_VC) }));
    const deps: RefreshDependencies = { verifyRefreshed: verifyOk, fetchImpl: recorder.fetchImpl };
    const promise = withPollutedPrototypeAsync({ url: 'https://attacker.example/refresh' }, () =>
      refreshCredential(vc, { now: NOW }, deps),
    );
    await expect(promise).rejects.toMatchObject({ code: ErrorCodes.REFRESH_FAILED });
    expect(recorder.calls).toHaveLength(0);
  });

  it('id を持たない refreshService は継承した id で要求を組み立てない', async () => {
    const { id: _omitted, ...withoutId } = SERVICE;
    const vc = makeVc({ refreshService: withoutId as RefreshServiceConfig });
    const recorder = recordingFetch(JSON.stringify({ credential: JSON.stringify(NEW_VC) }));
    const deps: RefreshDependencies = { verifyRefreshed: verifyOk, fetchImpl: recorder.fetchImpl };
    const promise = withPollutedPrototypeAsync({ id: 'attacker-service' }, () =>
      refreshCredential(vc, { now: NOW }, deps),
    );
    await expect(promise).rejects.toMatchObject({ code: ErrorCodes.REFRESH_FAILED });
    expect(recorder.calls).toHaveLength(0);
  });

  it('id を持たない VC は継承した credentialId を要求本文に載せない', async () => {
    const { id: _omitted, ...withoutId } = makeVc();
    const vc = withoutId as VerifiableCredential;
    const recorder = recordingFetch(JSON.stringify({ credential: JSON.stringify(NEW_VC) }));
    const deps: RefreshDependencies = { verifyRefreshed: verifyOk, fetchImpl: recorder.fetchImpl };
    const result = await withPollutedPrototypeAsync({ id: 'urn:vc:attacker' }, () =>
      refreshCredential(vc, { now: NOW }, deps),
    );
    expect(result.refreshed).toBe(true);
    expect(recorder.calls[0]?.body).toBe(JSON.stringify({ refreshServiceId: 'refresh-1' }));
    // 旧 VC の ID が無いのだからチェーンエッジも張れない（汚染値で張ってはならない）。
    expect(result.credential?.derivedFrom).toBeUndefined();
  });

  it('credential を持たない応答は継承値を新しい生 VC として採用しない', async () => {
    let verifyCalled = false;
    const deps: RefreshDependencies = {
      verifyRefreshed: async (raw) => {
        verifyCalled = true;
        return JSON.parse(raw) as VerifiableCredential;
      },
      fetchImpl: recordingFetch('{}').fetchImpl,
    };
    const promise = withPollutedPrototypeAsync({ credential: JSON.stringify(NEW_VC) }, () =>
      refreshCredential(makeVc(), { now: NOW }, deps),
    );
    await expect(promise).rejects.toMatchObject({ code: ErrorCodes.REFRESH_FAILED });
    expect(verifyCalled).toBe(false);
  });

  it('verifiableCredential の継承値も新しい生 VC として採用しない', async () => {
    const deps: RefreshDependencies = {
      verifyRefreshed: verifyOk,
      fetchImpl: recordingFetch('{}').fetchImpl,
    };
    const promise = withPollutedPrototypeAccessorAsync(
      { verifiableCredential: () => JSON.stringify(NEW_VC) },
      () => refreshCredential(makeVc(), { now: NOW }, deps),
    );
    await expect(promise).rejects.toMatchObject({ code: ErrorCodes.REFRESH_FAILED });
  });
});

describe('refreshCredential の VC 本文読み取りの汚染耐性', () => {
  it('requireHolderConsent を宣言していないサービスに同意要求を生やさない', async () => {
    // 同意コールバックは注入していない。汚染値を拾えば 3023 で正当なリフレッシュが止まる。
    const deps: RefreshDependencies = {
      verifyRefreshed: verifyOk,
      fetchImpl: recordingFetch(JSON.stringify({ credential: JSON.stringify(NEW_VC) })).fetchImpl,
    };
    const result = await withPollutedPrototypeAsync({ requireHolderConsent: true }, () =>
      refreshCredential(makeVc(), { now: NOW }, deps),
    );
    expect(result.refreshed).toBe(true);
  });

  it('expirationDate を持たない VC は継承した期限でしきい値判定を飛ばさない', async () => {
    // 無期限 VC は期限チェック対象外 ＝ そのままリフレッシュへ進むのが正。汚染された
    // 遠い未来の期限を拾うと「しきい値未達」に化け、入れ替えが無言でスキップされる。
    const { expirationDate: _omitted, ...withoutExp } = makeVc();
    const endless = withoutExp as VerifiableCredential;
    const deps: RefreshDependencies = {
      verifyRefreshed: verifyOk,
      fetchImpl: recordingFetch(JSON.stringify({ credential: JSON.stringify(NEW_VC) })).fetchImpl,
    };
    const result = await withPollutedPrototypeAsync(
      { expirationDate: new Date(NOW + 365 * MS_PER_DAY).toISOString() },
      () => refreshCredential(endless, { now: NOW }, deps),
    );
    expect(result.refreshed).toBe(true);
    expect(result.credential?.id).toBe('urn:vc:new');
  });

  it('derivedFrom を持たない新 VC のチェーンエッジ付与が継承値でスキップされない', async () => {
    const deps: RefreshDependencies = {
      verifyRefreshed: verifyOk,
      fetchImpl: recordingFetch(JSON.stringify({ credential: JSON.stringify(NEW_VC) })).fetchImpl,
    };
    const result = await withPollutedPrototypeAsync({ derivedFrom: 'urn:vc:attacker' }, () =>
      refreshCredential(makeVc(), { now: NOW }, deps),
    );
    // 汚染を戻した後に読むので、これは新 VC 自身の own 値。
    expect(result.credential?.derivedFrom).toBe('urn:vc:old');
  });

  // クラスベース DI（prototype メソッド注入）の正常系は、レシーバ束ね直しまで検証する
  // `refresh-receiver.proto-pollution.test.ts` が上位互換で担保する。

  it('明示的に設定された requireHolderConsent / derivedFrom は従来どおり効く（正常系）', async () => {
    const chained = { ...NEW_VC, derivedFrom: 'urn:vc:issuer-set' };
    const vc = makeVc({ refreshService: { ...SERVICE, requireHolderConsent: true } });
    let consentAsked = false;
    const deps: RefreshDependencies = {
      verifyRefreshed: verifyOk,
      requestConsent: async () => {
        consentAsked = true;
        return true;
      },
      fetchImpl: recordingFetch(JSON.stringify({ credential: JSON.stringify(chained) })).fetchImpl,
    };
    const result = await refreshCredential(vc, { now: NOW }, deps);
    expect(consentAsked).toBe(true);
    expect(result.credential?.derivedFrom).toBe('urn:vc:issuer-set');
  });
});
