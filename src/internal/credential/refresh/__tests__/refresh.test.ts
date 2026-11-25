/**
 * refreshService に基づく VC 期限前リフレッシュのユニット / 統合テスト。
 *
 * 検証内容:
 * - shouldRefresh: autoRefresh / vcType / expirationDate / しきい値による自動更新トリガー判定。
 * - refreshCredential 成功: エンドポイント呼び出し → 検証 → 新 VC への入れ替えと derivedFrom 付与（統合）。
 * - refreshService 未設定で REFRESH_SERVICE_NOT_SET（3033）。
 * - しきい値未達（force なし）で入れ替えせず旧 VC を返す。
 * - Holder 同意拒否で HOLDER_CONSENT_NOT_OBTAINED（3023）。
 *
 * リフレッシュ失敗時の挙動（FO-9）は `refresh-fail-safe.test.ts`
 * （`.linterly.yml` の 1 ファイル 300 行上限のため分離）を参照。
 *
 * ネットワークは FetchLike スタブで注入し、実 HTTP は行わない（モックのみのダミーテストではなく
 * refresh ロジックの実挙動を検証する）。
 */

import { describe, expect, it } from 'bun:test';
import type { FetchLike } from '../../../auth/oid4vci/oid4vci.js';
import { ErrorCodes, VericertsError } from '../../../errors.js';
import type { RefreshServiceConfig, VerifiableCredential } from '../../vc/vc.js';
import {
  DEFAULT_REFRESH_THRESHOLD_DAYS,
  type RefreshDependencies,
  refreshCredential,
  shouldRefresh,
} from '../refresh.js';

const MS_PER_DAY = 24 * 60 * 60 * 1000;

/** 固定の現在時刻（2026-07-01T00:00:00Z）。 */
const NOW = Date.parse('2026-07-01T00:00:00Z');

const SERVICE: RefreshServiceConfig = {
  id: 'refresh-1',
  type: 'OID4VCIRefreshService2025',
  url: 'https://issuer.example/refresh',
};

/** 指定 exp（ISO）と refreshService を持つ最小 VC を作る。 */
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

/** JSON 本文 `{ credential: rawVc }` を 200 で返す FetchLike を作る。 */
function jsonFetch(rawVc: string, status = 200): FetchLike {
  return async () =>
    new Response(JSON.stringify({ credential: rawVc }), {
      status,
      headers: { 'Content-Type': 'application/json' },
    });
}

/** 受領した生 VC 文字列（JSON）をそのまま VC としてパースする verifyRefreshed スタブ。 */
const verifyOk: RefreshDependencies['verifyRefreshed'] = async (raw) =>
  JSON.parse(raw) as VerifiableCredential;

/** 新 VC（旧より遅い exp を持つ）。 */
const NEW_VC: VerifiableCredential = {
  '@context': ['https://www.w3.org/ns/credentials/v2'],
  type: ['VerifiableCredential', 'IdentityCredential'],
  issuer: 'did:example:issuer',
  credentialSubject: { id: 'did:example:holder' },
  issuanceDate: '2026-07-01T00:00:00Z',
  expirationDate: new Date(NOW + 365 * MS_PER_DAY).toISOString(),
  id: 'urn:vc:new',
};

describe('shouldRefresh（自動更新トリガー）', () => {
  it('しきい値内（exp まで 5 日 < 7 日）かつ autoRefresh=true で true', () => {
    const vc = makeVc();
    expect(shouldRefresh(vc, { vcType: 'IdentityCredential', autoRefresh: true }, NOW)).toBe(true);
  });

  it('autoRefresh=false なら常に false', () => {
    const vc = makeVc();
    expect(shouldRefresh(vc, { vcType: 'IdentityCredential', autoRefresh: false }, NOW)).toBe(
      false,
    );
  });

  it('vcType が VC の type に含まれなければ false', () => {
    const vc = makeVc();
    expect(shouldRefresh(vc, { vcType: 'OtherCredential', autoRefresh: true }, NOW)).toBe(false);
  });

  it('しきい値外（exp まで 30 日 > 7 日）なら false', () => {
    const vc = makeVc({ expirationDate: new Date(NOW + 30 * MS_PER_DAY).toISOString() });
    expect(shouldRefresh(vc, { vcType: 'IdentityCredential', autoRefresh: true }, NOW)).toBe(false);
  });

  it('expirationDate が無い（無期限）VC は false', () => {
    const vc = makeVc({ expirationDate: undefined });
    expect(shouldRefresh(vc, { vcType: 'IdentityCredential', autoRefresh: true }, NOW)).toBe(false);
  });

  it('既に期限切れの VC も対象（true）', () => {
    const vc = makeVc({ expirationDate: new Date(NOW - MS_PER_DAY).toISOString() });
    expect(shouldRefresh(vc, { vcType: 'IdentityCredential', autoRefresh: true }, NOW)).toBe(true);
  });

  it('カスタム thresholdDays を尊重する', () => {
    const vc = makeVc({ expirationDate: new Date(NOW + 20 * MS_PER_DAY).toISOString() });
    const policy = { vcType: 'IdentityCredential', autoRefresh: true, thresholdDays: 30 };
    expect(shouldRefresh(vc, policy, NOW)).toBe(true);
  });

  it('既定しきい値は 7 日', () => {
    expect(DEFAULT_REFRESH_THRESHOLD_DAYS).toBe(7);
  });
});

describe('refreshCredential（VC 入れ替え統合）', () => {
  it('しきい値内で新 VC を受領・検証し derivedFrom を付与して入れ替える', async () => {
    const deps: RefreshDependencies = {
      verifyRefreshed: verifyOk,
      fetchImpl: jsonFetch(JSON.stringify(NEW_VC)),
    };
    const result = await refreshCredential(makeVc(), { now: NOW }, deps);

    expect(result.refreshed).toBe(true);
    expect(result.credential?.id).toBe('urn:vc:new');
    // 旧 VC を指す derivedFrom が自動付与される（監査チェーン）。
    expect(result.credential?.derivedFrom).toBe('urn:vc:old');
    expect(result.warning).toBeUndefined();
  });

  it('新 VC が既に derivedFrom を持つ場合は Issuer 設定を優先する', async () => {
    const chained = { ...NEW_VC, derivedFrom: 'urn:vc:issuer-set' };
    const deps: RefreshDependencies = {
      verifyRefreshed: verifyOk,
      fetchImpl: jsonFetch(JSON.stringify(chained)),
    };
    const result = await refreshCredential(makeVc(), { now: NOW }, deps);
    expect(result.credential?.derivedFrom).toBe('urn:vc:issuer-set');
  });

  it('refreshService 未設定で REFRESH_SERVICE_NOT_SET（3033）', async () => {
    const vc = makeVc({ refreshService: undefined });
    const deps: RefreshDependencies = { verifyRefreshed: verifyOk, fetchImpl: jsonFetch('{}') };
    const promise = refreshCredential(vc, { now: NOW }, deps);
    await expect(promise).rejects.toBeInstanceOf(VericertsError);
    await expect(promise).rejects.toMatchObject({ code: ErrorCodes.REFRESH_SERVICE_NOT_SET });
  });

  it('しきい値未達（force なし）では入れ替えず旧 VC を返す', async () => {
    const vc = makeVc({ expirationDate: new Date(NOW + 30 * MS_PER_DAY).toISOString() });
    let called = false;
    const deps: RefreshDependencies = {
      verifyRefreshed: verifyOk,
      fetchImpl: async () => {
        called = true;
        return new Response('{}', { status: 200 });
      },
    };
    const result = await refreshCredential(vc, { now: NOW }, deps);
    expect(result.refreshed).toBe(false);
    expect(result.credential?.id).toBe('urn:vc:old');
    // エンドポイントは呼ばれない。
    expect(called).toBe(false);
  });

  it('force=true でしきい値外でも入れ替える', async () => {
    const vc = makeVc({ expirationDate: new Date(NOW + 30 * MS_PER_DAY).toISOString() });
    const deps: RefreshDependencies = {
      verifyRefreshed: verifyOk,
      fetchImpl: jsonFetch(JSON.stringify(NEW_VC)),
    };
    const result = await refreshCredential(vc, { now: NOW, force: true }, deps);
    expect(result.refreshed).toBe(true);
    expect(result.credential?.id).toBe('urn:vc:new');
  });
});

describe('refreshCredential（同意）', () => {
  it('requireHolderConsent かつ拒否で HOLDER_CONSENT_NOT_OBTAINED（3023）', async () => {
    const vc = makeVc({ refreshService: { ...SERVICE, requireHolderConsent: true } });
    const deps: RefreshDependencies = {
      verifyRefreshed: verifyOk,
      requestConsent: async () => false,
      fetchImpl: jsonFetch(JSON.stringify(NEW_VC)),
    };
    const promise = refreshCredential(vc, { now: NOW }, deps);
    await expect(promise).rejects.toMatchObject({ code: ErrorCodes.HOLDER_CONSENT_NOT_OBTAINED });
  });

  it('requireHolderConsent かつ同意で入れ替える', async () => {
    const vc = makeVc({ refreshService: { ...SERVICE, requireHolderConsent: true } });
    const deps: RefreshDependencies = {
      verifyRefreshed: verifyOk,
      requestConsent: async () => true,
      fetchImpl: jsonFetch(JSON.stringify(NEW_VC)),
    };
    const result = await refreshCredential(vc, { now: NOW }, deps);
    expect(result.refreshed).toBe(true);
  });

  it('silent=true なら同意 UI を省略して入れ替える', async () => {
    const vc = makeVc({ refreshService: { ...SERVICE, requireHolderConsent: true } });
    let consentAsked = false;
    const deps: RefreshDependencies = {
      verifyRefreshed: verifyOk,
      requestConsent: async () => {
        consentAsked = true;
        return true;
      },
      fetchImpl: jsonFetch(JSON.stringify(NEW_VC)),
    };
    const result = await refreshCredential(vc, { now: NOW, silent: true }, deps);
    expect(result.refreshed).toBe(true);
    expect(consentAsked).toBe(false);
  });
});

describe('refreshCredential: refreshService.url の公開ホスト検査', () => {
  it.each([
    'https://10.0.0.5/admin/reset',
    'https://127.0.0.1/refresh',
    'https://192.168.1.1/refresh',
    'https://169.254.169.254/latest',
    'https://localhost/refresh',
  ])('%s へは POST せず拒否する', async (url) => {
    let called = false;
    const deps: RefreshDependencies = {
      verifyRefreshed: verifyOk,
      fetchImpl: async () => {
        called = true;
        return new Response(JSON.stringify({ credential: JSON.stringify(NEW_VC) }), {
          status: 200,
        });
      },
    };
    const vc = makeVc({ refreshService: { ...SERVICE, url } });
    const result = await refreshCredential(vc, { now: NOW, force: true }, deps).catch(
      (error: unknown) => error,
    );
    expect(called).toBe(false);
    expect(result).toBeInstanceOf(VericertsError);
  });

  it('3xx 応答には追従せず（redirect: manual）、更新を採用しない', async () => {
    const inits: (RequestInit | undefined)[] = [];
    const deps: RefreshDependencies = {
      verifyRefreshed: verifyOk,
      fetchImpl: async (_url, init) => {
        inits.push(init);
        return new Response(null, { status: 302, headers: { location: 'https://10.0.0.5/x' } });
      },
    };
    const result = await refreshCredential(makeVc(), { now: NOW, force: true }, deps).catch(
      (error: unknown) => error,
    );
    expect(inits[0]?.redirect).toBe('manual');
    expect((result as { refreshed?: boolean }).refreshed).not.toBe(true);
  });
});
