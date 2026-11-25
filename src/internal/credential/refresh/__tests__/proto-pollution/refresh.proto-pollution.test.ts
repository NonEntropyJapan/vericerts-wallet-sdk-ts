/**
 * VC リフレッシュの `Object.prototype` 汚染耐性テスト。
 *
 * `opts.silent` をプロトタイプ鎖で読むと、`silent` を**渡していない**正当な呼び出しでも
 * 汚染値が「同意プロンプトを省略する」を満たし、`requireHolderConsent` を宣言した
 * サービスの Holder 同意がユーザー操作なしで飛ぶ。
 *
 * `opts.force` / `opts.thresholdDays` / `opts.now` も同じ経路で、期限しきい値の検査そのものが
 * 飛んだり、攻撃者の選んだ時刻・しきい値で入れ替え要否が評価されたりする。
 */

import { describe, expect, it } from 'bun:test';
import { withPollutedPrototypeAsync } from '../../../../__tests__/prototype-pollution.fixtures.js';
import type { FetchLike } from '../../../../auth/oid4vci/oid4vci.js';
import { ErrorCodes } from '../../../../errors.js';
import type { RefreshServiceConfig, VerifiableCredential } from '../../../vc/vc.js';
import { type RefreshDependencies, refreshCredential } from '../../refresh.js';

const MS_PER_DAY = 24 * 60 * 60 * 1000;
const NOW = Date.parse('2026-07-01T00:00:00Z');

const SERVICE: RefreshServiceConfig = {
  id: 'refresh-1',
  type: 'OID4VCIRefreshService2025',
  url: 'https://issuer.example/refresh',
};

const NEW_VC: VerifiableCredential = {
  '@context': ['https://www.w3.org/ns/credentials/v2'],
  type: ['VerifiableCredential', 'IdentityCredential'],
  issuer: 'did:example:issuer',
  credentialSubject: { id: 'did:example:holder' },
  issuanceDate: '2026-06-30T00:00:00Z',
  id: 'urn:vc:new',
};

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

function jsonFetch(rawVc: string): FetchLike {
  return async () =>
    new Response(JSON.stringify({ credential: rawVc }), {
      status: 200,
      headers: { 'Content-Type': 'application/json' },
    });
}

const verifyOk = async (): Promise<VerifiableCredential> => NEW_VC;

describe('refreshCredential の Object.prototype 汚染耐性', () => {
  it('継承した silent で Holder 同意プロンプトを省略できない', async () => {
    const vc = makeVc({ refreshService: { ...SERVICE, requireHolderConsent: true } });
    const deps: RefreshDependencies = {
      verifyRefreshed: verifyOk,
      requestConsent: async () => false,
      fetchImpl: jsonFetch(JSON.stringify(NEW_VC)),
    };
    // `silent` は渡していない。汚染値を拾えば同意が飛んで入れ替えが成功してしまう。
    await expect(
      withPollutedPrototypeAsync({ silent: true }, () => refreshCredential(vc, { now: NOW }, deps)),
    ).rejects.toMatchObject({ code: ErrorCodes.HOLDER_CONSENT_NOT_OBTAINED });
  });

  it('継承した silent は同意コールバック未提供時の拒否も飛ばさない', async () => {
    const vc = makeVc({ refreshService: { ...SERVICE, requireHolderConsent: true } });
    const deps: RefreshDependencies = {
      verifyRefreshed: verifyOk,
      fetchImpl: jsonFetch(JSON.stringify(NEW_VC)),
    };
    await expect(
      withPollutedPrototypeAsync({ silent: true }, () => refreshCredential(vc, { now: NOW }, deps)),
    ).rejects.toMatchObject({ code: ErrorCodes.HOLDER_CONSENT_NOT_OBTAINED });
  });

  it('継承した force はしきい値検査を飛ばさない', async () => {
    // 期限まで 30 日 ＝ 既定しきい値の外。force なしなら入れ替えないのが正。
    const vc = makeVc({ expirationDate: new Date(NOW + 30 * MS_PER_DAY).toISOString() });
    let called = false;
    const deps: RefreshDependencies = {
      verifyRefreshed: verifyOk,
      fetchImpl: async () => {
        called = true;
        return new Response('{}', { status: 200 });
      },
    };
    const result = await withPollutedPrototypeAsync({ force: true }, () =>
      refreshCredential(vc, { now: NOW }, deps),
    );
    expect(result.refreshed).toBe(false);
    expect(result.credential?.id).toBe('urn:vc:old');
    expect(called).toBe(false);
  });

  it('継承した thresholdDays はしきい値を広げない', async () => {
    const vc = makeVc({ expirationDate: new Date(NOW + 30 * MS_PER_DAY).toISOString() });
    const deps: RefreshDependencies = {
      verifyRefreshed: verifyOk,
      fetchImpl: jsonFetch(JSON.stringify(NEW_VC)),
    };
    const result = await withPollutedPrototypeAsync({ thresholdDays: 365 }, () =>
      refreshCredential(vc, { now: NOW }, deps),
    );
    expect(result.refreshed).toBe(false);
  });

  it('明示的に渡した silent / force は従来どおり効く（正常系）', async () => {
    const vc = makeVc({ refreshService: { ...SERVICE, requireHolderConsent: true } });
    const deps: RefreshDependencies = {
      verifyRefreshed: verifyOk,
      requestConsent: async () => false,
      fetchImpl: jsonFetch(JSON.stringify(NEW_VC)),
    };
    // silent: true を明示すれば同意プロンプトは省略され、入れ替えが進む。
    const result = await refreshCredential(vc, { now: NOW, silent: true }, deps);
    expect(result.refreshed).toBe(true);
    expect(result.credential?.id).toBe('urn:vc:new');

    const far = makeVc({ expirationDate: new Date(NOW + 30 * MS_PER_DAY).toISOString() });
    const forced = await refreshCredential(
      far,
      { now: NOW, force: true },
      {
        verifyRefreshed: verifyOk,
        fetchImpl: jsonFetch(JSON.stringify(NEW_VC)),
      },
    );
    expect(forced.refreshed).toBe(true);
  });
});
