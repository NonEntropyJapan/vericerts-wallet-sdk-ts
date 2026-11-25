/**
 * refreshCredential の FO-9 のうち、関数値 DI の読み取り規律と
 * 計時ウィンドウ（`FailOpenWindow`）の規律のテスト（regression）。
 *
 * `refresh-fail-safe.test.ts` から分離している（`.linterly.yml` の 1 ファイル 300 行上限）。
 *
 * 検証内容:
 * - プロトタイプメソッドで実装したクラスベース `deps`（`onPolicyEvent` / `requestFailSafeConsent`）
 *   でも FO-9 が成立する（own 限定読みだと無言で不活性化していたことの regression）。
 * - `onPolicyEvent` が例外を投げた場合は記録失敗として扱い Fail-closed に倒れる。
 * - リフレッシュ成功時に計時ウィンドウを破棄する（破棄しないと復旧後も計時が残り即座に時間上限
 *   超過になる）。
 * - 60 秒の時間上限を超えると Fail-closed に倒れる。
 * - `failOpenWindow` が `clear` を関数として持たない場合、成功パスはクラッシュしない（形状検証）。
 *
 * ネットワークは FetchLike スタブで注入し、実 HTTP は行わない。
 */

import { describe, expect, it } from 'bun:test';
import type { FetchLike } from '../../../auth/oid4vci/oid4vci.js';
import { ErrorCodes } from '../../../errors.js';
import {
  createFailOpenWindow,
  type FailOpenWindow,
  type FailSafeAuditRecord,
} from '../../../failsafe-policy/index.js';
import type { RefreshServiceConfig, VerifiableCredential } from '../../vc/vc.js';
import { type RefreshDependencies, refreshCredential } from '../refresh.js';

const MS_PER_DAY = 24 * 60 * 60 * 1000;
const NOW = Date.parse('2026-07-01T00:00:00Z');

const SERVICE: RefreshServiceConfig = {
  id: 'refresh-1',
  type: 'OID4VCIRefreshService2025',
  url: 'https://issuer.example/refresh',
};

/** 指定 exp（ISO）と refreshService を持つ最小 VC を作る。 */
function makeVc(): VerifiableCredential {
  return {
    '@context': ['https://www.w3.org/ns/credentials/v2'],
    type: ['VerifiableCredential', 'IdentityCredential'],
    issuer: 'did:example:issuer',
    credentialSubject: { id: 'did:example:holder' },
    issuanceDate: '2026-01-01T00:00:00Z',
    expirationDate: new Date(NOW + 5 * MS_PER_DAY).toISOString(),
    id: 'urn:vc:old',
    refreshService: SERVICE,
  };
}

/** JSON 本文 `{ credential: rawVc }` を指定ステータスで返す FetchLike を作る。 */
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

describe('refreshCredential（FO-9: 関数値 DI の読み取り規律の regression）', () => {
  it('プロトタイプメソッドで実装したクラスベース deps でも FO-9 が成立する（regression: own 限定読みだと無言で不活性化していた）', async () => {
    const records: FailSafeAuditRecord[] = [];
    class ClassDeps implements RefreshDependencies {
      readonly verifyRefreshed = verifyOk;
      readonly fetchImpl = jsonFetch('{}', 500);
      readonly failOpenWindow = createFailOpenWindow();
      // 意図的にプロトタイプメソッド（クラス構文）として定義する。インスタンスフィールド
      // （アロー関数の代入）と異なり、`Object.getOwnPropertyDescriptor(deps, name)` では
      // 見えず `Object.prototype.hasOwnProperty` 経由の own 限定読みでは「未指定」に化ける。
      onPolicyEvent(record: FailSafeAuditRecord): void {
        records.push(record);
      }
      requestFailSafeConsent(): boolean {
        return true;
      }
    }
    const deps = new ClassDeps();
    // `failSafePolicy` 未指定 = `prompt` 相当（ユーザー同意を要求）。
    const result = await refreshCredential(makeVc(), { now: NOW }, deps);
    expect(result.refreshed).toBe(false);
    expect(result.credential?.id).toBe('urn:vc:old');
    expect(result.warning?.policyEvent).toBe('FO-9');
    expect(records).toHaveLength(1);
    expect(records[0]).toMatchObject({ policy_event: 'FO-9', user_consent: 'accepted' });
  });

  it('onPolicyEvent が例外を投げた場合は記録失敗として扱い Fail-closed に倒れる', async () => {
    const deps: RefreshDependencies = {
      verifyRefreshed: verifyOk,
      fetchImpl: jsonFetch('{}', 500),
      failOpenWindow: createFailOpenWindow(),
      requestFailSafeConsent: () => true,
      onPolicyEvent: () => {
        throw new Error('audit sink down');
      },
    };
    const promise = refreshCredential(
      makeVc(),
      { now: NOW, failSafePolicy: { refreshFailure: 'keep-old' } },
      deps,
    );
    await expect(promise).rejects.toMatchObject({ code: ErrorCodes.REFRESH_FAILED });
  });
});

describe('refreshCredential（FO-9: 計時ウィンドウの規律の regression）', () => {
  it('リフレッシュ成功時に計時ウィンドウを破棄する（破棄しないと復旧後も計時が残り即座に時間上限超過になる）', async () => {
    const window = createFailOpenWindow();
    const opts = { failSafePolicy: { refreshFailure: 'keep-old' as const } };
    const failingDeps: RefreshDependencies = {
      verifyRefreshed: verifyOk,
      fetchImpl: jsonFetch('{}', 500),
      failOpenWindow: window,
      onPolicyEvent: () => {},
      requestFailSafeConsent: () => true,
    };

    // 1 回目: 失敗して fail-open 通過（同じキーの計時が開始する）。
    const first = await refreshCredential(makeVc(), { ...opts, now: NOW }, failingDeps);
    expect(first.warning?.policyEvent).toBe('FO-9');

    // 2 回目（61 秒後）: 成功する。成功時に計時を破棄しなければ、以降の失敗が「同じウィンドウの
    // 継続」として扱われ即座に時間上限超過になる。
    const succeedingDeps: RefreshDependencies = {
      ...failingDeps,
      fetchImpl: jsonFetch(JSON.stringify(NEW_VC)),
    };
    const second = await refreshCredential(
      makeVc(),
      { ...opts, now: NOW + 61_000 },
      succeedingDeps,
    );
    expect(second.refreshed).toBe(true);

    // 3 回目（さらに 1 秒後）: 再び失敗。計時が破棄されていれば新しい 60 秒枠が開き、
    // fail-open が成立する（破棄されていなければ直前の枠が超過済みで Fail-closed になる）。
    const third = await refreshCredential(makeVc(), { ...opts, now: NOW + 62_000 }, failingDeps);
    expect(third.warning?.policyEvent).toBe('FO-9');
  });

  it('60 秒の時間上限を超えると Fail-closed に倒れる', async () => {
    const window = createFailOpenWindow();
    const opts = { failSafePolicy: { refreshFailure: 'keep-old' as const } };
    const deps: RefreshDependencies = {
      verifyRefreshed: verifyOk,
      fetchImpl: jsonFetch('{}', 500),
      failOpenWindow: window,
      onPolicyEvent: () => {},
      requestFailSafeConsent: () => true,
    };

    const first = await refreshCredential(makeVc(), { ...opts, now: NOW }, deps);
    expect(first.warning?.policyEvent).toBe('FO-9');

    // 61 秒後（同一キー）。ウィンドウは破棄されていないため上限超過で Fail-closed になる。
    const promise = refreshCredential(makeVc(), { ...opts, now: NOW + 61_000 }, deps);
    await expect(promise).rejects.toMatchObject({ code: ErrorCodes.REFRESH_FAILED });
  });

  it('failOpenWindow が clear を関数として持たない場合、成功パスはクラッシュせず単に破棄をスキップする', async () => {
    const window = { allow: () => true } as unknown as FailOpenWindow;
    const deps: RefreshDependencies = {
      verifyRefreshed: verifyOk,
      fetchImpl: jsonFetch(JSON.stringify(NEW_VC)),
      failOpenWindow: window,
    };
    const result = await refreshCredential(makeVc(), { now: NOW }, deps);
    expect(result.refreshed).toBe(true);
  });

  it('clear() 自体が例外を投げても成功パスは落ちず refreshed:true を返す', async () => {
    // `clear` は関数として形状検証を通るが、呼び出し時に例外を投げる（storage 障害等を模す）。
    // 破棄呼び出しを無検証で try 内に置くと、リフレッシュ自体は成功しているのに例外が外側の
    // catch に飲まれ FO-9 評価（Fail-closed へ倒れうる）に化けてしまう。
    const window = {
      allow: () => true,
      clear: () => {
        throw new Error('window store down');
      },
    } as unknown as FailOpenWindow;
    const deps: RefreshDependencies = {
      verifyRefreshed: verifyOk,
      fetchImpl: jsonFetch(JSON.stringify(NEW_VC)),
      failOpenWindow: window,
    };
    const result = await refreshCredential(makeVc(), { now: NOW }, deps);
    expect(result.refreshed).toBe(true);
    expect(result.credential?.id).toBe('urn:vc:new');
  });

  it('failOpenWindow が clear を関数として持たない場合、FO-9 も発動せず Fail-closed になる（形状検証）', async () => {
    const window = { allow: () => true } as unknown as FailOpenWindow;
    const deps: RefreshDependencies = {
      verifyRefreshed: verifyOk,
      fetchImpl: jsonFetch('{}', 500),
      failOpenWindow: window,
      onPolicyEvent: () => {},
      requestFailSafeConsent: () => true,
    };
    const promise = refreshCredential(
      makeVc(),
      { now: NOW, failSafePolicy: { refreshFailure: 'keep-old' } },
      deps,
    );
    await expect(promise).rejects.toMatchObject({ code: ErrorCodes.REFRESH_FAILED });
  });
});
