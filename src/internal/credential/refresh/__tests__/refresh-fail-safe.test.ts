/**
 * refreshCredential のリフレッシュ失敗時の挙動（FO-9）のテスト。
 *
 * `refresh.test.ts` から分離している（`.linterly.yml` の 1 ファイル 300 行上限）。DI 読み取り規律
 * （クラスベース deps・監査記録失敗）と計時ウィンドウの規律（成功時破棄・時間上限・形状検証）は
 * 同じ理由で `refresh-fail-safe-window.test.ts` にさらに分離している。
 *
 * 検証内容:
 * - FO-9 の配線（`failOpenWindow` / `onPolicyEvent`）を渡さない既定では、リフレッシュ失敗が
 *   常に元のエラーとして送出される（Fail-closed）。
 * - `refreshFailure: 'keep-old'`: 同意プロンプトを省き、監査ログを記録して旧 VC を継続する
 *   （従来は無記録だったことの regression 確認）。
 * - `refreshFailure: 'discard'`: `decideFailSafe` が deny に倒すため Fail-closed（監査記録なし）。
 * - 未指定 / `refreshFailure: 'prompt'`: ユーザー同意を要求し、得られなければ Fail-closed。
 *
 * ネットワークは FetchLike スタブで注入し、実 HTTP は行わない。
 */

import { describe, expect, it } from 'bun:test';
import type { FetchLike } from '../../../auth/oid4vci/oid4vci.js';
import { ErrorCodes, VericertsError } from '../../../errors.js';
import {
  createFailOpenWindow,
  FAIL_OPEN_AUDIT_EVENTS,
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

describe('refreshCredential（失敗、FO-9 未配線 = 既定 Fail-closed）', () => {
  it('FO-9 の配線（failOpenWindow / onPolicyEvent）を渡さなければ HTTP エラーはそのまま送出される（3030）', async () => {
    const deps: RefreshDependencies = {
      verifyRefreshed: verifyOk,
      fetchImpl: jsonFetch('{}', 500),
    };
    const promise = refreshCredential(makeVc(), { now: NOW }, deps);
    await expect(promise).rejects.toMatchObject({ code: ErrorCodes.REFRESH_FAILED });
  });

  it('非 HTTPS エンドポイントは REFRESH_FAILED（3030）', async () => {
    const vc = makeVc({ refreshService: { ...SERVICE, url: 'http://issuer.example/refresh' } });
    const deps: RefreshDependencies = { verifyRefreshed: verifyOk, fetchImpl: jsonFetch('{}') };
    const promise = refreshCredential(vc, { now: NOW }, deps);
    await expect(promise).rejects.toMatchObject({ code: ErrorCodes.REFRESH_FAILED });
  });

  it('ネットワーク失敗は ISSUER_COMMUNICATION_FAILED（3004）', async () => {
    const deps: RefreshDependencies = {
      verifyRefreshed: verifyOk,
      fetchImpl: async () => {
        throw new Error('network down');
      },
    };
    const promise = refreshCredential(makeVc(), { now: NOW }, deps);
    await expect(promise).rejects.toMatchObject({
      code: ErrorCodes.ISSUER_COMMUNICATION_FAILED,
    });
  });

  it('新 VC 検証失敗は REFRESHED_VC_VERIFICATION_FAILED（3022）', async () => {
    const deps: RefreshDependencies = {
      verifyRefreshed: async () => {
        throw new VericertsError(ErrorCodes.SIG_INVALID);
      },
      fetchImpl: jsonFetch(JSON.stringify(NEW_VC)),
    };
    const promise = refreshCredential(makeVc(), { now: NOW }, deps);
    await expect(promise).rejects.toMatchObject({
      code: ErrorCodes.REFRESHED_VC_VERIFICATION_FAILED,
    });
  });

  it('応答に credential が無い場合も REFRESH_FAILED（3030）', async () => {
    const deps: RefreshDependencies = {
      verifyRefreshed: verifyOk,
      fetchImpl: jsonFetch(''),
    };
    // jsonFetch('') は { credential: "" } を返すため空文字は拒否される。
    const promise = refreshCredential(makeVc(), { now: NOW }, deps);
    await expect(promise).rejects.toMatchObject({ code: ErrorCodes.REFRESH_FAILED });
  });
});

describe('refreshCredential（FO-9: リフレッシュ失敗時の override）', () => {
  /** 監査ログ記録先のスタブ。呼ばれたレコードをそのまま蓄積する。 */
  function recordingAuditSink(): {
    readonly sink: (record: FailSafeAuditRecord) => void;
    readonly records: FailSafeAuditRecord[];
  } {
    const records: FailSafeAuditRecord[] = [];
    return { sink: (record) => records.push(record), records };
  }

  it('refreshFailure: keep-old は同意プロンプトを省いて旧 VC を継続し、監査ログを記録する（regression: 従来は無記録だった）', async () => {
    const deps: RefreshDependencies = {
      verifyRefreshed: verifyOk,
      fetchImpl: jsonFetch('{}', 500),
    };
    const { sink, records } = recordingAuditSink();
    let consentAsked = false;
    const result = await refreshCredential(
      makeVc(),
      { now: NOW, failSafePolicy: { refreshFailure: 'keep-old' } },
      {
        ...deps,
        failOpenWindow: createFailOpenWindow(),
        onPolicyEvent: sink,
        requestFailSafeConsent: () => {
          consentAsked = true;
          return true;
        },
      },
    );

    expect(result.refreshed).toBe(false);
    expect(result.credential?.id).toBe('urn:vc:old');
    expect(result.warning?.policyEvent).toBe('FO-9');
    // keep-old は同意プロンプトを省く。
    expect(consentAsked).toBe(false);
    // 監査ログは必須(従来はここが無記録だった)。
    expect(records).toHaveLength(1);
    expect(records[0]).toMatchObject({
      policy_event: 'FO-9',
      audit_event: FAIL_OPEN_AUDIT_EVENTS['FO-9'],
      user_consent: 'accepted',
      override: { refreshFailure: 'keep-old' },
    });
  });

  it('vc_id は SDK 側で vc.id から自動導出しない（regression）', async () => {
    // `vc.id`（'urn:vc:old'、W3C VC の URI）を監査レコードの `vc_id`（Wallet 内識別子）へ
    // 補完しないことを確認する。呼び出し側が `auditContext.vc_id` を渡していない場合、
    // 監査レコードに `vc_id` は含まれない。
    const deps: RefreshDependencies = {
      verifyRefreshed: verifyOk,
      fetchImpl: jsonFetch('{}', 500),
    };
    const { sink, records } = recordingAuditSink();
    await refreshCredential(
      makeVc(),
      { now: NOW, failSafePolicy: { refreshFailure: 'keep-old' } },
      { ...deps, failOpenWindow: createFailOpenWindow(), onPolicyEvent: sink },
    );
    expect(records).toHaveLength(1);
    expect(records[0]?.vc_id).toBeUndefined();
  });

  it('auditContext.vc_id を明示すれば監査レコードにそのまま反映される', async () => {
    const deps: RefreshDependencies = {
      verifyRefreshed: verifyOk,
      fetchImpl: jsonFetch('{}', 500),
    };
    const { sink, records } = recordingAuditSink();
    await refreshCredential(
      makeVc(),
      {
        now: NOW,
        failSafePolicy: { refreshFailure: 'keep-old' },
        auditContext: { vc_id: 'wallet-internal-id-123' },
      },
      { ...deps, failOpenWindow: createFailOpenWindow(), onPolicyEvent: sink },
    );
    expect(records[0]?.vc_id).toBe('wallet-internal-id-123');
  });

  it('refreshFailure: keep-old でも監査ログ記録先（onPolicyEvent）が無ければ Fail-closed になる', async () => {
    const deps: RefreshDependencies = {
      verifyRefreshed: verifyOk,
      fetchImpl: jsonFetch('{}', 500),
      failOpenWindow: createFailOpenWindow(),
      // onPolicyEvent は意図的に注入しない。
    };
    const promise = refreshCredential(
      makeVc(),
      { now: NOW, failSafePolicy: { refreshFailure: 'keep-old' } },
      deps,
    );
    await expect(promise).rejects.toMatchObject({ code: ErrorCodes.REFRESH_FAILED });
  });

  it('refreshFailure: discard は Fail-closed になる（旧 VC を継続させない）', async () => {
    const deps: RefreshDependencies = {
      verifyRefreshed: verifyOk,
      fetchImpl: jsonFetch('{}', 500),
    };
    const { sink, records } = recordingAuditSink();
    const promise = refreshCredential(
      makeVc(),
      { now: NOW, failSafePolicy: { refreshFailure: 'discard' } },
      { ...deps, failOpenWindow: createFailOpenWindow(), onPolicyEvent: sink },
    );
    await expect(promise).rejects.toMatchObject({ code: ErrorCodes.REFRESH_FAILED });
    // discard は escalate と同じく deny 判定であり、Fail-open を選択していないため監査記録もしない
    // （`failsafe-policy/gate.ts` の規律）。
    expect(records).toHaveLength(0);
  });

  it('refreshFailure 未指定は同意を要求し、同意すれば旧 VC を継続して記録する', async () => {
    const deps: RefreshDependencies = {
      verifyRefreshed: verifyOk,
      fetchImpl: jsonFetch('{}', 500),
    };
    const { sink, records } = recordingAuditSink();
    let consentAsked = false;
    const result = await refreshCredential(
      makeVc(),
      { now: NOW },
      {
        ...deps,
        failOpenWindow: createFailOpenWindow(),
        onPolicyEvent: sink,
        requestFailSafeConsent: () => {
          consentAsked = true;
          return true;
        },
      },
    );
    expect(consentAsked).toBe(true);
    expect(result.refreshed).toBe(false);
    expect(result.credential?.id).toBe('urn:vc:old');
    expect(records[0]).toMatchObject({ user_consent: 'accepted' });
  });

  it('refreshFailure: prompt は同意コールバック未指定なら Fail-closed（同意を得る手段が無い）', async () => {
    const deps: RefreshDependencies = {
      verifyRefreshed: verifyOk,
      fetchImpl: jsonFetch('{}', 500),
      failOpenWindow: createFailOpenWindow(),
      // requestFailSafeConsent は注入しない。
    };
    const promise = refreshCredential(
      makeVc(),
      { now: NOW, failSafePolicy: { refreshFailure: 'prompt' } },
      deps,
    );
    await expect(promise).rejects.toMatchObject({ code: ErrorCodes.REFRESH_FAILED });
  });

  it('refreshFailure: prompt でユーザーが同意しなければ Fail-closed かつ rejected を記録する', async () => {
    const deps: RefreshDependencies = {
      verifyRefreshed: verifyOk,
      fetchImpl: jsonFetch('{}', 500),
    };
    const { sink, records } = recordingAuditSink();
    const promise = refreshCredential(
      makeVc(),
      { now: NOW, failSafePolicy: { refreshFailure: 'prompt' } },
      {
        ...deps,
        failOpenWindow: createFailOpenWindow(),
        onPolicyEvent: sink,
        requestFailSafeConsent: () => false,
      },
    );
    await expect(promise).rejects.toMatchObject({ code: ErrorCodes.REFRESH_FAILED });
    expect(records).toHaveLength(1);
    expect(records[0]).toMatchObject({ policy_event: 'FO-9', user_consent: 'rejected' });
  });
});
