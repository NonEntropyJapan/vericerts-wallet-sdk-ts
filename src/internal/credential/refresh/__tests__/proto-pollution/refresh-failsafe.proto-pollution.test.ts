/**
 * VC リフレッシュ失敗時の FO-9 ゲート配線（`opts.failSafePolicy` / `opts.auditContext` /
 * `deps.requestFailSafeConsent` / `deps.onPolicyEvent` / `deps.failOpenWindow`）の
 * `Object.prototype` 汚染耐性テスト。
 *
 * `applyRefreshFailSafe`（`refresh-fail-safe.ts`）はこれらを読む際、`failSafePolicy` /
 * `auditContext`（純データ）は `ownProperty` で自身のプロパティに限って読み、`requestFailSafeConsent` /
 * `onPolicyEvent`（関数値 DI）と `failOpenWindow`（クラスインスタンスであり得る）は
 * `nonObjectPrototypeProperty` で `Object.prototype` 由来だけを弾く（`entity-configuration-fail-open.ts`
 * の FO-6 と同じ規律）。継承値を拾うと、これらを**省略した**正当な呼び出しが緩い側へ倒れる:
 *
 * - `failSafePolicy`: 汚染した `refreshFailure: 'keep-old'` が同意プロンプトを無断で省略する。
 * - `onPolicyEvent`: 汚染値が「監査シンクあり」に化け、監査記録を残さず Fail-open が成立する。
 * - `requestFailSafeConsent`: 汚染値が同意ありに化け、ユーザー操作なしで Fail-open が成立する。
 * - `failOpenWindow`: 汚染値が時間上限ウィンドウに化け、未注入のまま FO-9 が発動する。
 * - `auditContext`: 汚染した相関情報（`verifier` 等）が監査レコードに紛れ込む。
 *
 * いずれも「その任意プロパティを省略した正当な呼び出し」で検証する（明示指定は汚染と無関係に
 * 通るため無価値）。
 */

import { describe, expect, it } from 'bun:test';
import {
  withPollutedPrototypeAccessorAsync,
  withPollutedPrototypeAsync,
} from '../../../../__tests__/prototype-pollution.fixtures.js';
import { ErrorCodes } from '../../../../errors.js';
import {
  createFailOpenWindow,
  type FailSafeAuditRecord,
} from '../../../../failsafe-policy/index.js';
import type { RefreshServiceConfig, VerifiableCredential } from '../../../vc/vc.js';
import { type RefreshDependencies, refreshCredential } from '../../refresh.js';

const NOW = Date.parse('2026-07-01T00:00:00Z');

const SERVICE: RefreshServiceConfig = {
  id: 'refresh-1',
  type: 'OID4VCIRefreshService2025',
  url: 'https://issuer.example/refresh',
};

/** しきい値内（期限切れ）の旧 VC。 */
function makeVc(): VerifiableCredential {
  return {
    '@context': ['https://www.w3.org/ns/credentials/v2'],
    type: ['VerifiableCredential', 'IdentityCredential'],
    issuer: 'did:example:issuer',
    credentialSubject: { id: 'did:example:holder' },
    issuanceDate: '2026-01-01T00:00:00Z',
    expirationDate: new Date(NOW - 24 * 60 * 60 * 1000).toISOString(),
    id: 'urn:vc:old',
    refreshService: SERVICE,
  };
}

/** 常に HTTP 500 を返し、リフレッシュを失敗させる。 */
const failingDeps: Pick<RefreshDependencies, 'verifyRefreshed' | 'fetchImpl'> = {
  verifyRefreshed: async (raw) => JSON.parse(raw) as VerifiableCredential,
  fetchImpl: async () => new Response('{}', { status: 500 }),
};

describe('refreshCredential の FO-9 配線の Object.prototype 汚染耐性', () => {
  it('継承した failSafePolicy.refreshFailure(keep-old) は同意プロンプトを省略させない', async () => {
    let consentAsked = false;
    const deps: RefreshDependencies = {
      ...failingDeps,
      failOpenWindow: createFailOpenWindow(),
      onPolicyEvent: () => {},
      requestFailSafeConsent: () => {
        consentAsked = true;
        return true;
      },
    };
    // `opts.failSafePolicy` は渡していない。汚染値を拾えば keep-old と誤認し同意を求めない。
    const result = await withPollutedPrototypeAsync(
      { failSafePolicy: { refreshFailure: 'keep-old' } },
      () => refreshCredential(makeVc(), { now: NOW }, deps),
    );
    expect(consentAsked).toBe(true);
    expect(result.credential?.id).toBe('urn:vc:old');
  });

  it('継承した onPolicyEvent は監査記録先ありに化けず FO-9 を成立させない', async () => {
    const deps: RefreshDependencies = {
      ...failingDeps,
      failOpenWindow: createFailOpenWindow(),
      requestFailSafeConsent: () => true,
      // `onPolicyEvent` は注入していない。
    };
    const promise = withPollutedPrototypeAsync({ onPolicyEvent: () => {} }, () =>
      refreshCredential(
        makeVc(),
        { now: NOW, failSafePolicy: { refreshFailure: 'keep-old' } },
        deps,
      ),
    );
    await expect(promise).rejects.toMatchObject({ code: ErrorCodes.REFRESH_FAILED });
  });

  it('継承した requestFailSafeConsent は同意取得済みに化けず FO-9 を成立させない', async () => {
    const deps: RefreshDependencies = {
      ...failingDeps,
      failOpenWindow: createFailOpenWindow(),
      onPolicyEvent: () => {},
      // `requestFailSafeConsent` は注入していない（未指定 / prompt は同意必須）。
    };
    const promise = withPollutedPrototypeAsync({ requestFailSafeConsent: () => true }, () =>
      refreshCredential(makeVc(), { now: NOW }, deps),
    );
    await expect(promise).rejects.toMatchObject({ code: ErrorCodes.REFRESH_FAILED });
  });

  it('継承した failOpenWindow は時間上限ウィンドウとして採用されず FO-9 を発動させない', async () => {
    const deps: RefreshDependencies = {
      ...failingDeps,
      onPolicyEvent: () => {},
      requestFailSafeConsent: () => true,
      // `failOpenWindow` は注入していない（未注入 = FO-9 は明示的オプトインが必要）。
    };
    const promise = withPollutedPrototypeAsync(
      { failOpenWindow: { allow: () => true, clear: () => {} } },
      () =>
        refreshCredential(
          makeVc(),
          { now: NOW, failSafePolicy: { refreshFailure: 'keep-old' } },
          deps,
        ),
    );
    await expect(promise).rejects.toMatchObject({ code: ErrorCodes.REFRESH_FAILED });
  });

  it('継承した auditContext は監査レコードへ紛れ込まない', async () => {
    const records: FailSafeAuditRecord[] = [];
    const deps: RefreshDependencies = {
      ...failingDeps,
      failOpenWindow: createFailOpenWindow(),
      onPolicyEvent: (record) => {
        records.push(record);
      },
    };
    // `opts.auditContext` は渡していない。汚染値を拾うと監査レコードの `verifier` に紛れ込む。
    const result = await withPollutedPrototypeAsync(
      { auditContext: { verifier: 'attacker-hash' } },
      () =>
        refreshCredential(
          makeVc(),
          { now: NOW, failSafePolicy: { refreshFailure: 'keep-old' } },
          deps,
        ),
    );
    expect(result.credential?.id).toBe('urn:vc:old');
    expect(records).toHaveLength(1);
    expect(records[0]?.verifier).toBeUndefined();
  });

  it('own の allow/clear を持たない failOpenWindow は Object.prototype 汚染下でも受理しない', async () => {
    // `deps.failOpenWindow` 自体は own プロパティとして正しく渡しているが、中身が空オブジェクト
    // （own の allow/clear を持たない）。`window.allow` / `window.clear` を素のドットアクセスで
    // 検証すると Object.prototype 汚染を拾い、攻撃者の allow が常に true を返して FO-9 が
    // 無条件に成立してしまう（時間上限チェックの回避）。
    const deps: RefreshDependencies = {
      ...failingDeps,
      failOpenWindow: {} as ReturnType<typeof createFailOpenWindow>,
      onPolicyEvent: () => {},
      requestFailSafeConsent: () => true,
    };
    const promise = withPollutedPrototypeAsync(
      {
        allow: (): boolean => true,
        clear: (): void => {
          throw new Error('attacker clear must not be called');
        },
      },
      () =>
        refreshCredential(
          makeVc(),
          { now: NOW, failSafePolicy: { refreshFailure: 'keep-old' } },
          deps,
        ),
    );
    await expect(promise).rejects.toMatchObject({ code: ErrorCodes.REFRESH_FAILED });
  });

  it('継承した Object.prototype.vc_id は監査レコードの vc_id に紛れ込まない（own vc_id を持たない正当な auditContext）', async () => {
    const records: FailSafeAuditRecord[] = [];
    const deps: RefreshDependencies = {
      ...failingDeps,
      failOpenWindow: createFailOpenWindow(),
      onPolicyEvent: (record) => {
        records.push(record);
      },
    };
    // `opts.auditContext` は own の `vc_id` を持たない正当な呼び出し（`verifier` のみ指定）。
    // 汚染前の実装は `optsAuditContext?.vc_id` を鎖読みしており、own の `vc_id` を持たない
    // 正当な auditContext でも `Object.prototype.vc_id` の汚染値を採用してしまっていた。
    const result = await withPollutedPrototypeAsync({ vc_id: 'attacker-vc-id' }, () =>
      refreshCredential(
        makeVc(),
        {
          now: NOW,
          failSafePolicy: { refreshFailure: 'keep-old' },
          auditContext: { verifier: 'legit-verifier-hash' },
        },
        deps,
      ),
    );
    expect(result.credential?.id).toBe('urn:vc:old');
    expect(records).toHaveLength(1);
    expect(records[0]?.vc_id).toBeUndefined();
    expect(records[0]?.verifier).toBe('legit-verifier-hash');
  });

  it('継承した service.url は FO-9 の計時キーに採用されず、評価自体をスキップして元のエラーを送出する（regression）', async () => {
    // `id` を持たず、`refreshService` も own の `url` を持たない VC。
    // `callRefreshEndpoint` が own 限定で `url` を読んで REFRESH_FAILED（3030）を投げ、
    // catch 節（FO-9 評価）へ到達する。
    const serviceWithoutOwnUrl = {
      id: 'refresh-1',
      type: 'OID4VCIRefreshService2025',
    } as unknown as RefreshServiceConfig;
    const vc: VerifiableCredential = {
      '@context': ['https://www.w3.org/ns/credentials/v2'],
      type: ['VerifiableCredential', 'IdentityCredential'],
      issuer: 'did:example:issuer',
      credentialSubject: { id: 'did:example:holder' },
      issuanceDate: '2026-01-01T00:00:00Z',
      expirationDate: new Date(NOW - 24 * 60 * 60 * 1000).toISOString(),
      // `id` は意図的に持たない（計時キーのもう一方の候補も無い）。
      refreshService: serviceWithoutOwnUrl,
    };
    const deps: RefreshDependencies = {
      ...failingDeps,
      failOpenWindow: createFailOpenWindow(),
      onPolicyEvent: () => {},
      requestFailSafeConsent: () => true,
    };
    let callCount = 0;
    // getter 汚染: 呼び出しのたびに別の文字列を返す（毎回新しいウィンドウが開く鎖読みの欠陥を
    // 再現する）。`service.url` を own 限定で読めば、そもそもこの汚染値には到達しない。
    const promise = withPollutedPrototypeAccessorAsync(
      {
        url: () => {
          callCount += 1;
          return `https://attacker.example/${callCount}`;
        },
      },
      () =>
        refreshCredential(vc, { now: NOW, failSafePolicy: { refreshFailure: 'keep-old' } }, deps),
    );
    // `failSafePolicy.refreshFailure: 'keep-old'` と FO-9 の依存一式を渡していても、計時キーが
    // own 限定で取得できないため FO-9 は評価されず、`REFRESH_FAILED`（3030）がそのまま送出される
    // （Fail-open へ倒れない）。
    await expect(promise).rejects.toMatchObject({ code: ErrorCodes.REFRESH_FAILED });
  });
});
