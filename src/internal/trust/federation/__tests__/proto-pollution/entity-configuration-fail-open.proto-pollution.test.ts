/**
 * FO-6 の依存注入の `Object.prototype` 汚染耐性テスト。
 *
 * FO-6 は明示的なオプトインであり、`failOpenWindow`（時間上限）・`onPolicyEvent`（監査記録先）・
 * `requestConsent`（同意の取得）のいずれも**渡していない**呼び出しは fail-closed で
 * なければならない。これらをプロトタイプ鎖で読むと、当該オプションを省略した正当な呼び出しが
 * 汚染値だけで fail-open に反転し、Entity Configuration の取得失敗が stale なキャッシュで通過する
 * （監査レコードの宛先まで攻撃者が選べる）。
 *
 * 3 つの読み取り口を**個別に**汚染する。まとめて汚染すると「どれか 1 つが own 限定なら通る」
 * ゆるい検査になり、残り 2 つの退行を見逃すため。
 */

import { describe, expect, it } from 'bun:test';
import { withPollutedPrototypeAsync } from '../../../../__tests__/prototype-pollution.fixtures.js';
import { ErrorCodes, VericertsError } from '../../../../errors.js';
import type { FailSafeAuditRecord } from '../../../../failsafe-policy/index.js';
import { createFailOpenWindow } from '../../../../failsafe-policy/index.js';
import { createFederationStatementCache } from '../../cache/statement-cache.js';
import {
  type ResolveEntityConfigurationDeps,
  resolveEntityConfiguration,
} from '../../entity-configuration.js';
import { LEAF_KEY, NOW_SECONDS, signStatement, toJwk } from '../federation-fixtures.js';

const ENTITY_ID = 'https://leaf.example.eu';
const WELL_KNOWN = `${ENTITY_ID}/.well-known/openid-federation`;

/** 取得は常に 503。stale なキャッシュだけが判断材料として残る状況を作る。 */
const OFFLINE_FETCH = (async (_input: string | URL): Promise<Response> =>
  new Response('unavailable', { status: 503 })) as typeof fetch;

/** 記録された監査レコード（汚染したシンクに届いていないことの確認用）。 */
const records: FailSafeAuditRecord[] = [];

/** 監査ログの記録先（`onPolicyEvent`）。 */
function sink(record: FailSafeAuditRecord): void {
  records.push(record);
}

/** `exp` 内だが TTL 切れ（stale）のキャッシュを 1 件持つ依存注入。 */
function staleDeps(): ResolveEntityConfigurationDeps {
  const jwt = signStatement(
    LEAF_KEY,
    {
      iss: ENTITY_ID,
      sub: ENTITY_ID,
      iat: NOW_SECONDS - 3600,
      exp: NOW_SECONDS + 4000,
      jwks: { keys: [toJwk(LEAF_KEY, 'leaf-1')] },
    },
    { kid: 'leaf-1' },
  );
  const statementCache = createFederationStatementCache(() => NOW_SECONDS);
  // TTL 60 秒で 120 秒前に格納したので、検証時刻 `NOW_SECONDS` では TTL 切れ（warm）になる。
  statementCache.set(WELL_KNOWN, jwt, 60, NOW_SECONDS - 120);
  return { statementCache, fetchFn: OFFLINE_FETCH, now: (): number => NOW_SECONDS * 1000 };
}

/**
 * 1 つだけ汚染し、残りは明示的に渡した状態で解決を試みる。
 *
 * @param polluted `Object.prototype` に仕込む 1 件。
 * @param explicit 明示的に渡す残りの FO-6 オプション。
 */
async function resolveWithPollution(
  polluted: Readonly<Record<string, unknown>>,
  explicit: ResolveEntityConfigurationDeps,
): Promise<unknown> {
  records.length = 0;
  let caught: unknown;
  await withPollutedPrototypeAsync(polluted, async () => {
    try {
      await resolveEntityConfiguration(ENTITY_ID, { ...staleDeps(), ...explicit });
    } catch (error) {
      caught = error;
    }
  });
  return caught;
}

/** 5011 のまま伝播した（FO-6 が成立しなかった）ことを検証する。 */
function expectFailClosed(caught: unknown): void {
  expect(caught).toBeInstanceOf(VericertsError);
  expect((caught as VericertsError).code).toBe(ErrorCodes.FEDERATION_FETCH_FAILED);
  expect(records).toEqual([]);
}

describe('FO-6 の依存注入 汚染耐性', () => {
  it('継承した failOpenWindow では FO-6 は成立しない', async () => {
    const caught = await resolveWithPollution(
      { failOpenWindow: createFailOpenWindow() },
      { onPolicyEvent: sink, requestConsent: (): boolean => true },
    );
    expectFailClosed(caught);
  });

  it('継承した onPolicyEvent では監査記録先として採用しない', async () => {
    const caught = await resolveWithPollution(
      { onPolicyEvent: sink },
      { failOpenWindow: createFailOpenWindow(), requestConsent: (): boolean => true },
    );
    expectFailClosed(caught);
  });

  it('継承した requestConsent ではユーザー同意として採用しない', async () => {
    const caught = await resolveWithPollution(
      { requestConsent: (): boolean => true },
      { failOpenWindow: createFailOpenWindow(), onPolicyEvent: sink },
    );
    // 同意不能は `rejected` として記録されるため、記録の有無ではなく通過しないことを見る。
    expect(caught).toBeInstanceOf(VericertsError);
    expect((caught as VericertsError).code).toBe(ErrorCodes.FEDERATION_FETCH_FAILED);
    expect(records.map((record) => record.user_consent)).toEqual(['rejected']);
  });
});

/**
 * `createEntityConfigurationFailOpen` の `window.allow` / `window.clear` 鎖読みガード耐性テスト
 * （`etsi-tsl/fail-open.ts` の FO-5 で見つかったのと同一のバグクラスが FO-6 にも
 * あるかの棚卸し）。
 *
 * `deps.failOpenWindow` 自体は own プロパティとして正しく渡されていても、その中身
 * `window.allow` / `window.clear` を素のドットアクセスで検証すると `Object.prototype.allow` /
 * `.clear` の汚染を拾ってしまう。own の allow/clear を持たない不正な形状（`failOpenWindow: {}`）
 * を渡す呼び出し元が、汚染された `Object.prototype` 経由で攻撃者の関数をウィンドウとして受け
 * 入れてしまわないことを検証する。
 */
describe('FO-6 window.allow/window.clear 鎖読みガード耐性', () => {
  it('own の allow/clear を持たないウィンドウは Object.prototype 汚染下でも受理しない', async () => {
    const caught = await resolveWithPollution(
      {
        allow: (): boolean => true,
        clear: (): void => {
          throw new Error('attacker clear must not be called');
        },
      },
      {
        // own プロパティとしては正しく渡しているが、中身が空オブジェクト（own の allow/clear
        // を持たない）。`nonObjectPrototypeProperty` で検証していれば Object.prototype 由来の
        // allow/clear は「未指定」として弾かれ、FO-6 は不活性のままになる。
        failOpenWindow: {} as ReturnType<typeof createFailOpenWindow>,
        onPolicyEvent: sink,
        requestConsent: (): boolean => true,
      },
    );
    expectFailClosed(caught);
  });
});
