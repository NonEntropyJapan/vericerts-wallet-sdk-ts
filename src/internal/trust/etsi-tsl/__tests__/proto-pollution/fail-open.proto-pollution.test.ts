/**
 * FO-5 の依存注入の `Object.prototype` 汚染耐性テスト。
 *
 * FO-5 は明示的なオプトインであり、`failOpenWindow`（時間上限）・`onPolicyEvent`（監査記録先）・
 * `requestConsent`（同意の取得）のいずれも**渡していない**呼び出しは fail-closed で
 * なければならない。これらをプロトタイプ鎖で読むと、当該オプションを省略した正当な呼び出しが
 * 汚染値だけで fail-open に反転し、TSL の取得失敗が有効期限内のキャッシュで通過する（監査レコード
 * の宛先まで攻撃者が選べる）。`federation/__tests__/proto-pollution/entity-configuration-fail-open.
 * proto-pollution.test.ts` と同じ方針で、3 つの読み取り口を**個別に**汚染する。まとめて汚染すると
 * 「どれか 1 つが own 限定なら通る」ゆるい検査になり、残り 2 つの退行を見逃すため。
 */

import { describe, expect, it } from 'bun:test';
import { withPollutedPrototypeAsync } from '../../../../__tests__/prototype-pollution.fixtures.js';
import { ErrorCodes, VericertsError } from '../../../../errors.js';
import type { FailSafeAuditRecord } from '../../../../failsafe-policy/index.js';
import { createFailOpenWindow } from '../../../../failsafe-policy/index.js';
import { createTrustedListCache } from '../../cache.js';
import { type LoadTrustedListOptions, loadTrustedList } from '../../etsi-tsl.js';
import { CACHE_TTL_SECONDS, NOW_SECONDS, TSL_URL } from '../fail-open/harness.js';
import { makeCertificate } from '../fixtures.js';
import { signEnvelopedXml } from '../xml/xml-fixtures.js';

/** 取得は常に失敗。有効期限内のキャッシュだけが判断材料として残る状況を作る。 */
const OFFLINE_FETCHER = async (): Promise<string> => {
  throw new Error('network');
};

/**
 * 署名付きの空 TSL 本体。`resolveWithFailOpen` は署名の再検証を監査より先に行う（
 * 是正）ため、この汚染耐性テストで到達させたいのは「監査ゲートで拒否される」経路であり、
 * 署名検証自体で先に落ちてしまうと本来検証したい経路（拒否 ＝ TSL_FETCH_FAILED）に届かない。
 */
function signedEmptyTslXml(): string {
  const signer = makeCertificate({ cn: 'DE TSL Signer', kind: 'ec' });
  return signEnvelopedXml({
    bodyOpen: '<TrustServiceStatusList>',
    bodyInner: '',
    bodyClose: '</TrustServiceStatusList>',
    privateKey: signer.privateKey,
    certDer: signer.der,
    kind: 'ec',
  });
}

/** 記録された監査レコード（汚染したシンクに届いていないことの確認用）。 */
const records: FailSafeAuditRecord[] = [];

/** 監査ログの記録先（`onPolicyEvent`）。 */
function sink(record: FailSafeAuditRecord): void {
  records.push(record);
}

/** `NextUpdate`（+`CACHE_TTL_SECONDS`）内の有効なキャッシュを 1 件持つ依存注入を組み立てる。 */
function cachedDeps(): LoadTrustedListOptions {
  const cache = createTrustedListCache(() => NOW_SECONDS);
  const nextUpdate = new Date((NOW_SECONDS + CACHE_TTL_SECONDS) * 1000).toISOString();
  cache.set(
    TSL_URL,
    {
      url: TSL_URL,
      type: 'tsl',
      xml: signedEmptyTslXml(),
      signatureValid: true,
      nextUpdate,
      fetchedAt: new Date(NOW_SECONDS * 1000).toISOString(),
    },
    CACHE_TTL_SECONDS,
    NOW_SECONDS,
  );
  return { kind: 'tsl', cache, fetcher: OFFLINE_FETCHER, nowSeconds: NOW_SECONDS };
}

/**
 * 1 つだけ汚染し、残りは明示的に渡した状態で `loadTrustedList` を試みる。
 *
 * @param polluted `Object.prototype` に仕込む 1 件。
 * @param explicit 明示的に渡す残りの FO-5 オプション。
 */
async function loadWithPollution(
  polluted: Readonly<Record<string, unknown>>,
  explicit: Partial<LoadTrustedListOptions>,
): Promise<unknown> {
  records.length = 0;
  let caught: unknown;
  await withPollutedPrototypeAsync(polluted, async () => {
    try {
      await loadTrustedList(TSL_URL, { ...cachedDeps(), ...explicit });
    } catch (error) {
      caught = error;
    }
  });
  return caught;
}

/** TSL_FETCH_FAILED のまま伝播した（FO-5 が成立しなかった）ことを検証する。 */
function expectFailClosed(caught: unknown): void {
  expect(caught).toBeInstanceOf(VericertsError);
  expect((caught as VericertsError).code).toBe(ErrorCodes.TSL_FETCH_FAILED);
  expect(records).toEqual([]);
}

describe('FO-5 の依存注入 汚染耐性', () => {
  it('継承した failOpenWindow では FO-5 は成立しない', async () => {
    const caught = await loadWithPollution(
      { failOpenWindow: createFailOpenWindow() },
      { onPolicyEvent: sink, requestConsent: (): boolean => true },
    );
    expectFailClosed(caught);
  });

  it('継承した onPolicyEvent では監査記録先として採用しない', async () => {
    const caught = await loadWithPollution(
      { onPolicyEvent: sink },
      { failOpenWindow: createFailOpenWindow(), requestConsent: (): boolean => true },
    );
    expectFailClosed(caught);
  });

  it('継承した requestConsent ではユーザー同意として採用しない', async () => {
    const caught = await loadWithPollution(
      { requestConsent: (): boolean => true },
      { failOpenWindow: createFailOpenWindow(), onPolicyEvent: sink },
    );
    // 同意不能は `rejected` として記録されるため、記録の有無ではなく通過しないことを見る。
    expect(caught).toBeInstanceOf(VericertsError);
    expect((caught as VericertsError).code).toBe(ErrorCodes.TSL_FETCH_FAILED);
    expect(records.map((record) => record.user_consent)).toEqual(['rejected']);
  });
});

/**
 * `validFailOpenWindow` の `window.allow` / `window.clear` 鎖読みガード耐性テスト。
 *
 * `deps.failOpenWindow` 自体は own プロパティとして正しく渡されていても（＝上の describe が守る
 * 経路は通過済みでも）、その中身 `window.allow` / `window.clear` を素のドットアクセスで検証すると
 * `Object.prototype.allow` / `Object.prototype.clear` の汚染を拾ってしまう。own プロパティを
 * 持たない不正な形状（`failOpenWindow: {}`）を渡す呼び出し元が、汚染された `Object.prototype`
 * 経由で攻撃者の関数をウィンドウとして受け入れてしまわないことを検証する。
 */
describe('FO-5 window.allow/window.clear 鎖読みガード耐性', () => {
  it('own の allow/clear を持たないウィンドウは Object.prototype 汚染下でも受理しない', async () => {
    records.length = 0;
    let caught: unknown;
    await withPollutedPrototypeAsync(
      {
        allow: (): boolean => true,
        clear: (): void => {
          throw new Error('attacker clear must not be called');
        },
      },
      async () => {
        try {
          await loadTrustedList(TSL_URL, {
            ...cachedDeps(),
            // own プロパティとしては正しく渡しているが、中身が空オブジェクト（own の
            // allow/clear を持たない）。`nonObjectPrototypeProperty` で検証していれば
            // Object.prototype 由来の allow/clear は「未指定」として弾かれ、FO-5 は不活性の
            // ままになる。
            failOpenWindow: {} as ReturnType<typeof createFailOpenWindow>,
            onPolicyEvent: sink,
            requestConsent: (): boolean => true,
          });
        } catch (error) {
          caught = error;
        }
      },
    );
    expectFailClosed(caught);
  });
});
