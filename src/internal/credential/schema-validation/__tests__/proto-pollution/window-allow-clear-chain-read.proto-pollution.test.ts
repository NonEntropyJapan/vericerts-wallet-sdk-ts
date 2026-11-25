/**
 * `fail-safe.ts` の `resolveWindow` が `Object.prototype` 汚染下で `failOpenWindow.allow` /
 * `.clear` の鎖読みガードを素通りする欠陥の回帰テスト。
 *
 * `resolveWindow` は `options.failOpenWindow` 自体を `nonObjectPrototypeProperty` で own 限定に
 * 読むが、そこで得た `injected` オブジェクトの `.allow` / `.clear` を素のドットアクセス（プロトタイプ
 * 鎖読み）で検証すると、own の `allow` / `clear` を持たない不正な形状（`failOpenWindow: {}`）を
 * 渡す呼び出しに対して `Object.prototype.allow` / `.clear` の汚染を拾ってしまう
 * （`etsi-tsl/fail-open.ts` の FO-5 で見つかったのと同一のバグクラス）。
 *
 * `schemaFetchFailedResult`（FO-3、`gate` 経由で `resolveWindow` を使う）と
 * `applySchemaViolations` の成功パス（`resolveWindow(options)?.clear(key)`）の双方を対象に、
 * 攻撃者の `allow` / `clear` が一度も呼ばれず Fail-closed のまま（FO-3 が不成立、`clear` は
 * 黙ってスキップ）であることを固定する。
 */

import { describe, expect, it } from 'bun:test';
import { withPollutedPrototypeAsync } from '../../../../__tests__/prototype-pollution.fixtures.js';
import type { FailOpenWindow } from '../../../../failsafe-policy/index.js';
import { applySchemaViolations, schemaFetchFailedResult } from '../../fail-safe.js';

describe('resolveWindow(fail-safe.ts) の Object.prototype 汚染耐性', () => {
  it('own の allow/clear を持たない failOpenWindow は schemaFetchFailedResult（FO-3）を成立させない', async () => {
    let attackerAllowCalls = 0;
    const result = await withPollutedPrototypeAsync(
      {
        allow: (): boolean => {
          attackerAllowCalls += 1;
          return true;
        },
        clear: (): void => {
          throw new Error('attacker clear must not be called');
        },
      },
      () =>
        schemaFetchFailedResult('w3c:https://issuer.example.com/schema/1237', 1_000, {
          failOpenWindow: {} as FailOpenWindow,
          requestConsent: () => true,
          onPolicyEvent: () => {},
        }),
    );
    // ウィンドウが不正な形状 = 時間上限を計測できない = Fail-closed（呼び出し側が元の取得失敗を伝播）。
    expect(result).toBeUndefined();
    // 攻撃者の allow が一度も呼ばれていないこと（呼ばれていたら継承値を採用している）。
    expect(attackerAllowCalls).toBe(0);
  });

  it('own の allow/clear を持たない failOpenWindow は applySchemaViolations の成功パスで attacker.clear を呼ばない', async () => {
    let attackerClearCalls = 0;
    const result = await withPollutedPrototypeAsync(
      {
        allow: (): boolean => true,
        clear: (): void => {
          attackerClearCalls += 1;
        },
      },
      () =>
        applySchemaViolations(
          'w3c:https://issuer.example.com/schema/1237:fp',
          1_000,
          { valid: true },
          { failOpenWindow: {} as FailOpenWindow },
        ),
    );
    // 検証自体は成功しているため valid: true は維持されるが、不正な形状のウィンドウはクラッシュ
    // させず黙ってスキップする（クリア自体は起きない）。
    expect(result).toEqual({ valid: true, schemaAvailable: true, warnings: [] });
    // 攻撃者の clear が一度も呼ばれていないこと。
    expect(attackerClearCalls).toBe(0);
  });
});
