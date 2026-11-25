/**
 * Fail-open の時間上限（60 秒）の回帰テスト。
 *
 * 同一対象の警告通過は最初の許可から既定 60 秒まで。上限を超えて失敗が続く間は Fail-closed を保つ。
 *
 * 同意 / 監査記録の有無は `fail-safe.test.ts` が固定する。本ファイルは**時間軸とキー設計**を見る:
 *
 * - FO-3（取得失敗）は**スキーマ資源単位**で計時する。資源（URL）そのものの到達性はクレデンシャルに
 *   依らないため、同じ URL を参照するどのクレデンシャルの検証でも同じ計時を共有する。
 * - FO-4（任意属性違反）は**資源 + クレデンシャルの指紋単位**で計時する。
 *   資源単位だけだと、同じスキーマを参照する**無関係な別のクレデンシャル**がたまたま綺麗に通った
 *   だけで、違反しているクレデンシャル側の Fail-open 予算がリセットされてしまうため。
 * - 上限を超えると FO-3 は 3015 を伝播し、FO-4 は `valid: false` を返す。
 *   FO-3 はスキーマ取得の成功時にリセットする。FO-4 は同じスキーマ・同じ指紋で違反が0件になったときにリセットする。
 *
 * 時刻は `nowMs` の注入だけで進め、ウィンドウはテストごとに新規生成する（モジュール既定の共有
 * ウィンドウを使うと他テストの計時が混ざり実行順に依存する）。
 */

import { describe, expect, it } from 'bun:test';
import { ErrorCodes } from '../../../../errors.js';
import { FAIL_OPEN_AUDIT_EVENTS } from '../../../../failsafe/index.js';
import { createFailOpenWindow } from '../../../../failsafe-policy/index.js';
import { CredentialSchemaCache } from '../cache.js';
import type { ValidateCredentialSchemaOptions } from '../types.js';
import { validateClaimsAgainstCredentialSchema } from '../validate.js';
import { buildVc, createFetchStub, PERSON_SCHEMA, SCHEMA_URL } from './fixtures.js';

/** Fail-open の成立条件（同意 + 監査記録先 + 専用の計時ウィンドウ）を揃えたオプション。 */
function failOpenGrant(): ValidateCredentialSchemaOptions {
  return {
    requestConsent: () => true,
    onPolicyEvent: () => {},
    failOpenWindow: createFailOpenWindow(),
  };
}

/** FO-3 を起こす（取得失敗する）検証を指定時刻で 1 回実行する。 */
async function fetchFailureAt(nowMs: number, options: ValidateCredentialSchemaOptions) {
  const stub = createFetchStub({ [SCHEMA_URL]: { status: 500 } });
  return await validateClaimsAgainstCredentialSchema(
    buildVc({ name: '山田太郎' }, { id: SCHEMA_URL, type: 'JsonSchema' }),
    { fetchImpl: stub.fetchImpl, schemaCache: new CredentialSchemaCache(), nowMs, ...options },
  );
}

/** 任意属性のみが違反する（FO-4 になる）検証を、同じ内容のクレデンシャルで指定時刻に 1 回実行する。 */
async function optionalViolationAt(nowMs: number, options: ValidateCredentialSchemaOptions) {
  const stub = createFetchStub({ [SCHEMA_URL]: { json: PERSON_SCHEMA } });
  return await validateClaimsAgainstCredentialSchema(
    buildVc(
      { name: '山田太郎', nickname: 'ながすぎるニックネームです' },
      { id: SCHEMA_URL, type: 'JsonSchema' },
    ),
    { fetchImpl: stub.fetchImpl, schemaCache: new CredentialSchemaCache(), nowMs, ...options },
  );
}

/** スキーマに完全適合する（ウィンドウを破棄する）検証を指定時刻で 1 回実行する。 */
async function cleanPassAt(nowMs: number, options: ValidateCredentialSchemaOptions) {
  const stub = createFetchStub({ [SCHEMA_URL]: { json: PERSON_SCHEMA } });
  return await validateClaimsAgainstCredentialSchema(
    buildVc({ name: '山田太郎', nickname: 'たろ' }, { id: SCHEMA_URL, type: 'JsonSchema' }),
    { fetchImpl: stub.fetchImpl, schemaCache: new CredentialSchemaCache(), nowMs, ...options },
  );
}

describe('validateClaimsAgainstCredentialSchema — FO-3 の時間上限（資源単位）', () => {
  it('同じスキーマ URL への取得失敗は資源単位で計時する', async () => {
    const shared = failOpenGrant();

    const first = await fetchFailureAt(0, shared);
    expect(first.warnings).toEqual([FAIL_OPEN_AUDIT_EVENTS['FO-3']]);

    const withinWindow = await fetchFailureAt(60_000, shared);
    expect(withinWindow.warnings).toEqual([FAIL_OPEN_AUDIT_EVENTS['FO-3']]);

    await expect(fetchFailureAt(61_000, shared)).rejects.toMatchObject({
      code: ErrorCodes.SCHEMA_FETCH_FAILED,
    });
  });

  it('資源の取得に成功した時点で FO-3 のウィンドウを破棄し、次の失敗を新しい 60 秒で数える', async () => {
    // 修正前は `applySchemaViolations` の成功時 clear が FO-4 の `violationKey`（指紋付き）にしか
    // 効かず、FO-3 が使う資源キー（`w3c:<url>`）はどこでも clear されなかった。そのため t=0 で
    // 一度 Fail-open を消費すると、途中で取得が完全に成功しても資源キーの開始時刻は t=0 のまま
    // リセットされず、t=61 以降の新たな取得失敗も警告通過できない退行があった。
    const shared = failOpenGrant();

    const first = await fetchFailureAt(0, shared);
    expect(first.warnings).toEqual([FAIL_OPEN_AUDIT_EVENTS['FO-3']]);

    // t=10: 完全に適合する取得成功。資源キー（FO-3）のウィンドウを破棄するはず。
    expect(await cleanPassAt(10_000, shared)).toEqual({
      valid: true,
      schemaAvailable: true,
      warnings: [],
    });

    // t=65 は最初の許可（t=0）からは 65 秒後で、ウィンドウが破棄されていなければ resourceKey の
    // 開始時刻はまだ t=0 のままのはずなので 65 - 0 = 65 > 60 で Fail-closed になる（修正前の
    // 実際の挙動）。t=10 の clear が効いていれば、resourceKey の開始時刻はここで消えており、
    // `allow` はこの呼び出しを「新規キー」として扱い、開始時刻を t=65 として記録したうえで許可する
    // （`createFailOpenWindow` の `allow` は `clear` 済みキーを未計時として扱うため、新しい開始
    // 時刻は「clear された時刻」ではなく「clear 後 最初に失敗した時刻」になる）。
    const afterReset = await fetchFailureAt(65_000, shared);
    expect(afterReset.warnings).toEqual([FAIL_OPEN_AUDIT_EVENTS['FO-3']]);

    // 新しい開始時刻は t=65（上の呼び出し）なので、そこから 60 秒以内の t=125 はまだ許可される。
    const stillWithinNewWindow = await fetchFailureAt(125_000, shared);
    expect(stillWithinNewWindow.warnings).toEqual([FAIL_OPEN_AUDIT_EVENTS['FO-3']]);

    // t=65 から 61 秒後（t=126）は新しい予算も使い切っており、Fail-closed に戻る。
    await expect(fetchFailureAt(126_000, shared)).rejects.toMatchObject({
      code: ErrorCodes.SCHEMA_FETCH_FAILED,
    });
  });
});

describe('validateClaimsAgainstCredentialSchema — FO-4 の時間上限（クレデンシャル単位）', () => {
  it('同一クレデンシャルの違反は資源 + 指紋単位で 60 秒の予算を共有する', async () => {
    const shared = failOpenGrant();

    const first = await optionalViolationAt(0, shared);
    expect(first.valid).toBe(true);

    // 開始から 60 秒ちょうどはまだ上限内。同じクレデンシャル内容なので数え直さない。
    const withinWindow = await optionalViolationAt(60_000, shared);
    expect(withinWindow.valid).toBe(true);

    const overWindow = await optionalViolationAt(61_000, shared);
    expect(overWindow.valid).toBe(false);
    expect(overWindow.warnings).toEqual([]);
  });

  it('完全に綺麗に通った時点で当該クレデンシャルのウィンドウを破棄し、次の違反を新しい 60 秒で数える', async () => {
    const shared = failOpenGrant();

    await optionalViolationAt(0, shared);
    // 同一クレデンシャル（同じ subject）が綺麗に通った場合のみ、そのクレデンシャルのウィンドウを破棄する。
    // ここでは cleanPassAt が別内容（nickname: 'たろ'）のクレデンシャルのため、別キーとして扱われる。
    expect(await cleanPassAt(10_000, shared)).toEqual({
      valid: true,
      schemaAvailable: true,
      warnings: [],
    });

    // optionalViolationAt 自身のクレデンシャルはまだ 60 秒以内なので通過し続ける。
    const stillWithinWindow = await optionalViolationAt(59_000, shared);
    expect(stillWithinWindow.valid).toBe(true);
    const overWindow = await optionalViolationAt(61_000, shared);
    expect(overWindow.valid).toBe(false);
  });

  it('無関係な別クレデンシャルが綺麗に通っても、違反しているクレデンシャルの予算はリセットされない', async () => {
    // 同じスキーマ URL を参照する 2 つの別クレデンシャル。片方（violating）は任意属性が壊れており、
    // もう片方（clean）は完全に適合する。資源単位のみでキーイングしていた旧実装では、clean 側の
    // 成功が violating 側の Fail-open ウィンドウまで破棄してしまい、無期限に予算を延命できた。
    const shared = failOpenGrant();

    await optionalViolationAt(0, shared);
    // clean な別クレデンシャルが 30 秒後に綺麗に通っても、violating 側の計時には影響しない。
    expect(await cleanPassAt(30_000, shared)).toEqual({
      valid: true,
      schemaAvailable: true,
      warnings: [],
    });

    // violating 側は最初の許可（t=0）から 61 秒後には Fail-closed になる（30 秒地点の他者の
    // 成功でリセットされていれば valid: true のままになってしまう）。
    const overWindow = await optionalViolationAt(61_000, shared);
    expect(overWindow.valid).toBe(false);
    expect(overWindow.warnings).toEqual([]);
  });
});
