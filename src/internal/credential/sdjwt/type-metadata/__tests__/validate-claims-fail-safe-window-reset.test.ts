/**
 * SD-JWT VC Type Metadata 経路: 資源取得成功時の FO-3 ウィンドウ破棄。
 *
 * 取得に成功するとウィンドウを破棄し、次の取得失敗から新しく 60 秒を計る。
 *
 * 必須 / 任意違反の区別（FO-4）・取得失敗の基本挙動・FO-3 の時間上限・vct と schema_uri の
 * キー分離は `validate-claims-fail-safe.test.ts` が固定する（Linterly の 300 行上限のため分割）。
 *
 * 修正前は `applySchemaViolations` の成功時 clear が FO-4 の `violationKey`（指紋付き）にしか
 * 効かず、FO-3 が使う `vctResourceKey`（`sdjwt-vct:<vct>`）はどこでも clear されなかった。
 * `credential-schema` 経路（`fail-open-window.test.ts`）と同じ欠陥が SD-JWT 経路にも存在した。
 */

import { describe, expect, it } from 'bun:test';
import { type ErrorCode, ErrorCodes, VericertsError } from '../../../../errors.js';
import { FAIL_OPEN_AUDIT_EVENTS } from '../../../../failsafe/index.js';
import type { FailSafeAuditRecord } from '../../../../failsafe-policy/index.js';
import { createFailOpenWindow } from '../../../../failsafe-policy/index.js';
import { TypeMetadataCache } from '../cache.js';
import { validateClaimsAgainstTypeMetadata } from '../resolve.js';
import type { ResolveTypeMetadataOptions, SdJwtTypeMetadata } from '../types.js';
import { BASE_METADATA, BASE_VCT, createFetchStub } from './fixtures.js';

/** 期待するエラーコードで reject されることを確認する。 */
async function expectCode(promise: Promise<unknown>, code: ErrorCode): Promise<void> {
  try {
    await promise;
    throw new Error('should have thrown');
  } catch (err) {
    expect(err).toBeInstanceOf(VericertsError);
    expect((err as VericertsError).code).toBe(code);
  }
}

/** テストごとに独立したキャッシュを使う。 */
function freshCaches() {
  return {
    metadataCache: new TypeMetadataCache<SdJwtTypeMetadata>(),
    schemaCache: new TypeMetadataCache<Record<string, unknown>>(),
  };
}

/**
 * Fail-open の成立条件（同意 + 監査記録先 + 専用の計時ウィンドウ）を揃えたオプション。
 *
 * ウィンドウは必ず注入する。モジュール既定の共有ウィンドウはテスト間で状態が残り、
 * `BASE_VCT` を使う他のテストの実行順で結果が変わってしまうため。
 */
function failOpenGrant(records: FailSafeAuditRecord[] = []): ResolveTypeMetadataOptions {
  return {
    requestConsent: () => true,
    onPolicyEvent: (record) => {
      records.push(record);
    },
    failOpenWindow: createFailOpenWindow(),
  };
}

describe('validateClaimsAgainstTypeMetadata — 資源取得成功時の FO-3 ウィンドウ破棄（新規指摘 B）', () => {
  it('vct 資源への取得が成功した時点で FO-3 のウィンドウを破棄し、次の失敗を新しい 60 秒で数える', async () => {
    const shared = failOpenGrant();
    const failAt = async (nowMs: number) =>
      await validateClaimsAgainstTypeMetadata(
        BASE_VCT,
        { given_name: '太郎' },
        { fetchImpl: createFetchStub({}).fetchImpl, ...freshCaches(), nowMs, ...shared },
      );

    expect((await failAt(0)).warnings).toEqual([FAIL_OPEN_AUDIT_EVENTS['FO-3']]);

    // t=10: vct の取得成功 + 完全適合。vctResourceKey のウィンドウを破棄するはず。
    const successStub = createFetchStub({ [BASE_VCT]: { json: BASE_METADATA } });
    const clean = await validateClaimsAgainstTypeMetadata(
      BASE_VCT,
      { given_name: '太郎', nickname: 'たろ' },
      { fetchImpl: successStub.fetchImpl, ...freshCaches(), nowMs: 10_000, ...shared },
    );
    expect(clean).toEqual({ valid: true, schemaAvailable: true, warnings: [] });

    // t=65: 破棄されていなければ t=0 起点で 65 秒経過 = Fail-closed になるはずの時刻。
    // 破棄されていれば「clear 後、最初に失敗した時刻」を新しい開始時刻として許可する
    // （`createFailOpenWindow` の `allow` の契約）。
    expect((await failAt(65_000)).warnings).toEqual([FAIL_OPEN_AUDIT_EVENTS['FO-3']]);

    // 新しい開始時刻は t=65 なので、そこから 60 秒以内の t=125 はまだ許可される。
    expect((await failAt(125_000)).warnings).toEqual([FAIL_OPEN_AUDIT_EVENTS['FO-3']]);

    // t=65 から 61 秒後（t=126）は新しい予算も使い切っており、Fail-closed に戻る。
    await expectCode(failAt(126_000), ErrorCodes.TYPE_METADATA_FETCH_FAILED);
  });
});
