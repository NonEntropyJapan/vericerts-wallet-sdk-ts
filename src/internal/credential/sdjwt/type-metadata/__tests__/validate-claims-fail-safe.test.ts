/**
 * Type Metadata 経路の必須 / 任意違反の区別（FO-4）と取得失敗時の fail-safe（FO-3）のテスト
 *
 * FO-3（スキーマ取得失敗）と FO-4（任意属性違反）の警告通過には、同意コールバックと監査記録先が必要。
 *
 * 適合判定・構造不正（3061）・キャッシュは `validate-claims.test.ts` が固定する。取得成功時の
 * FO-3 資源キー破棄は
 * `validate-claims-fail-safe-window-reset.test.ts` が固定する
 * （いずれも Linterly の 300 行上限のため分割）。
 *
 * 検証内容:
 * - 必須属性違反は `valid: false` + `errors[].required === true`（FO-4 の対象外、警告を出さない）。
 * - 任意属性のみの違反は**同意 + 監査記録が揃ったときだけ**警告通過し（valid: true + FO-4 の監査キー）、
 *   揃わない / 不同意なら `valid: false` になる。`escalate: ['FO-4']` を指定した
 *   場合はいずれにせよ `valid: false` に格上げされる。
 * - 取得失敗（3060）は**同意 + 監査記録が揃ったときだけ** `schemaAvailable: false` + FO-3 の監査キー。
 *   揃わない / 不同意なら 3060 をそのまま伝播する。
 *   `escalate: ['FO-3']` を指定すると同意 + 監査記録があっても 3060 として伝播する。
 * - FO-3 の Fail-open 時間上限（既定 60 秒、`vct` 単位で計時）。
 */

import { describe, expect, it } from 'bun:test';
import { type ErrorCode, ErrorCodes, VericertsError } from '../../../../errors.js';
import { FAIL_OPEN_AUDIT_EVENTS } from '../../../../failsafe/index.js';
import type { FailSafeAuditRecord } from '../../../../failsafe-policy/index.js';
import { createFailOpenWindow } from '../../../../failsafe-policy/index.js';
import { TypeMetadataCache } from '../cache.js';
import { validateClaimsAgainstTypeMetadata } from '../resolve.js';
import type { ResolveTypeMetadataOptions, SdJwtTypeMetadata } from '../types.js';
import { BASE_METADATA, BASE_VCT, createFetchStub, SCHEMA_URI } from './fixtures.js';

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

describe('validateClaimsAgainstTypeMetadata — 必須 / 任意違反の区別（FO-4）', () => {
  it('必須属性違反は required: true で、警告通過の対象にしない', async () => {
    const stub = createFetchStub({ [BASE_VCT]: { json: BASE_METADATA } });
    const result = await validateClaimsAgainstTypeMetadata(
      BASE_VCT,
      { nickname: 'たろ' },
      { fetchImpl: stub.fetchImpl, ...freshCaches() },
    );
    expect(result.valid).toBe(false);
    expect(result.errors?.some((e) => e.required)).toBe(true);
    expect(result.warnings).toEqual([]);
  });

  it('任意属性のみの違反は同意 + 監査記録があれば警告通過する（valid: true + FO-4 の監査キー）', async () => {
    const stub = createFetchStub({ [BASE_VCT]: { json: BASE_METADATA } });
    const records: FailSafeAuditRecord[] = [];
    const result = await validateClaimsAgainstTypeMetadata(
      BASE_VCT,
      // nickname は maxLength: 8 を超過。given_name は満たしている。
      { given_name: '太郎', nickname: '123456789' },
      { fetchImpl: stub.fetchImpl, ...freshCaches(), ...failOpenGrant(records) },
    );
    // FO-4 の既定は「警告通過」。valid: false にすると仕様と逆になる。
    expect(result.valid).toBe(true);
    expect(result.schemaAvailable).toBe(true);
    expect(result.warnings).toEqual([FAIL_OPEN_AUDIT_EVENTS['FO-4']]);
    // 通過させても違反内容は呼び出し側が確認できるよう残す。
    expect(result.errors?.every((e) => !e.required)).toBe(true);
    expect(result.errors?.[0]?.path).toBe('/nickname');
    expect(records.map((r) => [r.policy_event, r.user_consent])).toEqual([['FO-4', 'accepted']]);
  });

  it('同意コールバックも監査記録先も無ければ任意属性違反は valid: false になる', async () => {
    // 回帰。同意も監査記録も無いまま警告通過させない。
    const stub = createFetchStub({ [BASE_VCT]: { json: BASE_METADATA } });
    const result = await validateClaimsAgainstTypeMetadata(
      BASE_VCT,
      { given_name: '太郎', nickname: '123456789' },
      { fetchImpl: stub.fetchImpl, ...freshCaches(), failOpenWindow: createFailOpenWindow() },
    );
    expect(result.valid).toBe(false);
    expect(result.warnings).toEqual([]);
    // 通過させない場合も違反内容は残す。
    expect(result.errors?.[0]?.path).toBe('/nickname');
  });

  it('ユーザーが同意しなければ任意属性違反は valid: false になる', async () => {
    const stub = createFetchStub({ [BASE_VCT]: { json: BASE_METADATA } });
    const records: FailSafeAuditRecord[] = [];
    const result = await validateClaimsAgainstTypeMetadata(
      BASE_VCT,
      { given_name: '太郎', nickname: '123456789' },
      {
        fetchImpl: stub.fetchImpl,
        ...freshCaches(),
        requestConsent: () => false,
        onPolicyEvent: (record) => {
          records.push(record);
        },
        failOpenWindow: createFailOpenWindow(),
      },
    );
    expect(result.valid).toBe(false);
    expect(result.warnings).toEqual([]);
    expect(records.map((r) => r.user_consent)).toEqual(['rejected']);
  });

  it('escalate: ["FO-4"] を指定すると任意属性違反も valid: false に格上げされる', async () => {
    const stub = createFetchStub({ [BASE_VCT]: { json: BASE_METADATA } });
    const records: FailSafeAuditRecord[] = [];
    const result = await validateClaimsAgainstTypeMetadata(
      BASE_VCT,
      { given_name: '太郎', nickname: '123456789' },
      {
        fetchImpl: stub.fetchImpl,
        failSafePolicy: { escalate: ['FO-4'] },
        ...freshCaches(),
        ...failOpenGrant(records),
      },
    );
    expect(result.valid).toBe(false);
    expect(result.warnings).toEqual([]);
    expect(result.errors?.length).toBeGreaterThan(0);
    // `deny` は Fail-open を選んでいないので監査の記録対象ではない。
    expect(records).toEqual([]);
  });
});

describe('validateClaimsAgainstTypeMetadata — 取得失敗時の fail-safe（FO-3）', () => {
  it('取得失敗は同意 + 監査記録があれば schema_fetch_failed を警告として返す', async () => {
    const stub = createFetchStub({ [BASE_VCT]: { networkError: true } });
    const records: FailSafeAuditRecord[] = [];
    const result = await validateClaimsAgainstTypeMetadata(
      BASE_VCT,
      { given_name: '太郎' },
      { fetchImpl: stub.fetchImpl, ...freshCaches(), ...failOpenGrant(records) },
    );
    expect(result).toEqual({
      valid: true,
      schemaAvailable: false,
      warnings: [FAIL_OPEN_AUDIT_EVENTS['FO-3']],
    });
    expect(records.map((r) => [r.policy_event, r.user_consent])).toEqual([['FO-3', 'accepted']]);
  });

  it('schema_uri の取得失敗も警告通過にする', async () => {
    const stub = createFetchStub({
      [BASE_VCT]: { json: { vct: BASE_VCT, schema_uri: SCHEMA_URI } },
      [SCHEMA_URI]: { status: 500 },
    });
    const result = await validateClaimsAgainstTypeMetadata(
      BASE_VCT,
      { given_name: '太郎' },
      { fetchImpl: stub.fetchImpl, ...freshCaches(), ...failOpenGrant() },
    );
    expect(result.warnings).toEqual([FAIL_OPEN_AUDIT_EVENTS['FO-3']]);
  });

  it('同意コールバックも監査記録先も無ければ取得失敗を 3060 として伝播する', async () => {
    // ここを警告通過させると、同意も監査記録も無いまま
    // 「Type Metadata 未検証の VC」が valid: true で通ってしまう。
    const stub = createFetchStub({ [BASE_VCT]: { networkError: true } });
    await expectCode(
      validateClaimsAgainstTypeMetadata(
        BASE_VCT,
        { given_name: '太郎' },
        { fetchImpl: stub.fetchImpl, ...freshCaches(), failOpenWindow: createFailOpenWindow() },
      ),
      ErrorCodes.TYPE_METADATA_FETCH_FAILED,
    );
  });

  it('ユーザーが同意しなければ取得失敗を伝播し、不同意も監査記録する', async () => {
    const stub = createFetchStub({ [BASE_VCT]: { networkError: true } });
    const records: FailSafeAuditRecord[] = [];
    await expectCode(
      validateClaimsAgainstTypeMetadata(
        BASE_VCT,
        { given_name: '太郎' },
        {
          fetchImpl: stub.fetchImpl,
          ...freshCaches(),
          requestConsent: () => false,
          onPolicyEvent: (record) => {
            records.push(record);
          },
          failOpenWindow: createFailOpenWindow(),
        },
      ),
      ErrorCodes.TYPE_METADATA_FETCH_FAILED,
    );
    expect(records.map((r) => r.user_consent)).toEqual(['rejected']);
  });

  it('監査記録先が無ければ同意コールバックがあっても取得失敗を伝播する', async () => {
    const stub = createFetchStub({ [BASE_VCT]: { networkError: true } });
    await expectCode(
      validateClaimsAgainstTypeMetadata(
        BASE_VCT,
        { given_name: '太郎' },
        {
          fetchImpl: stub.fetchImpl,
          ...freshCaches(),
          requestConsent: () => true,
          failOpenWindow: createFailOpenWindow(),
        },
      ),
      ErrorCodes.TYPE_METADATA_FETCH_FAILED,
    );
  });

  it('escalate: ["FO-3"] なら同意 + 監査記録があっても取得失敗を 3060 として伝播する', async () => {
    const stub = createFetchStub({ [BASE_VCT]: { networkError: true } });
    const records: FailSafeAuditRecord[] = [];
    await expectCode(
      validateClaimsAgainstTypeMetadata(
        BASE_VCT,
        { given_name: '太郎' },
        {
          fetchImpl: stub.fetchImpl,
          failSafePolicy: { escalate: ['FO-3'] },
          ...freshCaches(),
          ...failOpenGrant(records),
        },
      ),
      ErrorCodes.TYPE_METADATA_FETCH_FAILED,
    );
    expect(records).toEqual([]);
  });

  it('60 秒の上限を超えた継続は取得失敗を伝播する（vct 単位で計時）', async () => {
    const shared = failOpenGrant();
    /** 同じ `vct` の取得失敗を指定時刻で 1 回起こす。 */
    const failAt = async (nowMs: number) =>
      await validateClaimsAgainstTypeMetadata(
        BASE_VCT,
        { given_name: '太郎' },
        { fetchImpl: createFetchStub({}).fetchImpl, ...freshCaches(), nowMs, ...shared },
      );

    expect((await failAt(0)).warnings).toEqual([FAIL_OPEN_AUDIT_EVENTS['FO-3']]);
    expect((await failAt(60_000)).warnings).toEqual([FAIL_OPEN_AUDIT_EVENTS['FO-3']]);
    await expectCode(failAt(61_000), ErrorCodes.TYPE_METADATA_FETCH_FAILED);
  });

  it('vct 起因の失敗と schema_uri 起因の失敗は別キーで計時する', async () => {
    // 修正前は schema_uri の取得失敗も vct をキーに計時しており、vct チェーン自体の取得失敗と
    // 区別できなかった。vct を使い切った Fail-open 予算が、無関係な schema_uri の取得失敗にも
    // （逆もまた同様に）誤って適用されないことを確認する。
    const shared = failOpenGrant();

    // vct の取得失敗で t=0〜61 秒の予算を使い切る。
    const vctFailStub = createFetchStub({});
    await validateClaimsAgainstTypeMetadata(
      BASE_VCT,
      { given_name: '太郎' },
      { fetchImpl: vctFailStub.fetchImpl, ...freshCaches(), nowMs: 0, ...shared },
    );
    await expectCode(
      validateClaimsAgainstTypeMetadata(
        BASE_VCT,
        { given_name: '太郎' },
        { fetchImpl: vctFailStub.fetchImpl, ...freshCaches(), nowMs: 61_000, ...shared },
      ),
      ErrorCodes.TYPE_METADATA_FETCH_FAILED,
    );

    // vct の取得自体は成功するが schema_uri の取得が失敗するケースは、独立した新しい予算で
    // t=61 秒でも問題なく警告通過する（vct 側の予算切れの影響を受けない）。
    const schemaUriFailStub = createFetchStub({
      [BASE_VCT]: { json: { vct: BASE_VCT, schema_uri: SCHEMA_URI } },
    });
    const result = await validateClaimsAgainstTypeMetadata(
      BASE_VCT,
      { given_name: '太郎' },
      { fetchImpl: schemaUriFailStub.fetchImpl, ...freshCaches(), nowMs: 61_000, ...shared },
    );
    expect(result.warnings).toEqual([FAIL_OPEN_AUDIT_EVENTS['FO-3']]);
  });
});
