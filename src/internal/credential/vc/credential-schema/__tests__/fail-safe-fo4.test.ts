/**
 * `credentialSchema` 経路の必須 / 任意属性違反の区別（FO-4）テスト。
 *
 * `credentialSchema` の任意属性違反（FO-4）を警告として通過させるには、同意コールバックと監査記録先が必要。
 *
 * 検証対象なし・FO-3（取得失敗）・3015/3016 以外の例外は `fail-safe.test.ts` が固定する。
 * Fail-open の時間上限は `fail-open-window.test.ts` が固定する。
 * 本ファイルは Linterly の 300 行上限のため `fail-safe.test.ts` から分割したもの。
 *
 * - 必須属性違反は `valid: false` + `errors[].required === true`（FO-4 の対象外、警告を出さない）。
 * - 任意属性のみの違反（FO-4）は**同意 + 監査記録が揃ったときだけ**警告通過し、揃わない / 不同意なら
 *   `valid: false` になる。
 * - `escalate: ['FO-4']` を指定すると任意属性違反が `valid: false` に格上げされる。
 */

import { describe, expect, it } from 'bun:test';
import { FAIL_OPEN_AUDIT_EVENTS } from '../../../../failsafe/index.js';
import type { FailSafeAuditRecord } from '../../../../failsafe-policy/index.js';
import { createFailOpenWindow } from '../../../../failsafe-policy/index.js';
import { CredentialSchemaCache } from '../cache.js';
import type { ValidateCredentialSchemaOptions } from '../types.js';
import { validateClaimsAgainstCredentialSchema } from '../validate.js';
import { buildVc, createFetchStub, PERSON_SCHEMA, SCHEMA_URL } from './fixtures.js';

/** 既定キャッシュを共有しないよう、テストごとに専用キャッシュを渡す。 */
function freshCache(): CredentialSchemaCache {
  return new CredentialSchemaCache();
}

/**
 * Fail-open の成立条件（同意 + 監査記録先 + 専用の計時ウィンドウ）を揃えたオプション。
 *
 * ウィンドウは必ず注入する。モジュール既定の共有ウィンドウはテスト間で状態が残り、
 * `SCHEMA_URL` を使う他のテストの実行順で結果が変わってしまうため。
 */
function failOpenGrant(records: FailSafeAuditRecord[] = []): ValidateCredentialSchemaOptions {
  return {
    requestConsent: () => true,
    onPolicyEvent: (record) => {
      records.push(record);
    },
    failOpenWindow: createFailOpenWindow(),
  };
}

describe('validateClaimsAgainstCredentialSchema — 必須 / 任意違反の区別（FO-4）', () => {
  /** `nickname`（任意 / maxLength: 8）だけが違反する VC。 */
  function buildOptionalViolation() {
    return buildVc(
      { name: '山田太郎', nickname: 'ながすぎるニックネームです' },
      { id: SCHEMA_URL, type: 'JsonSchema' },
    );
  }

  it('スキーマに適合する credentialSubject は警告なしで通過する', async () => {
    const stub = createFetchStub({ [SCHEMA_URL]: { json: PERSON_SCHEMA } });
    const vc = buildVc(
      { name: '山田太郎', nickname: 'たろ' },
      { id: SCHEMA_URL, type: 'JsonSchema' },
    );

    // 完全に綺麗に通る経路は同意・監査記録を必要としない。
    const result = await validateClaimsAgainstCredentialSchema(vc, {
      fetchImpl: stub.fetchImpl,
      schemaCache: freshCache(),
      nowMs: 1000,
    });

    expect(result).toEqual({ valid: true, schemaAvailable: true, warnings: [] });
  });

  it('必須属性違反は required: true で、警告通過の対象にしない', async () => {
    const stub = createFetchStub({ [SCHEMA_URL]: { json: PERSON_SCHEMA } });
    const vc = buildVc({ nickname: 'たろ' }, { id: SCHEMA_URL, type: 'JsonSchema' });
    const records: FailSafeAuditRecord[] = [];

    const result = await validateClaimsAgainstCredentialSchema(vc, {
      fetchImpl: stub.fetchImpl,
      schemaCache: freshCache(),
      nowMs: 1000,
      ...failOpenGrant(records),
    });

    expect(result.valid).toBe(false);
    expect(result.schemaAvailable).toBe(true);
    expect(result.errors?.some((e) => e.required)).toBe(true);
    expect(result.warnings).toEqual([]);
    // FO-4 の対象外なのでゲート自体を通さない（同意も監査記録も発生しない）。
    expect(records).toEqual([]);
  });

  it('任意属性のみの違反は同意 + 監査記録があれば警告通過する（valid: true + FO-4 の監査キー）', async () => {
    const stub = createFetchStub({ [SCHEMA_URL]: { json: PERSON_SCHEMA } });
    const records: FailSafeAuditRecord[] = [];

    const result = await validateClaimsAgainstCredentialSchema(buildOptionalViolation(), {
      fetchImpl: stub.fetchImpl,
      schemaCache: freshCache(),
      nowMs: 1000,
      ...failOpenGrant(records),
    });

    // FO-4 の既定は「警告通過」。valid: false にすると FO-4 が fail-closed に見えてしまう。
    expect(result.valid).toBe(true);
    expect(result.schemaAvailable).toBe(true);
    expect(result.warnings).toEqual([FAIL_OPEN_AUDIT_EVENTS['FO-4']]);
    // 通過させても違反内容は呼び出し側が確認できるよう残す。
    expect(result.errors?.every((e) => !e.required)).toBe(true);
    expect(result.errors?.[0]?.path).toBe('/nickname');
    expect(records.map((r) => [r.policy_event, r.user_consent])).toEqual([['FO-4', 'accepted']]);
  });

  it('同意コールバックも監査記録先も無ければ任意属性違反は valid: false になる', async () => {
    // FO-4 側の検証。同意も監査記録も無いまま警告通過させない。
    const stub = createFetchStub({ [SCHEMA_URL]: { json: PERSON_SCHEMA } });

    const result = await validateClaimsAgainstCredentialSchema(buildOptionalViolation(), {
      fetchImpl: stub.fetchImpl,
      schemaCache: freshCache(),
      nowMs: 1000,
      failOpenWindow: createFailOpenWindow(),
    });

    expect(result.valid).toBe(false);
    expect(result.schemaAvailable).toBe(true);
    expect(result.warnings).toEqual([]);
    // 通過させない場合も違反内容は残す（呼び出し側が理由を確認できる）。
    expect(result.errors?.[0]?.path).toBe('/nickname');
  });

  it('ユーザーが同意しなければ任意属性違反は valid: false になる', async () => {
    const stub = createFetchStub({ [SCHEMA_URL]: { json: PERSON_SCHEMA } });
    const records: FailSafeAuditRecord[] = [];

    const result = await validateClaimsAgainstCredentialSchema(buildOptionalViolation(), {
      fetchImpl: stub.fetchImpl,
      schemaCache: freshCache(),
      nowMs: 1000,
      requestConsent: () => false,
      onPolicyEvent: (record) => {
        records.push(record);
      },
      failOpenWindow: createFailOpenWindow(),
    });

    expect(result.valid).toBe(false);
    expect(result.warnings).toEqual([]);
    expect(records.map((r) => r.user_consent)).toEqual(['rejected']);
  });

  it('escalate: ["FO-4"] を指定すると任意属性違反も valid: false に格上げされる', async () => {
    const stub = createFetchStub({ [SCHEMA_URL]: { json: PERSON_SCHEMA } });
    const records: FailSafeAuditRecord[] = [];

    const result = await validateClaimsAgainstCredentialSchema(buildOptionalViolation(), {
      fetchImpl: stub.fetchImpl,
      schemaCache: freshCache(),
      nowMs: 1000,
      failSafePolicy: { escalate: ['FO-4'] },
      ...failOpenGrant(records),
    });

    expect(result.valid).toBe(false);
    expect(result.warnings).toEqual([]);
    expect(result.errors?.length).toBeGreaterThan(0);
    // `deny` は Fail-open を選んでいないので監査の記録対象ではない。
    expect(records).toEqual([]);
  });
});
