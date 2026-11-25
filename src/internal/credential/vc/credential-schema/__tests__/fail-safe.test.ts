/**
 * `credentialSchema` 経路の fail-safe 挙動のテスト。
 *
 * `credentialSchema` の取得失敗（FO-3）と任意属性違反（FO-4）の警告通過には、同意コールバックと監査記録先が必要。
 *
 * 検証内容:
 * - `credentialSchema` が宣言されていない / JSON Schema 系でない場合は検証対象なしとして
 *   `schemaAvailable: false`（警告なし）。警告通過を必要とする事象ではないので同意・監査記録は要らない。
 * - 未対応の `JsonSchemaCredential` だけを持つ VC も検証対象なし（偽の違反を作らない）。
 * - 取得失敗（FO-3）は**同意 + 監査記録が揃ったときだけ** `valid: true` + FO-3 の監査キー。
 *   揃わない / 不同意なら 3015 をそのまま伝播する。
 * - `escalate: ['FO-3']` を指定すると 3015 / 3016 を伝播する。
 * - 3015 / 3016 以外の例外は握りつぶさず再 throw する。
 *
 * Fail-open の時間上限は `fail-open-window.test.ts` が固定する。
 * 必須 / 任意属性違反の区別（FO-4）は `fail-safe-fo4.test.ts` が固定する
 * （Linterly の 300 行上限のため分割。300行/dir上限に配慮）。
 *
 * SD-JWT VC の Type Metadata 経路（`sdjwt/type-metadata/__tests__/validate-claims.test.ts`）と
 * 同じ FO-3 / FO-4 の観点を、別エコシステムである本経路でも確認する。
 */

import { describe, expect, it } from 'bun:test';
import { ErrorCodes, VericertsError } from '../../../../errors.js';
import { FAIL_OPEN_AUDIT_EVENTS } from '../../../../failsafe/index.js';
import type { FailSafeAuditRecord } from '../../../../failsafe-policy/index.js';
import { createFailOpenWindow } from '../../../../failsafe-policy/index.js';
import { CredentialSchemaCache } from '../cache.js';
import type { ValidateCredentialSchemaOptions } from '../types.js';
import { validateClaimsAgainstCredentialSchema } from '../validate.js';
import {
  buildVc,
  createFetchStub,
  PERSON_SCHEMA,
  SCHEMA_URL,
  type StubResponse,
} from './fixtures.js';

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

describe('validateClaimsAgainstCredentialSchema — 検証対象なし', () => {
  it('credentialSchema が無い VC はスキーマ未取得として通過する', async () => {
    const stub = createFetchStub({});
    const vc = buildVc({ name: '山田太郎' });

    // 同意・監査オプションを一切渡さなくても通る（Fail-open 許容事象ではないため）。
    const result = await validateClaimsAgainstCredentialSchema(vc, {
      fetchImpl: stub.fetchImpl,
      schemaCache: freshCache(),
      nowMs: 1000,
    });

    expect(result).toEqual({ valid: true, schemaAvailable: false, warnings: [] });
    expect(stub.requested).toEqual([]);
  });

  it('JSON Schema 系でない credentialSchema だけの VC も検証対象なしとして扱う', async () => {
    const stub = createFetchStub({});
    const vc = buildVc(
      { name: '山田太郎' },
      { id: 'https://issuer.example.com/shacl.ttl', type: 'ShaclValidator2017' },
    );

    const result = await validateClaimsAgainstCredentialSchema(vc, {
      fetchImpl: stub.fetchImpl,
      schemaCache: freshCache(),
      nowMs: 1000,
    });

    expect(result).toEqual({ valid: true, schemaAvailable: false, warnings: [] });
    expect(stub.requested).toEqual([]);
  });

  it('未対応の JsonSchemaCredential だけの VC は検証対象なしとして扱う', async () => {
    // vc-json-schema §4.2 の `id` は「スキーマを内包する VC」を指す。VC 署名検証と
    // `credentialSubject.jsonSchema` の取り出しが未対応のまま VC 文書をスキーマとして扱うと、
    // ルートの `type` 配列などが型違反として報告され偽の違反になるため受理しない。
    const stub = createFetchStub({});
    const vc = buildVc(
      { name: '山田太郎' },
      { id: 'https://issuer.example.com/schema-credential', type: 'JsonSchemaCredential' },
    );

    const result = await validateClaimsAgainstCredentialSchema(vc, {
      fetchImpl: stub.fetchImpl,
      schemaCache: freshCache(),
      nowMs: 1000,
    });

    expect(result).toEqual({ valid: true, schemaAvailable: false, warnings: [] });
    expect(stub.requested).toEqual([]);
  });

  it('escalate: ["FO-3"] なら credentialSchema 不在を 3016 として伝播する', async () => {
    const stub = createFetchStub({});
    const vc = buildVc({ name: '山田太郎' });

    const promise = validateClaimsAgainstCredentialSchema(vc, {
      fetchImpl: stub.fetchImpl,
      schemaCache: freshCache(),
      nowMs: 1000,
      failSafePolicy: { escalate: ['FO-3'] },
    });

    await expect(promise).rejects.toBeInstanceOf(VericertsError);
    await expect(promise).rejects.toMatchObject({ code: ErrorCodes.SCHEMA_NOT_SPECIFIED });
  });
});

describe('validateClaimsAgainstCredentialSchema — 取得失敗時の fail-safe（FO-3）', () => {
  it.each<[string, string, StubResponse | undefined]>([
    ['非 HTTPS URL', 'http://issuer.example.com/schemas/person.json', undefined],
    ['HTTP 500', SCHEMA_URL, { status: 500 }],
    ['非 JSON Content-Type', SCHEMA_URL, { json: PERSON_SCHEMA, contentType: 'text/html' }],
    ['ネットワークエラー', SCHEMA_URL, { networkError: true }],
  ])('%s の取得失敗は同意 + 監査記録があれば schema_fetch_failed を警告として返す', async (_label, url, route) => {
    const stub = createFetchStub(route === undefined ? {} : { [url]: route });
    const vc = buildVc({ name: '山田太郎' }, { id: url, type: 'JsonSchema' });

    const result = await validateClaimsAgainstCredentialSchema(vc, {
      fetchImpl: stub.fetchImpl,
      schemaCache: freshCache(),
      nowMs: 1000,
      ...failOpenGrant(),
    });

    expect(result).toEqual({
      valid: true,
      schemaAvailable: false,
      warnings: [FAIL_OPEN_AUDIT_EVENTS['FO-3']],
    });
  });

  it('同意コールバックも監査記録先も無ければ取得失敗をそのまま伝播する', async () => {
    // ここを警告通過させると、同意も監査記録も無いまま
    // 「スキーマ未検証の VC」が valid: true で通ってしまう。
    const stub = createFetchStub({ [SCHEMA_URL]: { status: 500 } });
    const vc = buildVc({ name: '山田太郎' }, { id: SCHEMA_URL, type: 'JsonSchema' });

    const promise = validateClaimsAgainstCredentialSchema(vc, {
      fetchImpl: stub.fetchImpl,
      schemaCache: freshCache(),
      nowMs: 1000,
      failOpenWindow: createFailOpenWindow(),
    });

    await expect(promise).rejects.toBeInstanceOf(VericertsError);
    await expect(promise).rejects.toMatchObject({ code: ErrorCodes.SCHEMA_FETCH_FAILED });
  });

  it('監査記録先だけあり同意コールバックが無ければ取得失敗を伝播する', async () => {
    const stub = createFetchStub({ [SCHEMA_URL]: { status: 500 } });
    const vc = buildVc({ name: '山田太郎' }, { id: SCHEMA_URL, type: 'JsonSchema' });
    const records: FailSafeAuditRecord[] = [];

    const promise = validateClaimsAgainstCredentialSchema(vc, {
      fetchImpl: stub.fetchImpl,
      schemaCache: freshCache(),
      nowMs: 1000,
      onPolicyEvent: (record) => {
        records.push(record);
      },
      failOpenWindow: createFailOpenWindow(),
    });

    await expect(promise).rejects.toMatchObject({ code: ErrorCodes.SCHEMA_FETCH_FAILED });
    // 同意不能も監査の記録対象（user_consent: 'rejected'）。
    expect(records).toEqual([
      {
        policy_event: 'FO-3',
        audit_event: FAIL_OPEN_AUDIT_EVENTS['FO-3'],
        user_consent: 'rejected',
        override: {},
      },
    ]);
  });

  it('同意コールバックだけあり監査記録先が無ければ取得失敗を伝播する', async () => {
    const stub = createFetchStub({ [SCHEMA_URL]: { status: 500 } });
    const vc = buildVc({ name: '山田太郎' }, { id: SCHEMA_URL, type: 'JsonSchema' });

    const promise = validateClaimsAgainstCredentialSchema(vc, {
      fetchImpl: stub.fetchImpl,
      schemaCache: freshCache(),
      nowMs: 1000,
      requestConsent: () => true,
      failOpenWindow: createFailOpenWindow(),
    });

    await expect(promise).rejects.toMatchObject({ code: ErrorCodes.SCHEMA_FETCH_FAILED });
  });

  it('ユーザーが同意しなければ取得失敗を伝播し、不同意も監査記録する', async () => {
    const stub = createFetchStub({ [SCHEMA_URL]: { status: 500 } });
    const vc = buildVc({ name: '山田太郎' }, { id: SCHEMA_URL, type: 'JsonSchema' });
    const records: FailSafeAuditRecord[] = [];

    const promise = validateClaimsAgainstCredentialSchema(vc, {
      fetchImpl: stub.fetchImpl,
      schemaCache: freshCache(),
      nowMs: 1000,
      requestConsent: () => false,
      onPolicyEvent: (record) => {
        records.push(record);
      },
      failOpenWindow: createFailOpenWindow(),
    });

    await expect(promise).rejects.toMatchObject({ code: ErrorCodes.SCHEMA_FETCH_FAILED });
    expect(records.map((r) => r.user_consent)).toEqual(['rejected']);
  });

  it('同意が得られた場合は監査レコードを残して警告通過する', async () => {
    const stub = createFetchStub({ [SCHEMA_URL]: { status: 500 } });
    const vc = buildVc({ name: '山田太郎' }, { id: SCHEMA_URL, type: 'JsonSchema' });
    const records: FailSafeAuditRecord[] = [];

    const result = await validateClaimsAgainstCredentialSchema(vc, {
      fetchImpl: stub.fetchImpl,
      schemaCache: freshCache(),
      nowMs: 1000,
      auditContext: { vc_id: 'vc-1' },
      ...failOpenGrant(records),
    });

    expect(result.warnings).toEqual([FAIL_OPEN_AUDIT_EVENTS['FO-3']]);
    expect(records).toEqual([
      {
        vc_id: 'vc-1',
        policy_event: 'FO-3',
        audit_event: FAIL_OPEN_AUDIT_EVENTS['FO-3'],
        user_consent: 'accepted',
        override: {},
      },
    ]);
  });

  it('escalate: ["FO-3"] なら同意 + 監査記録があっても 3015 を伝播する', async () => {
    const stub = createFetchStub({ [SCHEMA_URL]: { status: 500 } });
    const vc = buildVc({ name: '山田太郎' }, { id: SCHEMA_URL, type: 'JsonSchema' });
    const records: FailSafeAuditRecord[] = [];

    const promise = validateClaimsAgainstCredentialSchema(vc, {
      fetchImpl: stub.fetchImpl,
      schemaCache: freshCache(),
      nowMs: 1000,
      failSafePolicy: { escalate: ['FO-3'] },
      ...failOpenGrant(records),
    });

    await expect(promise).rejects.toBeInstanceOf(VericertsError);
    await expect(promise).rejects.toMatchObject({ code: ErrorCodes.SCHEMA_FETCH_FAILED });
    // `deny` は Fail-open を選んでいないので監査の記録対象ではない（同意も求めない）。
    expect(records).toEqual([]);
  });

  it('3015 / 3016 以外の例外は握りつぶさず再 throw する', async () => {
    // キャッシュ層の想定外エラーを fail-open で飲み込むと、検証したつもりの穴になるため。
    class BrokenCache extends CredentialSchemaCache {
      override get(): undefined {
        throw new RangeError('cache is broken');
      }
    }
    const stub = createFetchStub({ [SCHEMA_URL]: { json: PERSON_SCHEMA } });
    const vc = buildVc({ name: '山田太郎' }, { id: SCHEMA_URL, type: 'JsonSchema' });

    const promise = validateClaimsAgainstCredentialSchema(vc, {
      fetchImpl: stub.fetchImpl,
      schemaCache: new BrokenCache(),
      nowMs: 1000,
      ...failOpenGrant(),
    });

    await expect(promise).rejects.toBeInstanceOf(RangeError);
  });
});
