/**
 * 経路ディスパッチと両経路へのオプション透過のテスト。
 *
 * FO-3（取得失敗）と FO-4（任意属性違反）の警告通過には、同意コールバックと監査記録先が必要。
 *
 * 検証内容:
 * - SD-JWT VC 形式は Type Metadata 経路（`route: 'sd-jwt-vc-type-metadata'`）で検証される。
 * - W3C VC 形式は `credentialSchema` 経路（`route: 'w3c-vc-credential-schema'`）で検証される。
 * - FO-3 / FO-4 の警告が両経路とも `route` 付きでそのまま透過する。
 * - 同意コールバック・監査記録先・監査相関情報が選ばれた経路へ透過し、渡されていなければ
 *   両経路とも Fail-closed に倒れる。
 * - `failSafePolicy.escalate` が両経路へ透過し、各経路のエラーコードで伝播する。
 * - `fetchImpl` / `nowMs` / 経路固有キャッシュが選ばれた経路へ渡る。
 *
 * 両形式のシグナルを併せ持つ入力（`route: 'both'`）は `ambiguous.test.ts` で検証する。
 */

import { describe, expect, it } from 'bun:test';
import { ErrorCodes, VericertsError } from '../../../errors.js';
import { FAIL_OPEN_AUDIT_EVENTS } from '../../../failsafe/index.js';
import type { FailSafeAuditRecord } from '../../../failsafe-policy/index.js';
import { TYPE_METADATA_CACHE_TTL_MS } from '../../sdjwt/type-metadata/types.js';
import { validateClaimsAgainstSchema } from '../dispatch.js';
import {
  buildSdJwt,
  buildVc,
  createFetchStub,
  failOpenGrant,
  freshRouteOptions,
  PERSON_SCHEMA,
  PERSON_TYPE_METADATA,
  SCHEMA_URL,
  VCT_URL,
} from './fixtures.js';

/** `credentialSchema` を持つ W3C VC を組み立てる。 */
function buildVcWithSchema(credentialSubject: Readonly<Record<string, unknown>>) {
  return buildVc(credentialSubject, { id: SCHEMA_URL, type: 'JsonSchema' });
}

describe('validateClaimsAgainstSchema — SD-JWT VC 経路', () => {
  it('vct + claims の入力は Type Metadata 経路で検証する', async () => {
    const stub = createFetchStub({ [VCT_URL]: { json: PERSON_TYPE_METADATA } });

    const result = await validateClaimsAgainstSchema(
      buildSdJwt({ given_name: '太郎', nickname: 'たろ' }),
      { fetchImpl: stub.fetchImpl, nowMs: 1000, ...freshRouteOptions() },
    );

    expect(result).toEqual({
      valid: true,
      schemaAvailable: true,
      warnings: [],
      route: 'sd-jwt-vc-type-metadata',
    });
    expect(stub.requested).toEqual([VCT_URL]);
  });

  it('必須属性違反は required: true の違反として route 付きで返る', async () => {
    const stub = createFetchStub({ [VCT_URL]: { json: PERSON_TYPE_METADATA } });

    const result = await validateClaimsAgainstSchema(buildSdJwt({ nickname: 'たろ' }), {
      fetchImpl: stub.fetchImpl,
      nowMs: 1000,
      ...freshRouteOptions(),
    });

    expect(result.route).toBe('sd-jwt-vc-type-metadata');
    expect(result.valid).toBe(false);
    expect(result.errors?.some((e) => e.required)).toBe(true);
    expect(result.warnings).toEqual([]);
  });

  it('任意属性のみの違反は FO-4 の警告が透過する', async () => {
    const stub = createFetchStub({ [VCT_URL]: { json: PERSON_TYPE_METADATA } });

    const result = await validateClaimsAgainstSchema(
      buildSdJwt({ given_name: '太郎', nickname: 'ながすぎるニックネームです' }),
      { fetchImpl: stub.fetchImpl, nowMs: 1000, ...freshRouteOptions(), ...failOpenGrant() },
    );

    expect(result.route).toBe('sd-jwt-vc-type-metadata');
    // FO-4 の既定は警告通過（valid: true）。違反内容は errors に残る。
    expect(result.valid).toBe(true);
    expect(result.warnings).toEqual([FAIL_OPEN_AUDIT_EVENTS['FO-4']]);
    expect(result.errors?.length).toBeGreaterThan(0);
  });

  it('vct が HTTPS URL でなければ Type Metadata 経路のまま検証をスキップする', async () => {
    const stub = createFetchStub({});

    const result = await validateClaimsAgainstSchema(
      buildSdJwt({ given_name: '太郎' }, 'urn:example:person'),
      { fetchImpl: stub.fetchImpl, nowMs: 1000, ...freshRouteOptions() },
    );

    expect(result).toEqual({
      valid: true,
      schemaAvailable: false,
      warnings: [],
      route: 'sd-jwt-vc-type-metadata',
    });
    expect(stub.requested).toEqual([]);
  });
});

describe('validateClaimsAgainstSchema — W3C VC 経路', () => {
  it('credentialSubject + credentialSchema の入力は credentialSchema 経路で検証する', async () => {
    const stub = createFetchStub({ [SCHEMA_URL]: { json: PERSON_SCHEMA } });

    const result = await validateClaimsAgainstSchema(
      buildVcWithSchema({ name: '山田太郎', nickname: 'たろ' }),
      { fetchImpl: stub.fetchImpl, nowMs: 1000, ...freshRouteOptions() },
    );

    expect(result).toEqual({
      valid: true,
      schemaAvailable: true,
      warnings: [],
      route: 'w3c-vc-credential-schema',
    });
    expect(stub.requested).toEqual([SCHEMA_URL]);
  });

  it('credentialSchema を持たない VC も VC 経路として検証対象なしを返す', async () => {
    const stub = createFetchStub({});

    const result = await validateClaimsAgainstSchema(buildVc({ name: '山田太郎' }), {
      fetchImpl: stub.fetchImpl,
      nowMs: 1000,
      ...freshRouteOptions(),
    });

    expect(result).toEqual({
      valid: true,
      schemaAvailable: false,
      warnings: [],
      route: 'w3c-vc-credential-schema',
    });
    expect(stub.requested).toEqual([]);
  });

  it('任意属性のみの違反は FO-4 の警告が透過する', async () => {
    const stub = createFetchStub({ [SCHEMA_URL]: { json: PERSON_SCHEMA } });

    const result = await validateClaimsAgainstSchema(
      buildVcWithSchema({ name: '山田太郎', nickname: 'ながすぎるニックネームです' }),
      { fetchImpl: stub.fetchImpl, nowMs: 1000, ...freshRouteOptions(), ...failOpenGrant() },
    );

    expect(result.route).toBe('w3c-vc-credential-schema');
    // FO-4 の既定は警告通過（valid: true）。違反内容は errors に残る。
    expect(result.valid).toBe(true);
    expect(result.warnings).toEqual([FAIL_OPEN_AUDIT_EVENTS['FO-4']]);
    expect(result.errors?.length).toBeGreaterThan(0);
  });
});

describe('validateClaimsAgainstSchema — fail-open（FO-3）が両経路で透過する', () => {
  it('SD-JWT VC 経路の取得失敗は schema_fetch_failed を警告として返す', async () => {
    const stub = createFetchStub({ [VCT_URL]: { status: 500 } });

    const result = await validateClaimsAgainstSchema(buildSdJwt({ given_name: '太郎' }), {
      fetchImpl: stub.fetchImpl,
      nowMs: 1000,
      ...freshRouteOptions(),
      ...failOpenGrant(),
    });

    expect(result).toEqual({
      valid: true,
      schemaAvailable: false,
      warnings: [FAIL_OPEN_AUDIT_EVENTS['FO-3']],
      route: 'sd-jwt-vc-type-metadata',
    });
  });

  it('W3C VC 経路の取得失敗は schema_fetch_failed を警告として返す', async () => {
    const stub = createFetchStub({ [SCHEMA_URL]: { status: 500 } });

    const result = await validateClaimsAgainstSchema(buildVcWithSchema({ name: '山田太郎' }), {
      fetchImpl: stub.fetchImpl,
      nowMs: 1000,
      ...freshRouteOptions(),
      ...failOpenGrant(),
    });

    expect(result).toEqual({
      valid: true,
      schemaAvailable: false,
      warnings: [FAIL_OPEN_AUDIT_EVENTS['FO-3']],
      route: 'w3c-vc-credential-schema',
    });
  });
});

describe('validateClaimsAgainstSchema — 同意 / 監査オプションが両経路へ透過する', () => {
  it.each<[string, () => unknown, string]>([
    ['SD-JWT VC', () => buildSdJwt({ given_name: '太郎' }), VCT_URL],
    ['W3C VC', () => buildVcWithSchema({ name: '山田太郎' }), SCHEMA_URL],
  ])('%s 経路で同意コールバックも監査記録先も無ければ取得失敗を伝播する', async (_label, build, url) => {
    // 回帰。ディスパッチャ経由でも「同意 + 監査記録が無ければ通さない」を保つ。
    const stub = createFetchStub({ [url]: { status: 500 } });

    const promise = validateClaimsAgainstSchema(build() as never, {
      fetchImpl: stub.fetchImpl,
      nowMs: 1000,
      ...freshRouteOptions(),
    });

    await expect(promise).rejects.toBeInstanceOf(VericertsError);
  });

  it('監査レコードは選ばれた経路から呼び出し側のシンクへ届く', async () => {
    const stub = createFetchStub({ [SCHEMA_URL]: { status: 500 } });
    const records: FailSafeAuditRecord[] = [];

    await validateClaimsAgainstSchema(buildVcWithSchema({ name: '山田太郎' }), {
      fetchImpl: stub.fetchImpl,
      nowMs: 1000,
      auditContext: { trace_id: 'trace-1' },
      requestConsent: () => true,
      onPolicyEvent: (record) => {
        records.push(record);
      },
      ...freshRouteOptions(),
    });

    expect(records).toEqual([
      {
        trace_id: 'trace-1',
        policy_event: 'FO-3',
        audit_event: FAIL_OPEN_AUDIT_EVENTS['FO-3'],
        user_consent: 'accepted',
        override: {},
      },
    ]);
  });
});

describe('validateClaimsAgainstSchema — failSafePolicy が両経路へ透過する', () => {
  it('SD-JWT VC 経路では 3060 を伝播する', async () => {
    const stub = createFetchStub({ [VCT_URL]: { status: 500 } });

    const promise = validateClaimsAgainstSchema(buildSdJwt({ given_name: '太郎' }), {
      fetchImpl: stub.fetchImpl,
      nowMs: 1000,
      failSafePolicy: { escalate: ['FO-3'] },
      ...freshRouteOptions(),
      ...failOpenGrant(),
    });

    await expect(promise).rejects.toBeInstanceOf(VericertsError);
    await expect(promise).rejects.toMatchObject({
      code: ErrorCodes.TYPE_METADATA_FETCH_FAILED,
    });
  });

  it('W3C VC 経路では 3015 を伝播する', async () => {
    const stub = createFetchStub({ [SCHEMA_URL]: { status: 500 } });

    const promise = validateClaimsAgainstSchema(buildVcWithSchema({ name: '山田太郎' }), {
      fetchImpl: stub.fetchImpl,
      nowMs: 1000,
      failSafePolicy: { escalate: ['FO-3'] },
      ...freshRouteOptions(),
      ...failOpenGrant(),
    });

    await expect(promise).rejects.toBeInstanceOf(VericertsError);
    await expect(promise).rejects.toMatchObject({ code: ErrorCodes.SCHEMA_FETCH_FAILED });
  });
});

describe('validateClaimsAgainstSchema — nowMs と経路固有キャッシュの透過', () => {
  it('同じキャッシュと同じ nowMs なら 2 回目はフェッチしない', async () => {
    const stub = createFetchStub({ [VCT_URL]: { json: PERSON_TYPE_METADATA } });
    const routeOptions = freshRouteOptions();
    const credential = buildSdJwt({ given_name: '太郎' });

    await validateClaimsAgainstSchema(credential, {
      fetchImpl: stub.fetchImpl,
      nowMs: 1000,
      ...routeOptions,
    });
    await validateClaimsAgainstSchema(credential, {
      fetchImpl: stub.fetchImpl,
      nowMs: 1000,
      ...routeOptions,
    });

    expect(stub.requested).toEqual([VCT_URL]);
  });

  it('nowMs が TTL を超えて進むと再フェッチする（nowMs が経路へ渡っている証拠）', async () => {
    const stub = createFetchStub({ [VCT_URL]: { json: PERSON_TYPE_METADATA } });
    const routeOptions = freshRouteOptions();
    const credential = buildSdJwt({ given_name: '太郎' });

    await validateClaimsAgainstSchema(credential, {
      fetchImpl: stub.fetchImpl,
      nowMs: 1000,
      ...routeOptions,
    });
    await validateClaimsAgainstSchema(credential, {
      fetchImpl: stub.fetchImpl,
      nowMs: 1000 + TYPE_METADATA_CACHE_TTL_MS,
      ...routeOptions,
    });

    expect(stub.requested).toEqual([VCT_URL, VCT_URL]);
  });
});
