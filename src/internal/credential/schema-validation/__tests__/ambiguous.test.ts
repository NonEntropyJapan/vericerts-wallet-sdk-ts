/**
 * 両形式のシグナルを併せ持つ入力の扱い（回帰テスト）。
 *
 * `vct` + `claims` と `credentialSubject` を**自身のプロパティとして同時に持つ**入力を、
 * 分岐の記述順で片方へ倒すと、良性の `vct`（Type Metadata にスキーマ無し = `valid: true`）を
 * 併記するだけで実際の `credentialSchema` 検証を回避できてしまう。優先順位を付けず両経路で
 * 検証し、結果を合成する（`route: 'both'`）。
 *
 * 検証内容:
 * - 両シグナルを持つ入力は `both` と判定する。
 * - 良性の `vct` を併記しても `credentialSchema` 側の必須属性違反が消えない（回避不能）。
 * - 合成結果の `valid` は AND、`warnings` は和集合、`errors` は連結。
 * - プロトタイプ由来の `vct` は `both` にならない（`Object.hasOwn` 判定）。
 */

import { describe, expect, it } from 'bun:test';
import { FAIL_OPEN_AUDIT_EVENTS } from '../../../failsafe/index.js';
import { detectSchemaValidationRoute, validateClaimsAgainstSchema } from '../dispatch.js';
import type { SchemaValidatableCredential } from '../types.js';
import {
  buildVc,
  createFetchStub,
  failOpenGrant,
  freshRouteOptions,
  PERSON_SCHEMA,
  PERSON_TYPE_METADATA,
  SCHEMA_URL,
  VCT_URL,
} from './fixtures.js';

/** スキーマを持たない（＝それ自体では必ず通る）良性の Type Metadata。 */
const EMPTY_TYPE_METADATA = { vct: VCT_URL, name: 'Benign' };

/** `vct` + `claims` と `credentialSubject` + `credentialSchema` を同時に持つ入力を組み立てる。 */
function buildAmbiguous(
  credentialSubject: Readonly<Record<string, unknown>>,
  claims: Readonly<Record<string, unknown>> = {},
): SchemaValidatableCredential {
  return {
    ...buildVc(credentialSubject, { id: SCHEMA_URL, type: 'JsonSchema' }),
    vct: VCT_URL,
    claims,
  } as unknown as SchemaValidatableCredential;
}

describe('detectSchemaValidationRoute — 両シグナルの同居', () => {
  it('vct + claims と credentialSubject を自身のプロパティに持つ入力は both と判定する', () => {
    expect(detectSchemaValidationRoute(buildAmbiguous({ name: '山田太郎' }))).toBe('both');
  });

  it('プロトタイプ由来の vct では both にならない（自身のプロパティのみを見る）', () => {
    const polluted: Record<string, unknown> = Object.create({ vct: VCT_URL, claims: {} });
    polluted.credentialSubject = { name: '山田太郎' };

    expect(detectSchemaValidationRoute(polluted)).toBe('w3c-vc-credential-schema');
  });
});

describe('validateClaimsAgainstSchema — both は両経路を課す', () => {
  it('良性の vct を併記しても credentialSchema の必須属性違反を回避できない', async () => {
    const stub = createFetchStub({
      [VCT_URL]: { json: EMPTY_TYPE_METADATA },
      [SCHEMA_URL]: { json: PERSON_SCHEMA },
    });

    // name（必須）を欠く credentialSubject。SD-JWT VC 側は制約が無いので単体なら通る。
    const result = await validateClaimsAgainstSchema(buildAmbiguous({ nickname: 'たろ' }), {
      fetchImpl: stub.fetchImpl,
      nowMs: 1000,
      ...freshRouteOptions(),
    });

    expect(result.route).toBe('both');
    expect(result.valid).toBe(false);
    expect(result.errors?.some((e) => e.required)).toBe(true);
    expect(stub.requested).toEqual([VCT_URL, SCHEMA_URL]);
  });

  it('両経路とも適合すれば valid: true（警告なし）', async () => {
    const stub = createFetchStub({
      [VCT_URL]: { json: PERSON_TYPE_METADATA },
      [SCHEMA_URL]: { json: PERSON_SCHEMA },
    });

    const result = await validateClaimsAgainstSchema(
      buildAmbiguous({ name: '山田太郎' }, { given_name: '太郎' }),
      { fetchImpl: stub.fetchImpl, nowMs: 1000, ...freshRouteOptions() },
    );

    expect(result).toEqual({
      valid: true,
      schemaAvailable: true,
      warnings: [],
      route: 'both',
    });
  });

  it('両経路の FO 監査キーは和集合にまとめる（同じ ID を 2 回並べない）', async () => {
    const stub = createFetchStub({
      [VCT_URL]: { json: PERSON_TYPE_METADATA },
      [SCHEMA_URL]: { json: PERSON_SCHEMA },
    });

    // どちらの経路でも任意属性（nickname）だけが違反する = FO-4 が両方で立つ。
    const result = await validateClaimsAgainstSchema(
      buildAmbiguous(
        { name: '山田太郎', nickname: 'ながすぎるニックネームです' },
        { given_name: '太郎', nickname: 'ながすぎるニックネームです' },
      ),
      { fetchImpl: stub.fetchImpl, nowMs: 1000, ...freshRouteOptions(), ...failOpenGrant() },
    );

    expect(result.route).toBe('both');
    expect(result.valid).toBe(true);
    expect(result.warnings).toEqual([FAIL_OPEN_AUDIT_EVENTS['FO-4']]);
    expect(result.errors).toHaveLength(2);
  });

  it('片方が取得失敗でももう片方の検証結果は失わない', async () => {
    const stub = createFetchStub({
      [VCT_URL]: { status: 500 },
      [SCHEMA_URL]: { json: PERSON_SCHEMA },
    });

    const result = await validateClaimsAgainstSchema(buildAmbiguous({ nickname: 'たろ' }), {
      fetchImpl: stub.fetchImpl,
      nowMs: 1000,
      ...freshRouteOptions(),
      ...failOpenGrant(),
    });

    expect(result.route).toBe('both');
    // Type Metadata 側は FO-3 で警告通過、credentialSchema 側は必須違反で valid: false。
    expect(result.warnings).toEqual([FAIL_OPEN_AUDIT_EVENTS['FO-3']]);
    expect(result.valid).toBe(false);
    expect(result.schemaAvailable).toBe(true);
  });
});
