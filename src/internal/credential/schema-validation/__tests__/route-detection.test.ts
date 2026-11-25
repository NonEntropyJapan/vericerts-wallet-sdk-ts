/**
 * 検証経路の自動判定のテスト。
 *
 * W3C VC の `credentialSchema` と SD-JWT VC の Type Metadata の検証経路を区別する。
 *
 * 検証内容:
 * - `vct` + `claims` を持つ入力は SD-JWT VC 経路と判定する。
 * - `credentialSubject` を持つ入力は `credentialSchema` 経路と判定する。
 * - どちらとも判定できない入力は `none`（検証せず通過・フェッチもしない）。
 * - **プロトタイプ経由でしか `vct` を持たない**オブジェクトを SD-JWT VC 経路と誤判定しない
 *   （`Object.hasOwn` ベースの判定であること）。
 */

import { describe, expect, it } from 'bun:test';
import { detectSchemaValidationRoute, validateClaimsAgainstSchema } from '../dispatch.js';
import type { SchemaValidatableCredential } from '../types.js';
import {
  buildSdJwt,
  buildVc,
  createFetchStub,
  freshRouteOptions,
  SCHEMA_URL,
  VCT_URL,
} from './fixtures.js';

describe('detectSchemaValidationRoute — 形式からの経路判定', () => {
  it('vct と claims を持つ入力は SD-JWT VC 経路と判定する', () => {
    expect(detectSchemaValidationRoute(buildSdJwt({ given_name: '太郎' }))).toBe(
      'sd-jwt-vc-type-metadata',
    );
  });

  it('credentialSubject を持つ入力は credentialSchema 経路と判定する', () => {
    expect(detectSchemaValidationRoute(buildVc({ name: '山田太郎' }))).toBe(
      'w3c-vc-credential-schema',
    );
  });

  it.each<[string, unknown]>([
    ['null', null],
    ['undefined', undefined],
    ['文字列', 'https://issuer.example.com/vct/person/1.0'],
    ['数値', 42],
    ['配列', [{ vct: 'https://issuer.example.com/vct/person/1.0', claims: {} }]],
    ['空オブジェクト', {}],
    ['claims の無い vct のみ', { vct: 'https://issuer.example.com/vct/person/1.0' }],
    ['vct の無い claims のみ', { claims: { given_name: '太郎' } }],
    ['vct が空文字列', { vct: '', claims: { given_name: '太郎' } }],
    ['claims が object でない', { vct: 'https://issuer.example.com/vct/person/1.0', claims: 'x' }],
    ['credentialSubject が object でない', { credentialSubject: 'x' }],
  ])('%s は none と判定する', (_label, input) => {
    expect(detectSchemaValidationRoute(input)).toBe('none');
  });
});

describe('detectSchemaValidationRoute — プロトタイプ汚染ガード', () => {
  it('プロトタイプ経由でしか vct を持たないオブジェクトは SD-JWT VC 経路にしない', () => {
    // `'vct' in obj` や `obj.vct !== undefined` で判定するとここで誤爆する。
    const polluted = Object.create({ vct: VCT_URL, claims: { given_name: '太郎' } });

    expect(detectSchemaValidationRoute(polluted)).toBe('none');
  });

  it('プロトタイプ由来の vct と自身の credentialSubject が同居しても VC 経路を選ぶ', () => {
    // 継承した `vct` で SD-JWT VC 経路へ逸らし、`credentialSchema` 検証を回避させる細工。
    const polluted: Record<string, unknown> = Object.create({ vct: VCT_URL, claims: {} });
    polluted.credentialSubject = { name: '山田太郎' };

    expect(detectSchemaValidationRoute(polluted)).toBe('w3c-vc-credential-schema');
  });

  it('constructor 等の組み込みプロパティで経路判定が成立しない', () => {
    // `'constructor' in {}` は true になるため、存在チェックの実装差が出やすい箇所。
    expect(detectSchemaValidationRoute({ constructor: Object })).toBe('none');
  });

  it('プロトタイプ経由の vct を渡しても検証せず fetch も呼ばない', async () => {
    const stub = createFetchStub({});
    const polluted = Object.create({
      vct: VCT_URL,
      claims: { given_name: '太郎' },
    }) as SchemaValidatableCredential;

    const result = await validateClaimsAgainstSchema(polluted, {
      fetchImpl: stub.fetchImpl,
      nowMs: 1000,
      ...freshRouteOptions(),
    });

    expect(result).toEqual({ valid: true, schemaAvailable: false, warnings: [], route: 'none' });
    expect(stub.requested).toEqual([]);
  });
});

describe('validateClaimsAgainstSchema — 判定できない入力', () => {
  it('どちらの形式でもない入力は検証せず route: none を返し fetch も呼ばない', async () => {
    const stub = createFetchStub({ [SCHEMA_URL]: { json: {} }, [VCT_URL]: { json: {} } });

    const result = await validateClaimsAgainstSchema({} as SchemaValidatableCredential, {
      fetchImpl: stub.fetchImpl,
      nowMs: 1000,
      ...freshRouteOptions(),
    });

    expect(result).toEqual({ valid: true, schemaAvailable: false, warnings: [], route: 'none' });
    expect(stub.requested).toEqual([]);
  });
});
