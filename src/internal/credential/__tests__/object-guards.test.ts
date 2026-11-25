/**
 * 共有ヘルパー `internal/credential/object-guards.ts` の判定規則を固定するテスト。
 *
 * `wallet/did/facade.ts` / `presentation-exchange/{evaluate,definition}.ts` /
 * `credential/{json-schema/object-properties,manifest/parse,sdjwt/claims,
 * schema-validation/dispatch,evidence-tou/{evidence,odrl}}.ts` /
 * `wallet-migration/backup-serialize.ts` に個別定義されていた同一ロジック（配列を除く非 null
 * オブジェクトか）を {@link isPlainObject} へ集約した際の**挙動不変**を担保する。
 */

import { describe, expect, it } from 'bun:test';
import { isPlainObject } from '../object-guards.js';

describe('isPlainObject', () => {
  it('プレーンオブジェクトは true', () => {
    expect(isPlainObject({})).toBe(true);
    expect(isPlainObject({ a: 1 })).toBe(true);
    expect(isPlainObject(Object.create(null))).toBe(true);
  });

  it('null は false', () => {
    expect(isPlainObject(null)).toBe(false);
  });

  it('配列は false（除外対象）', () => {
    expect(isPlainObject([])).toBe(false);
    expect(isPlainObject([1, 2, 3])).toBe(false);
  });

  it('プリミティブ・関数・undefined は false', () => {
    expect(isPlainObject('string')).toBe(false);
    expect(isPlainObject(42)).toBe(false);
    expect(isPlainObject(true)).toBe(false);
    expect(isPlainObject(undefined)).toBe(false);
    expect(isPlainObject(() => {})).toBe(false);
  });
});
