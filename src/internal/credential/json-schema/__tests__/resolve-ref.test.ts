/**
 * `$ref` 解決のハードニング回帰テスト。
 *
 * `resolveRef` は JSON Pointer のセグメントを 1 つずつ辿るが、素朴なプロパティアクセスだと
 * `#/constructor/prototype` や `#/__proto__` が**プロトタイプチェーン上のオブジェクト**へ
 * 到達し、それを「解決できたスキーマ」として扱ってしまう。自身のプロパティのみを辿る
 * ことで、こうした参照が必ず違反（解決不能）になることを保証する。
 *
 * あわせて、不正なパーセントエンコード（`#/%` 等）で `decodeURIComponent` が `URIError` を
 * 投げ、「例外を投げず `errors` にまとめて返す」という `validateAgainstSchema` の契約が破れる
 * 欠陥（C5）の回帰も押さえる。スキーマは Issuer が配布するリモート文書なので、この例外は
 * fail-open 入口（FO-3 / FO-4）を未捕捉例外に化けさせる。
 */

import { describe, expect, it } from 'bun:test';
import { resolveRef } from '../ref.js';
import { validateAgainstSchema } from '../validate.js';

describe('resolveRef — プロトタイプチェーンを辿らない', () => {
  it.each([
    ['#/constructor/prototype'],
    ['#/__proto__'],
    ['#/__proto__/constructor'],
    ['#/toString'],
    ['#/properties/name/__proto__'],
  ])('%s は解決できない（undefined）', (ref) => {
    const root = { type: 'object', properties: { name: { type: 'string' } } };
    expect(resolveRef(root, ref)).toBeUndefined();
  });

  it('自身のプロパティ経由のローカル参照は従来どおり解決する', () => {
    const root = { $defs: { name: { type: 'string' } } };
    expect(resolveRef(root, '#/$defs/name')).toEqual({ type: 'string' });
    expect(resolveRef(root, '#')).toBe(root);
  });
});

describe('validateAgainstSchema — プロトタイプ経由 $ref は違反になる', () => {
  it.each([
    ['#/constructor/prototype'],
    ['#/__proto__'],
  ])('$ref: %s は解決不能として報告し、値を素通しにしない', (ref) => {
    const schema = { type: 'object', properties: { name: { $ref: ref } } };
    const result = validateAgainstSchema(schema, { name: 12345 });

    expect(result.valid).toBe(false);
    const errors = result.errors ?? [];
    expect(errors.length).toBe(1);
    expect(errors[0]?.path).toBe('/name');
    expect(errors[0]?.message).toContain('$ref');
  });
});

describe('resolveRef — 不正なパーセントエンコードで例外を投げない（C5）', () => {
  it.each([
    ['#/%'],
    ['#/%zz'],
    ['#/$defs/%E0%A4%A'],
    ['#/a/%/b'],
  ])('%s は例外にせず解決不能（undefined）として扱う', (ref) => {
    const root = { $defs: { name: { type: 'string' } } };
    expect(() => resolveRef(root, ref)).not.toThrow();
    expect(resolveRef(root, ref)).toBeUndefined();
  });

  it('validateAgainstSchema は例外を投げず違反として報告する', () => {
    const schema = { $ref: '#/%' };
    let result: ReturnType<typeof validateAgainstSchema> | undefined;
    expect(() => {
      result = validateAgainstSchema(schema, { name: 'x' });
    }).not.toThrow();
    expect(result?.valid).toBe(false);
    expect(result?.errors?.[0]?.message).toContain('$ref');
  });

  it('パーセントエンコードされた正当なセグメントは従来どおり解決する', () => {
    const root = { $defs: { 'a b': { type: 'string' } } };
    expect(resolveRef(root, '#/$defs/a%20b')).toEqual({ type: 'string' });
  });
});
