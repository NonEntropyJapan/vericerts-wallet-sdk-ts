/**
 * `parseJsonWithoutPrototype` が素の `JSON.parse` + 1 回の反復走査で動くこと。
 *
 * reviver 付き `JSON.parse` は V8 の高速経路を外れ、素の 5〜40 倍遅かった（1 MiB 未満の本文 9 通で 3.4 秒）。
 * 実時間ではなく、reviver が渡されないこと・全オブジェクトが `null` プロトタイプになること・
 * 深さ上限の境界で pin する。要素の形（空オブジェクト / 配列 / 数値 / 入れ子）を変えた複数形状で確認する。
 */

import { afterEach, describe, expect, spyOn, test } from 'bun:test';
import {
  MAX_JSON_NESTING_DEPTH,
  parseJsonWithoutPrototype,
} from '../../prototype-safety/parse-json.js';

let parseSpy: { mockRestore(): void; mock: { calls: unknown[][] } } | undefined;
afterEach(() => {
  parseSpy?.mockRestore();
  parseSpy = undefined;
});

/** `root` 以下の全オブジェクト（配列は除く）が `null` プロトタイプかを反復で確かめる。 */
function allPlainObjectsAreNullProto(root: unknown): boolean {
  const stack: unknown[] = [root];
  while (stack.length > 0) {
    const node = stack.pop();
    if (node === null || typeof node !== 'object') {
      continue;
    }
    if (!Array.isArray(node) && Object.getPrototypeOf(node) !== null) {
      return false;
    }
    stack.push(...Object.values(node));
  }
  return true;
}

describe('parseJsonWithoutPrototype: reviver を使わない', () => {
  const shapes: [string, string][] = [
    ['空オブジェクトの巨大配列', `[${Array(50_000).fill('{}').join(',')}]`],
    ['空配列の巨大配列', `[${Array(50_000).fill('[]').join(',')}]`],
    ['数値の巨大配列', `[${Array(100_000).fill('1234').join(',')}]`],
    ['キー付きオブジェクトの配列', `[${Array(10_000).fill('{"a":1,"b":[{"c":null}]}').join(',')}]`],
    ['少数の巨大な文字列', `{"pad":"${'x'.repeat(1_000_000)}"}`],
  ];

  test.each(
    shapes,
  )('%s: JSON.parse は reviver 無しで 1 回だけ呼ばれ、全オブジェクトが null プロトタイプ', (_name, text) => {
    parseSpy = spyOn(JSON, 'parse');
    const parsed = parseJsonWithoutPrototype(text);
    expect(parseSpy.mock.calls).toHaveLength(1);
    expect(parseSpy.mock.calls[0]).toHaveLength(1);
    expect(allPlainObjectsAreNullProto(parsed)).toBe(true);
  });

  test('__proto__ キーは own のデータプロパティのまま保たれ、プロトタイプを書き換えない', () => {
    const parsed = parseJsonWithoutPrototype('{"a":{"__proto__":{"polluted":1}}}') as {
      a: Record<string, unknown>;
    };
    expect(Object.hasOwn(parsed.a, '__proto__')).toBe(true);
    expect(Object.getPrototypeOf(parsed.a)).toBeNull();
    expect(({} as Record<string, unknown>).polluted).toBeUndefined();
  });
});

describe('parseJsonWithoutPrototype: ネスト深さの上限', () => {
  const nested = (depth: number) => '{"a":'.repeat(depth - 1) + '{}' + '}'.repeat(depth - 1);
  const nestedArrays = (depth: number) => '['.repeat(depth) + ']'.repeat(depth);

  test.each([
    ['オブジェクトの入れ子', nested],
    ['配列の入れ子', nestedArrays],
  ])('%s: 上限ちょうどは通り、1 段超は SyntaxError', (_name, build) => {
    expect(() => parseJsonWithoutPrototype(build(MAX_JSON_NESTING_DEPTH))).not.toThrow();
    expect(() => parseJsonWithoutPrototype(build(MAX_JSON_NESTING_DEPTH + 1))).toThrow(SyntaxError);
  });

  test('深い入れ子でもスタックを枯渇させない（RangeError ではなく SyntaxError）', () => {
    expect(() => parseJsonWithoutPrototype(nested(5_000))).toThrow(SyntaxError);
  });
});
