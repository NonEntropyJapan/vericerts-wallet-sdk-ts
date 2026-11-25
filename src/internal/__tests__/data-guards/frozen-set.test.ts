/**
 * `toFrozenSetView`（変更不能な集合ビュー）の単体テスト。
 *
 * 検証内容:
 * - `add` / `delete` / `clear` は直接呼び出し・`Set.prototype` 経由のいずれも `TypeError` になり、
 *   ビューの中身が書き換わらない。
 * - `forEach` のコールバック第 3 引数がビュー（Proxy）であり、そこから可変な実体が漏れない。
 * - `constructor` / `size` / `Symbol.toStringTag` / `instanceof` といった非メソッドは素通しされ、
 *   ビューが `Set` として振る舞い続ける。
 * - メソッド参照は生成時に 1 度だけ作られ、参照のたびに新しい関数が割り当てられない。
 * - 生成元の反復可能値を後から変更してもビューには伝播しない（独立コピー）。
 *
 * 公開バレルからは到達できない内部ヘルパのため、実装モジュールを直接 import する。
 */

import { describe, expect, it } from 'bun:test';
import { toFrozenSetView } from '../../prototype-safety/frozen-set.js';

const MEMBERS = ['dc+sd-jwt', 'vc+sd-jwt'] as const;
const FOREIGN = 'kb+jwt';

/** テスト対象の標準的なビューを作る。 */
function makeView(): ReadonlySet<string> {
  return toFrozenSetView<string>([...MEMBERS]);
}

describe('toFrozenSetView は変更操作を必ず拒否する', () => {
  it('add / delete / clear の直接呼び出しは TypeError になる', () => {
    const view = makeView();
    const mutable = view as Set<string>;
    expect(() => mutable.add(FOREIGN)).toThrow(TypeError);
    expect(() => mutable.delete(MEMBERS[0])).toThrow(TypeError);
    expect(() => mutable.clear()).toThrow(TypeError);
    expect([...view]).toEqual([...MEMBERS]);
  });

  it('Set.prototype 経由の変更も TypeError になり中身は無傷である', () => {
    const view = makeView();
    expect(() => Set.prototype.add.call(view, FOREIGN)).toThrow(TypeError);
    expect(() => Set.prototype.delete.call(view, MEMBERS[0])).toThrow(TypeError);
    expect(() => Set.prototype.clear.call(view)).toThrow(TypeError);
    expect(view.has(FOREIGN)).toBe(false);
    expect(view.size).toBe(MEMBERS.length);
  });

  it('プロパティの定義・削除・プロトタイプ差し替えも通らない', () => {
    const view = makeView();
    expect(Reflect.set(view, 'injected', 1)).toBe(false);
    expect(Reflect.defineProperty(view, 'injected', { value: 1 })).toBe(false);
    expect(Reflect.deleteProperty(view, 'size')).toBe(false);
    expect(Reflect.setPrototypeOf(view, null)).toBe(false);
    expect(view.size).toBe(MEMBERS.length);
  });
});

describe('toFrozenSetView の forEach は可変な実体を漏らさない', () => {
  it('コールバック第 3 引数はビュー自身であり、そこから add できない', () => {
    const view = makeView();
    const errors: unknown[] = [];
    const receivedSets: unknown[] = [];
    view.forEach((_value, _value2, set) => {
      receivedSets.push(set);
      try {
        (set as Set<string>).add(FOREIGN);
      } catch (error) {
        errors.push(error);
      }
    });

    expect(receivedSets).toEqual([view, view]);
    expect(errors).toHaveLength(MEMBERS.length);
    for (const error of errors) {
      expect(error).toBeInstanceOf(TypeError);
    }
    expect(view.has(FOREIGN)).toBe(false);
    expect([...view]).toEqual([...MEMBERS]);
  });

  it('第 1・第 2 引数は要素値であり、thisArg も従来どおり効く', () => {
    const view = makeView();
    const context = { seen: [] as string[] };
    view.forEach(function collect(this: typeof context, value, value2) {
      expect(value2).toBe(value);
      this.seen.push(value);
    }, context);
    expect(context.seen).toEqual([...MEMBERS]);
  });
});

describe('toFrozenSetView は Set としての読み取り挙動を保つ', () => {
  it('constructor は Set のままで、instanceof / toStringTag も従来どおり', () => {
    const view = makeView();
    expect(view.constructor).toBe(Set);
    expect(view instanceof Set).toBe(true);
    expect(Object.prototype.toString.call(view)).toBe('[object Set]');
  });

  it('has / size / スプレッド / new Set / for...of が動く', () => {
    const view = makeView();
    expect(view.has(MEMBERS[0])).toBe(true);
    expect(view.has(FOREIGN)).toBe(false);
    expect(view.size).toBe(MEMBERS.length);
    expect([...view]).toEqual([...MEMBERS]);
    expect([...new Set(view)]).toEqual([...MEMBERS]);
    expect([...view.keys()]).toEqual([...MEMBERS]);
    expect([...view.values()]).toEqual([...MEMBERS]);
    expect([...view.entries()]).toEqual(MEMBERS.map((m) => [m, m]));
    const iterated: string[] = [];
    for (const value of view) {
      iterated.push(value);
    }
    expect(iterated).toEqual([...MEMBERS]);
  });

  it('size は実体を追随し、拒否された変更のあとも正しい', () => {
    expect(toFrozenSetView([]).size).toBe(0);
    expect(toFrozenSetView(['a', 'a', 'b']).size).toBe(2);
    const view = makeView();
    expect(() => (view as Set<string>).add(FOREIGN)).toThrow(TypeError);
    expect(view.size).toBe(MEMBERS.length);
  });

  it('メソッド参照は生成時に 1 度だけ作られる（参照のたびに再生成しない）', () => {
    const view = makeView();
    expect(view.has).toBe(view.has);
    expect(view.forEach).toBe(view.forEach);
    expect(view[Symbol.iterator]).toBe(view[Symbol.iterator]);
    expect(view.has).not.toBe(makeView().has);
  });

  it('ES2025 の集合演算メソッドが使える（ランタイムが備える場合）', () => {
    const view = makeView();
    if (typeof view.union !== 'function') {
      return;
    }
    expect([...view.union(new Set([FOREIGN]))]).toEqual([...MEMBERS, FOREIGN]);
    expect([...view.intersection(new Set([MEMBERS[0]]))]).toEqual([MEMBERS[0]]);
    expect(view.isSupersetOf(new Set([MEMBERS[0]]))).toBe(true);
    expect(view.isDisjointFrom(new Set([FOREIGN]))).toBe(true);
    // 演算結果は新しい可変 `Set` であり、ビュー自身は変わらない。
    expect(view.size).toBe(MEMBERS.length);
  });
});

describe('toFrozenSetView は生成元から独立したコピーを保持する', () => {
  it('生成元の Set を後から変更してもビューには伝播しない', () => {
    const source = new Set<string>([...MEMBERS]);
    const view = toFrozenSetView(source);
    source.add(FOREIGN);
    source.delete(MEMBERS[0]);
    expect(view.has(FOREIGN)).toBe(false);
    expect(view.has(MEMBERS[0])).toBe(true);
    expect(view.size).toBe(MEMBERS.length);
  });

  it('生成元の配列を後から変更してもビューには伝播しない', () => {
    const source: string[] = [...MEMBERS];
    const view = toFrozenSetView(source);
    source.push(FOREIGN);
    expect(view.has(FOREIGN)).toBe(false);
    expect(view.size).toBe(MEMBERS.length);
  });
});
