/**
 * `internal/prototype-safety/deep-snapshot.ts` の保全範囲と「既知の限界」のテスト。
 *
 * 契約の中核（アクセサを 1 度だけ評価して畳むこと・複製対象をプレーンなコンテナに限ること）は
 * `deep-snapshot.test.ts` にある。本ファイルはその周辺で「元の入力と一致していなければならない
 * もの」と「意識的に一致させないもの」を固定する。
 *
 * - **保全**: プロパティ記述子（列挙可能性）/ `Symbol` キー / 入れ子の `undefined` / `null` /
 *   配列の穴と `length` / 循環参照と共有参照のグラフ形状 / 深い入れ子でのスタック安全性。
 *   列挙可能性を落とすと `JSON.stringify` の出力が変わり（非列挙だったキーが署名済み出力に載る）、
 *   非列挙を写さないと Art.9 走査（`Object.getOwnPropertyNames`）の検知範囲が狭まる。どちらも退行。
 * - **既知の限界**: 参照のまま残す対象の own アクセサは畳まれない／プレーンなコンテナを包む
 *   `Proxy` は**限界に入らない**（複製対象なので `ownKeys` は 1 度だけ呼ばれる）／own の
 *   throwing getter の例外はそのまま伝播する（正規化は呼び出し側の責務）。
 *
 * 1 ファイル 300 行の上限（`.linterly.yml`）に収めるため `deep-snapshot.test.ts` から分けている。
 */

import { describe, expect, it } from 'bun:test';
import { deepSnapshot } from '../../prototype-safety/deep-snapshot.js';
import { defineCountedAccessor } from '../accessor-toctou.fixtures.js';
import { withPollutedPrototype } from '../prototype-pollution.fixtures.js';

describe('deepSnapshot: 値・記述子・グラフの保全', () => {
  it('入れ子の undefined / null / 配列 / null プロトタイプを保つ', () => {
    const nullProto = Object.create(null) as Record<string, unknown>;
    nullProto.kind = 'bare';

    const snapshot = deepSnapshot({
      meta: { absent: undefined, empty: null, tags: ['a', 'b'], nullProto },
    }) as Record<string, unknown>;
    const meta = snapshot.meta as Record<string, unknown>;

    expect(Object.hasOwn(meta, 'absent')).toBe(true);
    expect(meta.absent).toBeUndefined();
    expect(meta.empty).toBeNull();
    expect(meta.tags).toEqual(['a', 'b']);
    expect(Array.isArray(meta.tags)).toBe(true);
    expect(Object.getPrototypeOf(meta.nullProto as object)).toBeNull();
    // 中身までアサートする。プロトタイプだけ見ると「null プロトタイプの入れ子が空の複製に
    // なる」退行を検知できない。
    expect((meta.nullProto as Record<string, unknown>).kind).toBe('bare');
  });

  it('非列挙 own プロパティは非列挙のまま写す（JSON 出力と走査範囲を同時に保つ）', () => {
    const source: Record<string, unknown> = { visible: 1 };
    Object.defineProperty(source, 'hidden', {
      configurable: true,
      enumerable: false,
      value: 'secret',
      writable: true,
    });

    const snapshot = deepSnapshot(source) as Record<string, unknown>;

    // Art.9 走査（`Object.getOwnPropertyNames`）からは見える。
    expect(Object.getOwnPropertyNames(snapshot)).toContain('hidden');
    // JSON 化（`Object.keys`）からは見えない = 出力は元と一致する。
    expect(Object.keys(snapshot)).not.toContain('hidden');
    expect(JSON.stringify(snapshot)).toBe(JSON.stringify(source));
  });

  it('Symbol キーの own プロパティも写す（記述子ごと引き継ぐ）', () => {
    const tag = Symbol('tag');
    const source: Record<string | symbol, unknown> = { a: 1 };
    source[tag] = 'symbol-value';

    const snapshot = deepSnapshot(source) as Record<string | symbol, unknown>;

    expect(Reflect.ownKeys(snapshot)).toContain(tag);
    expect(snapshot[tag]).toBe('symbol-value');
    // Symbol キーは JSON に現れないため出力は変わらない。
    expect(JSON.stringify(snapshot)).toBe(JSON.stringify(source));
  });

  it('循環参照でも停止し、循環と共有参照を保つ', () => {
    const cyclic: Record<string, unknown> = { kind: 'node' };
    cyclic.self = cyclic;
    const shared = { id: 'shared' };

    const snapshot = deepSnapshot({ cyclic, first: shared, second: shared }) as Record<
      string,
      unknown
    >;
    const copied = snapshot.cyclic as Record<string, unknown>;

    expect(copied.self).toBe(copied);
    expect(copied).not.toBe(cyclic);
    expect(snapshot.first).toBe(snapshot.second);
    expect(snapshot.first).not.toBe(shared);
  });

  it('配列の穴と length を保つ', () => {
    const sparse: unknown[] = [1];
    sparse.length = 3;

    const copied = (deepSnapshot({ sparse }) as { sparse: unknown[] }).sparse;

    expect(copied.length).toBe(3);
    expect(JSON.stringify(copied)).toBe('[1,null,null]');
  });

  it('深い入れ子でもスタックオーバーフローしない（再帰ではなく明示スタック）', () => {
    const depth = 20_000;
    const root: Record<string, unknown> = {};
    let cursor = root;
    for (let i = 0; i < depth; i += 1) {
      const next: Record<string, unknown> = {};
      cursor.next = next;
      cursor = next;
    }

    const snapshot = deepSnapshot(root) as Record<string, unknown>;

    let walked = 0;
    let node: Record<string, unknown> | undefined = snapshot;
    while (node?.next !== undefined) {
      node = node.next as Record<string, unknown>;
      walked += 1;
    }
    expect(walked).toBe(depth);
  });
});

describe('deepSnapshot: 既知の限界（文書化した範囲どおりであること）', () => {
  it('参照のまま残す対象の own アクセサは畳まれない', () => {
    class Sub extends Array<unknown> {}
    const sub = new Sub();
    const reads = defineCountedAccessor(sub as unknown as Record<string, unknown>, 'flag', [
      'first',
      'second',
    ]);

    const snapshot = deepSnapshot({ records: sub }) as Record<string, unknown>;
    const kept = snapshot.records as unknown as Record<string, unknown>;

    expect(kept).toBe(sub as unknown as Record<string, unknown>);
    expect(reads()).toBe(0);
    expect(kept.flag).toBe('first');
    expect(kept.flag).toBe('second');
  });

  it('プレーンなコンテナを包む Proxy は限界に入らない（ownKeys は 1 度だけ呼ばれ確定値に畳まれる）', () => {
    // で実測。`isPlainContainer` は `Object.getPrototypeOf`（= ターゲットの
    // プロトタイプ）で判定するため、プレーンなコンテナを包む Proxy は複製対象になる。
    let ownKeysCalls = 0;
    const target = { a: 1, healthData: 'HIV+' };
    const proxy = new Proxy(target, {
      ownKeys(): ArrayLike<string | symbol> {
        ownKeysCalls += 1;
        return ownKeysCalls === 1 ? ['a'] : ['a', 'healthData'];
      },
      getOwnPropertyDescriptor(t, k): PropertyDescriptor | undefined {
        return Object.getOwnPropertyDescriptor(t, k);
      },
    });

    const snapshot = deepSnapshot({ nested: proxy }) as Record<string, unknown>;

    // 判別力の中核は「トラップが 1 度しか呼ばれず、複製が Proxy を参照しない」ことである。
    expect(ownKeysCalls).toBe(1);
    expect(snapshot.nested).not.toBe(proxy);
    expect(JSON.stringify(snapshot)).toBe('{"nested":{"a":1}}');
    // Proxy を直接読めば 2 回目は隠れていたキーが現れる（＝ 汚染の仕込みが有効であることの
    // 対照。これが無いと「そもそも Proxy が何もしていない」だけでテストが通ってしまう）。
    expect(Object.keys(proxy)).toEqual(['a', 'healthData']);
    expect(ownKeysCalls).toBe(2);
  });

  it('getPrototypeOf トラップを持つ Proxy でもプロトタイプは 1 度しか読まれない（複製先が差し替わらない）', () => {
    // （major）。判定（`plainContainerPrototype`）と複製
    // （`createEmptyCopy`）でプロトタイプを 2 度読むと、1 回目に `Object.prototype`・2 回目に
    // `Date.prototype` を返すトラップだけで**判定を通った値が `Date.prototype` の複製先へ
    // 書き込まれ**、`JSON.stringify` が `[[DateValue]]` 不在の素の `TypeError` を投げる
    // （本モジュールが塞ぐはずの二重評価が本モジュール自身の中で成立する）。
    let prototypeReads = 0;
    const target = { a: 1 };
    const proxy = new Proxy(target, {
      getPrototypeOf(): object | null {
        prototypeReads += 1;
        return prototypeReads === 1 ? Object.prototype : Date.prototype;
      },
    });

    const snapshot = deepSnapshot({ nested: proxy }) as Record<string, unknown>;

    expect(prototypeReads).toBe(1);
    expect(Object.getPrototypeOf(snapshot.nested as object)).toBe(Object.prototype);
    expect(JSON.stringify(snapshot)).toBe('{"nested":{"a":1}}');
  });

  it('getPrototypeOf トラップが非プレーンなプロトタイプを返す Proxy は参照のまま残る（fail-closed）', () => {
    // 上の裏面。`Proxy` を JavaScript から判別する手段は無く `Date` を包む `Proxy` と区別
    // できないため、判定が「プレーンでない」に倒れた場合は壊れた複製を作らず参照のまま残す。
    // その代償として `ownKeys` / `get` トラップは後段で再評価されうる（文書化した限界）。
    const target = { a: 1 };
    const proxy = new Proxy(target, {
      getPrototypeOf: (): object | null => Date.prototype,
    });

    const snapshot = deepSnapshot({ nested: proxy }) as Record<string, unknown>;

    expect(snapshot.nested).toBe(proxy);
  });

  it('own の throwing getter の例外はそのまま伝播する（正規化は呼び出し側の責務）', () => {
    const nested: Record<string, unknown> = {};
    Object.defineProperty(nested, 'boom', {
      configurable: true,
      enumerable: true,
      get(): never {
        throw new TypeError('attacker-controlled');
      },
    });

    expect(() => deepSnapshot({ nested })).toThrow(TypeError);
  });
});

describe('deepSnapshot: 記述子自身も own 限定で読む（Object.prototype 汚染耐性）', () => {
  it('Object.prototype.value 汚染下でも入れ子 getter がデータ記述子と誤分類されない', () => {
    // `Object.getOwnPropertyDescriptor` の戻り値は `Object.prototype` を継承する通常の
    // オブジェクトで、**アクセサ記述子は own `value` を持たない**。したがって
    // `'value' in descriptor` / `descriptor.value` の鎖読みは、この汚染下で
    // **すべての入れ子 getter をデータ記述子と誤分類し、getter を呼ばずに汚染値を
    // 確定値としてスナップショットへ書き込む**（本モジュールの目的が反転する）。
    const nested: Record<string, unknown> = {};
    const reads = defineCountedAccessor(nested, 'detail', [{ ok: 1 }]);

    const snapshot = withPollutedPrototype({ value: { healthData: 'HIV+' } }, () => {
      return deepSnapshot({ nested }) as Record<string, unknown>;
    });

    // getter は実際に呼ばれ、汚染値ではなく getter の返り値が畳まれている。
    expect(reads()).toBe(1);
    expect(JSON.stringify(snapshot)).toBe('{"nested":{"detail":{"ok":1}}}');
    expect(JSON.stringify(snapshot)).not.toContain('healthData');
  });

  it('Object.prototype.value 汚染下でもデータプロパティの値は元のまま', () => {
    const snapshot = withPollutedPrototype({ value: 'PWN' }, () => {
      return deepSnapshot({ nested: { a: 1 } }) as Record<string, unknown>;
    });

    expect(JSON.stringify(snapshot)).toBe('{"nested":{"a":1}}');
  });

  it('Object.prototype.writable 汚染下でも畳んだプロパティは書き換え可能なまま', () => {
    // アクセサ記述子は own `writable` を持たないため、`descriptor.writable ?? true` の
    // 鎖読みはこの汚染下で到達し、畳んだプロパティが非 writable になる。
    const nested: Record<string, unknown> = {};
    defineCountedAccessor(nested, 'detail', ['value']);

    const snapshot = withPollutedPrototype({ writable: false }, () => {
      return deepSnapshot({ nested }) as Record<string, unknown>;
    });

    const copied = snapshot.nested as Record<string, unknown>;
    expect(Object.getOwnPropertyDescriptor(copied, 'detail')?.writable).toBe(true);
  });

  it('Object.prototype.get 汚染下でも setter だけのプロパティは undefined のまま', () => {
    const nested: Record<string, unknown> = {};
    Object.defineProperty(nested, 'writeOnly', {
      configurable: true,
      enumerable: true,
      set(_v: unknown): void {
        /* no-op */
      },
    });

    const snapshot = withPollutedPrototype({ get: () => 'PWN' }, () => {
      return deepSnapshot({ nested }) as Record<string, unknown>;
    });

    expect((snapshot.nested as Record<string, unknown>).writeOnly).toBeUndefined();
  });
});
