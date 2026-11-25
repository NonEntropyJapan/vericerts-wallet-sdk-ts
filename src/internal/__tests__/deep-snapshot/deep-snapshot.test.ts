/**
 * `internal/prototype-safety/deep-snapshot.ts` の意味論テスト。
 *
 * `deepSnapshot` は 3 つの面から共有される（発行系 `issuer/module/normalized-issue-input.ts` /
 * DID Log 経路 `identity/normalized-log-input.ts` / VC チェーン `credential/chain/build.ts`）。
 * 意味論の保証をどれか 1 つの呼び出し側のテストに置くと、その呼び出し側を消したときに共有実装の
 * 保証が丸ごと失われるため、**共有実装を直接叩く形**でここに置く。各呼び出し側のテストは
 * 「その経路で二重評価ドリフトが成立しないこと」だけを見る。
 *
 * 本ファイルが固定するのは契約の中核 2 点:
 * - own アクセサはちょうど 1 回だけ評価してデータプロパティへ畳む
 * - 複製するのは**プレーンなコンテナだけ**（素の配列とプレーンオブジェクト）で、それ以外は
 *   **参照のまま**（内部スロットを壊さない）
 *
 * 残りの契約（記述子・`Symbol` キー・循環参照・配列の穴・深い入れ子の反復走査と、「既知の限界」
 * として明記した範囲が実際に限界のままであること）は `deep-snapshot.limits.test.ts` にある。
 * 1 ファイル 300 行の上限（`.linterly.yml`）に収めるため責務で分けている。
 */

import { describe, expect, it } from 'bun:test';
import { deepSnapshot } from '../../prototype-safety/deep-snapshot.js';
import { defineCountedAccessor } from '../accessor-toctou.fixtures.js';

describe('deepSnapshot: アクセサの畳み込み', () => {
  it('入れ子の own アクセサをちょうど 1 回だけ評価してデータプロパティへ畳む', () => {
    const nested: Record<string, unknown> = {};
    const reads = defineCountedAccessor(nested, 'detail', [{ ok: 1 }, { health: 'HIV+' }]);

    const snapshot = deepSnapshot({ nested }) as Record<string, unknown>;

    expect(reads()).toBe(1);
    const copied = snapshot.nested as Record<string, unknown>;
    expect(copied.detail).toEqual({ ok: 1 });
    // 何度読んでも同じ値（データプロパティに畳まれている）。
    expect(copied.detail).toEqual({ ok: 1 });
    expect(JSON.stringify(snapshot)).toBe('{"nested":{"detail":{"ok":1}}}');
    expect(reads()).toBe(1);
  });

  it('setter だけのプロパティは元を読んだのと同じ undefined になる', () => {
    const source: Record<string, unknown> = {};
    Object.defineProperty(source, 'writeOnly', {
      configurable: true,
      enumerable: true,
      set(_v: unknown): void {
        /* no-op */
      },
    });

    const snapshot = deepSnapshot(source) as Record<string, unknown>;

    expect(Object.hasOwn(snapshot, 'writeOnly')).toBe(true);
    expect(snapshot.writeOnly).toBeUndefined();
    expect(JSON.stringify(snapshot)).toBe(JSON.stringify(source));
  });
});

describe('deepSnapshot: 何を複製し、何を参照のまま残すか', () => {
  it('Date / クラスインスタンスは参照のまま保つ（内部スロットを壊さない）', () => {
    class Amount {
      constructor(private readonly cents: number) {}
      toJSON(): string {
        return `${this.cents / 100}`;
      }
    }
    const issuedAt = new Date('2026-01-01T00:00:00.000Z');
    const amount = new Amount(1250);

    const snapshot = deepSnapshot({ meta: { issuedAt, amount } }) as Record<string, unknown>;
    const meta = snapshot.meta as { issuedAt: Date; amount: Amount };

    expect(meta.issuedAt).toBe(issuedAt);
    expect(meta.amount).toBe(amount);
    // `JSON.stringify` の出力（= 署名されるバイト列）が元と 1 バイトも変わらないこと。
    expect(JSON.stringify(snapshot)).toBe(
      '{"meta":{"issuedAt":"2026-01-01T00:00:00.000Z","amount":"12.5"}}',
    );
  });

  it('Map / Set / TypedArray も参照のまま保つ', () => {
    const map = new Map([['k', 1]]);
    const set = new Set([1, 2]);
    const bytes = new Uint8Array([1, 2, 3]);

    const snapshot = deepSnapshot({ map, set, bytes }) as Record<string, unknown>;

    expect(snapshot.map).toBe(map);
    expect(snapshot.set).toBe(set);
    expect(snapshot.bytes).toBe(bytes);
  });

  it('カスタム toJSON を持つ Array サブクラスは参照のまま保つ（複製して壊さない）', () => {
    class MoneyArray extends Array<number> {
      toJSON(): string {
        return `$${(this.reduce((sum, cents) => sum + cents, 0) / 100).toFixed(2)}`;
      }
    }
    const money = MoneyArray.from([1000, 250]) as MoneyArray;

    const snapshot = deepSnapshot({ meta: { money } }) as Record<string, unknown>;
    const meta = snapshot.meta as { money: MoneyArray };

    // 判別力を持つのはこの 1 行（複製されていれば別インスタンスになる）。
    expect(meta.money).toBe(money);
    // 以下は同一性から論理的に導かれる**対照**で、独立した判別力は持たない。参照のまま残す
    // という契約が「何を壊さないと言っているのか」を読み手に示すために置く（複製へ変えると
    // ここが `TypeError` や別の出力になる、という契約の内容そのもの）。
    expect(Array.isArray(meta.money)).toBe(true);
    expect(Object.getPrototypeOf(meta.money)).toBe(MoneyArray.prototype);
    expect(meta.money.toJSON()).toBe('$12.50');
    expect(JSON.stringify(meta.money)).toBe(JSON.stringify(money));
  });

  it('素の配列とプレーンオブジェクトは複製する（プロトタイプは保つ）', () => {
    const nullProto = Object.create(null) as Record<string, unknown>;
    nullProto.kind = 'bare';
    const plain = { a: 1 };
    const arr = [1, 2];

    const snapshot = deepSnapshot({ nullProto, plain, arr }) as Record<string, unknown>;

    expect(snapshot.plain).not.toBe(plain);
    expect(snapshot.arr).not.toBe(arr);
    expect(snapshot.nullProto).not.toBe(nullProto);
    expect(Object.getPrototypeOf(snapshot.plain as object)).toBe(Object.prototype);
    expect(Object.getPrototypeOf(snapshot.arr as object)).toBe(Array.prototype);
    expect(Object.getPrototypeOf(snapshot.nullProto as object)).toBeNull();
    expect(Array.isArray(snapshot.arr)).toBe(true);
  });

  it('複製対象外の値（プリミティブ / null / 関数）はそのまま返す', () => {
    const fn = (): number => 1;

    expect(deepSnapshot('s')).toBe('s');
    expect(deepSnapshot(1)).toBe(1);
    expect(deepSnapshot(null)).toBeNull();
    expect(deepSnapshot(undefined)).toBeUndefined();
    expect(deepSnapshot(fn)).toBe(fn);
  });
});
