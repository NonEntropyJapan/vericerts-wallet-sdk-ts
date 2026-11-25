/**
 * `withoutHDKeyOptionPollution` の単体検証。
 *
 * グローバル状態（`Object.prototype`）を一時的に書き換えるヘルパーなので、
 * 「区間中は消えている」「区間後は記述子ごと必ず戻る」「非同期を渡したら落ちる」を個別に押さえる。
 */

import { describe, expect, it } from 'bun:test';
import {
  withPollutedPrototype,
  withPollutedPrototypeAccessor,
} from '../../../__tests__/prototype-pollution.fixtures.js';
import { withoutHDKeyOptionPollution } from '../../hardening/hdkey-option-guard.js';

const proto = Object.prototype as unknown as Record<string, unknown>;

/** `Object.prototype.then` 汚染を再現する props。 */
const THEN_POLLUTION = {
  // biome-ignore lint/suspicious/noThenProperty: 汚染を再現する意図的な then。
  then: () => undefined,
};

describe('withoutHDKeyOptionPollution', () => {
  it('区間中は汚染された HDKey オプションキーが見えない', () => {
    withPollutedPrototype({ index: 42, depth: 3, parentFingerprint: 9 }, () => {
      withoutHDKeyOptionPollution(() => {
        for (const key of ['index', 'depth', 'parentFingerprint']) {
          expect(Object.hasOwn(proto, key)).toBe(false);
          expect(({} as Record<string, unknown>)[key]).toBeUndefined();
        }
      });
    });
  });

  it('区間後は元の記述子をそのまま復元する', () => {
    withPollutedPrototype({ index: 42 }, () => {
      const before = Object.getOwnPropertyDescriptor(proto, 'index');
      withoutHDKeyOptionPollution(() => undefined);
      expect(Object.getOwnPropertyDescriptor(proto, 'index')).toEqual(before as PropertyDescriptor);
    });
  });

  it('fn が例外を投げても復元し、例外はそのまま伝播する', () => {
    withPollutedPrototype({ index: 42 }, () => {
      const sentinel = new Error('boom');
      expect(() =>
        withoutHDKeyOptionPollution(() => {
          throw sentinel;
        }),
      ).toThrow(sentinel);
      expect(proto.index).toBe(42);
    });
  });

  it('汚染がなければ Object.prototype に何も生やさない', () => {
    withoutHDKeyOptionPollution(() => undefined);
    for (const key of ['index', 'depth', 'parentFingerprint', 'publicKey', 'privateKey']) {
      expect(Object.hasOwn(proto, key)).toBe(false);
    }
  });

  it('入れ子で呼んでも最終的に復元される', () => {
    withPollutedPrototype({ index: 42 }, () => {
      withoutHDKeyOptionPollution(() => {
        withoutHDKeyOptionPollution(() => {
          expect(Object.hasOwn(proto, 'index')).toBe(false);
        });
        // 内側の復元対象は空なので、外側の区間はまだ汚染が外れたまま。
        expect(Object.hasOwn(proto, 'index')).toBe(false);
      });
      expect(proto.index).toBe(42);
    });
  });

  it('非同期関数を渡すと TypeError で落ちる（復元が await より先に走るため）', () => {
    withPollutedPrototype({ index: 42 }, () => {
      expect(() => withoutHDKeyOptionPollution(() => Promise.resolve(1))).toThrow(TypeError);
      // 誤用時も復元は済んでいる。
      expect(proto.index).toBe(42);
    });
  });

  it('アクセサ形式の汚染も getter ごとそのまま往復する', () => {
    const getter = (): unknown => 42;
    withPollutedPrototypeAccessor({ index: getter }, () => {
      withoutHDKeyOptionPollution(() => {
        expect(Object.hasOwn(proto, 'index')).toBe(false);
      });
      const descriptor = Object.getOwnPropertyDescriptor(proto, 'index');
      // 同一の getter 関数オブジェクトが戻ること（値へ潰していないこと）。
      expect(descriptor?.get).toBe(getter);
      expect(descriptor?.configurable).toBe(true);
      expect(descriptor?.enumerable).toBe(false);
    });
  });

  it('reject する素の thenable を渡しても unhandledRejection を起こさず TypeError で落ちる', () => {
    // `.catch` を持たない thenable。ガードが `Promise.resolve` 経由で握り潰せることを確認する。
    const thenable: PromiseLike<never> = {
      // biome-ignore lint/suspicious/noThenProperty: ガードの thenable 判定を検証する意図的な thenable。
      then: (_onFulfilled, onRejected) => {
        onRejected?.(new Error('should be swallowed'));
        return thenable;
      },
    };
    expect(() => withoutHDKeyOptionPollution(() => thenable)).toThrow(TypeError);
  });

  it('reject 済みの Promise を渡しても TypeError で落ちる', () => {
    const rejected = Promise.reject(new Error('should be swallowed'));
    // bun のテストランナーは「throw する関数の中でだけ handler が付く rejected promise」を
    // 誤って unhandled と報告するため、テスト側でも handler を付けておく。
    rejected.catch(() => undefined);
    expect(() => withoutHDKeyOptionPollution(() => rejected)).toThrow(TypeError);
  });

  it('Object.prototype.then 汚染下でも通常の戻り値を Promise と誤判定しない', () => {
    withPollutedPrototype(THEN_POLLUTION, () => {
      const value = { hd: 'not-a-promise' };
      expect(withoutHDKeyOptionPollution(() => value)).toBe(value);
    });
  });

  it('Object.prototype.then 汚染下でも本物の Promise は誤用として検出する', () => {
    withPollutedPrototype(THEN_POLLUTION, () => {
      const resolved = Promise.resolve(1);
      // 本物の Promise は `Promise.prototype.then` を持つので汚染とは区別できる。
      expect(() => withoutHDKeyOptionPollution(() => resolved)).toThrow(TypeError);
    });
  });

  it('fn の戻り値をそのまま返す', () => {
    expect(withoutHDKeyOptionPollution(() => 'ok')).toBe('ok');
    expect(withoutHDKeyOptionPollution(() => null)).toBeNull();
    expect(withoutHDKeyOptionPollution(() => undefined)).toBeUndefined();
  });
});
