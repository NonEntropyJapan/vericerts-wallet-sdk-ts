/**
 * `internal/prototype-safety/define-data-property.ts` の回帰テスト。
 *
 * 読み取り側だけでなく**書き込み側**（`Object.defineProperty` へ渡す記述子そのもの）が
 * プロトタイプ汚染を受ける経路を塞ぐヘルパーの契約を固定する。
 *
 * 固定する契約:
 *
 * - `Object.prototype.get` / `.set` が関数で汚染されていても `defineDataProperty` が成功する。
 *   記述子をオブジェクトリテラルへ戻すと「`value` とアクセサの同時指定」と解釈され
 *   `TypeError: Invalid property. 'value' present on property with getter or setter.` で必ず落ちる。
 * - `key` が `__proto__` でも own データプロパティになり、`target` のプロトタイプは変わらない
 *   （生代入 `target[key] = value` へ戻すと壊れる）。
 * - `flags` は own 限定で読む（`Object.prototype.writable = false` 等が既定値 `true` を裏返さない）。
 * - `toBareDescriptor` は own メンバだけを写した `null` プロトタイプの複製を返し、汚染下でも
 *   そのまま `Object.defineProperty` へ渡せる（エンジンが返す生の記述子は渡せない）。
 * - `keymanager/hardening/hdkey-option-guard.ts` の復元経路が、**区間の途中で** `get` が
 *   汚染されても退避した記述子を復元できる。
 *
 * 汚染は必ずフィクスチャ経由で仕込み、`finally` で戻す（他のテストへ漏らさない）。
 */

import { describe, expect, it } from 'bun:test';
import { withoutHDKeyOptionPollution } from '../../keymanager/hardening/hdkey-option-guard.js';
import {
  defineDataProperty,
  toBareDescriptor,
} from '../../prototype-safety/define-data-property.js';
import { pollutePrototype, withPollutedPrototype } from '../prototype-pollution.fixtures.js';

/** `Object.prototype.get` / `.set` へ仕込むアクセサ相当の関数（値そのものは使わない）。 */
const POLLUTED_ACCESSOR = (): undefined => undefined;

/** 既定フラグ（すべて `true`）のデータ記述子。 */
const DEFAULT_DESCRIPTOR = {
  value: 'value',
  writable: true,
  enumerable: true,
  configurable: true,
} as const;

/** `defineDataProperty` が作った own データ記述子を 1 つ取り出す。 */
function dataDescriptorOf(value: unknown): PropertyDescriptor {
  const source: Record<string, unknown> = {};
  defineDataProperty(source, 'claim', value);
  return Object.getOwnPropertyDescriptor(source, 'claim') as PropertyDescriptor;
}

/** 生代入（`target[key] = value`）。`__proto__` setter の発火を対比するために使う。 */
function assignRaw(target: Record<string, unknown>, key: string, value: unknown): void {
  target[key] = value;
}

describe('defineDataProperty: 記述子自身のプロトタイプ汚染', () => {
  it('Object.prototype.get が関数で汚染されていても own データプロパティを定義できる', () => {
    const descriptor = withPollutedPrototype({ get: POLLUTED_ACCESSOR }, () => {
      const target: Record<string, unknown> = {};
      defineDataProperty(target, 'claim', 'value');
      return Object.getOwnPropertyDescriptor(target, 'claim');
    });

    expect(descriptor).toEqual({ ...DEFAULT_DESCRIPTOR });
  });

  it('Object.prototype.set が関数で汚染されていても own データプロパティを定義できる', () => {
    const descriptor = withPollutedPrototype({ set: POLLUTED_ACCESSOR }, () => {
      const target: Record<string, unknown> = {};
      defineDataProperty(target, 'claim', 'value');
      return Object.getOwnPropertyDescriptor(target, 'claim');
    });

    expect(descriptor).toEqual({ ...DEFAULT_DESCRIPTOR });
  });
});

describe('defineDataProperty: __proto__ キーの扱い', () => {
  it('__proto__ を own データプロパティとして定義し、プロトタイプを差し替えない', () => {
    const marker = { attacker: true };
    const defined: Record<string, unknown> = {};

    defineDataProperty(defined, '__proto__', marker);

    expect(Object.getPrototypeOf(defined)).toBe(Object.prototype);
    expect(Object.hasOwn(defined, '__proto__')).toBe(true);
    expect(Object.getOwnPropertyDescriptor(defined, '__proto__')?.value).toBe(marker);

    // 対比: 生代入だと継承した `__proto__` setter が発火し、own プロパティは生えないまま
    // プロトタイプごと差し替わる。`defineDataProperty` が避けているのはこの挙動である。
    const assigned: Record<string, unknown> = {};
    assignRaw(assigned, '__proto__', marker);

    expect(Object.getPrototypeOf(assigned)).toBe(marker);
    expect(Object.hasOwn(assigned, '__proto__')).toBe(false);
  });

  it('汚染下でも __proto__ の定義が成功する', () => {
    const value = withPollutedPrototype({ get: POLLUTED_ACCESSOR }, () => {
      const target: Record<string, unknown> = {};
      defineDataProperty(target, '__proto__', 'bare');
      return Object.getOwnPropertyDescriptor(target, '__proto__')?.value;
    });

    expect(value).toBe('bare');
  });
});

describe('defineDataProperty: flags を own 限定で読む', () => {
  it('Object.prototype 側の writable / enumerable / configurable 汚染が既定値を裏返さない', () => {
    // フラグを 1 つも渡さない正当な呼び出し。既定 `{}` リテラルは `Object.prototype` を
    // 継承するため、鎖読み（`flags.writable !== false`）だと汚染値 `false` を拾ってしまう。
    const descriptor = withPollutedPrototype(
      { writable: false, enumerable: false, configurable: false },
      () => {
        const target: Record<string, unknown> = {};
        defineDataProperty(target, 'claim', 'value');
        return Object.getOwnPropertyDescriptor(target, 'claim');
      },
    );

    expect(descriptor).toEqual({ ...DEFAULT_DESCRIPTOR });
  });

  it('一部だけ own 指定した場合、残りは汚染ではなく既定 true になる', () => {
    const descriptor = withPollutedPrototype({ enumerable: false, configurable: false }, () => {
      const target: Record<string, unknown> = {};
      defineDataProperty(target, 'claim', 'value', { writable: false });
      return Object.getOwnPropertyDescriptor(target, 'claim');
    });

    expect(descriptor).toEqual({
      value: 'value',
      writable: false,
      enumerable: true,
      configurable: true,
    });
  });

  it('own で明示した false はそのまま反映される', () => {
    const target: Record<string, unknown> = {};

    defineDataProperty(target, 'claim', 'value', {
      writable: false,
      enumerable: false,
      configurable: false,
    });

    expect(Object.getOwnPropertyDescriptor(target, 'claim')).toEqual({
      value: 'value',
      writable: false,
      enumerable: false,
      configurable: false,
    });
  });
});

describe('toBareDescriptor: 退避した記述子の bare 化', () => {
  it('own メンバだけを写した null プロトタイプの複製を返す', () => {
    const raw = dataDescriptorOf('value');
    const bare = toBareDescriptor(raw);

    expect(Object.getPrototypeOf(bare)).toBeNull();
    expect(Object.getOwnPropertyNames(bare).sort()).toEqual([
      'configurable',
      'enumerable',
      'value',
      'writable',
    ]);
    expect(bare.value).toBe('value');
    expect(bare.writable).toBe(true);
    expect(bare.enumerable).toBe(true);
    expect(bare.configurable).toBe(true);
    // 複製であって同一参照ではない（元の記述子を書き換えない）。
    expect(bare).not.toBe(raw);
  });

  it('アクセサ記述子でも own メンバ（get / set）だけを写す', () => {
    const source = {};
    const getter = (): string => 'from-getter';
    Object.defineProperty(source, 'claim', { get: getter, enumerable: false, configurable: true });
    const raw = Object.getOwnPropertyDescriptor(source, 'claim') as PropertyDescriptor;

    const bare = toBareDescriptor(raw);

    expect(Object.getPrototypeOf(bare)).toBeNull();
    expect(Object.getOwnPropertyNames(bare).sort()).toEqual([
      'configurable',
      'enumerable',
      'get',
      'set',
    ]);
    expect(bare.get).toBe(getter);
    expect(Object.hasOwn(bare, 'value')).toBe(false);
  });

  it('汚染下では bare 化した記述子だけが defineProperty へ渡せる', () => {
    const raw = dataDescriptorOf('value');

    const outcome = withPollutedPrototype({ get: POLLUTED_ACCESSOR }, () => {
      // 生の記述子は `Object.prototype` を継承するため、継承 `get` が見えて弾かれる。
      const rawTarget: Record<string, unknown> = {};
      let rawRejected = false;
      try {
        Object.defineProperty(rawTarget, 'claim', raw);
      } catch {
        rawRejected = true;
      }

      // bare 化した複製はプロトタイプを持たないのでそのまま渡せる。
      const bareTarget: Record<string, unknown> = {};
      Object.defineProperty(bareTarget, 'claim', toBareDescriptor(raw));
      return { rawRejected, bareValue: bareTarget.claim };
    });

    // 生の記述子が実際に弾かれることまで確認する（汚染が効いていない場合のトートロジー防止）。
    expect(outcome.rawRejected).toBe(true);
    expect(outcome.bareValue).toBe('value');
  });
});

/** 汚染値。復元後にこの値が戻っていることで「記述子ごと復元された」ことを確かめる。 */
const ATTACKER_PRIVATE_KEY = 'attacker-private-key';

/**
 * `withoutHDKeyOptionPollution` の同期区間の**途中**で `Object.prototype.get` を汚染する。
 *
 * `withPollutedPrototype` は `fn` を抜ける時点で汚染を解除するため、「区間の途中で汚染が
 * 始まり、ガードの `finally` による復元をまたいでから解除する」状況を作れない。解除時点を
 * 呼び出し側が決められる `pollutePrototype` を使い、ここで確実に `finally` 解除する。
 *
 * @returns 区間内で `Object.prototype.privateKey` が退避されていたか。
 */
function runGuardedIntervalPollutingGetMidway(): boolean {
  const restores: Array<() => void> = [];
  try {
    return withoutHDKeyOptionPollution(() => {
      const removed = !Object.hasOwn(Object.prototype, 'privateKey');
      restores.push(pollutePrototype({ get: POLLUTED_ACCESSOR }));
      return removed;
    });
  } finally {
    for (const restore of restores) {
      restore();
    }
  }
}

describe('hdkey-option-guard の復元経路: 区間途中の get 汚染', () => {
  it('退避した記述子を bare 化して復元するので privateKey が消えたままにならない', () => {
    const outcome = withPollutedPrototype({ privateKey: ATTACKER_PRIVATE_KEY }, () => {
      const removedInsideInterval = runGuardedIntervalPollutingGetMidway();
      return {
        removedInsideInterval,
        restored: Object.getOwnPropertyDescriptor(Object.prototype, 'privateKey'),
      };
    });

    // 前提: 区間内では実際に退避（削除）されていた。
    expect(outcome.removedInsideInterval).toBe(true);
    // 本題: 区間途中で get が汚染されても記述子ごと復元されている。
    expect(outcome.restored).toEqual({
      value: ATTACKER_PRIVATE_KEY,
      writable: true,
      enumerable: false,
      configurable: true,
    });
  });
});
