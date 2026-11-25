/**
 * `VericertsError` コンストラクタの `options.cause` / `options.context` を own 限定で読むことの
 * 回帰テスト。
 *
 * `options` は呼び出し側が渡すプレーンオブジェクトであり、`context` のみ／`cause` のみを渡す
 * （もう片方を省略した）正当な呼び出しが SDK 全域に存在する。オプショナルチェイニングは
 * `options` 自体が `undefined` の場合しか短絡しないため、実オブジェクトに対する省略側の読み取りは
 * `Object.prototype` まで鎖を辿ってしまう。汚染下でその省略側に継承値が紛れ込まないことを検証する。
 */

import { describe, expect, test } from 'bun:test';
import { ErrorCodes, VericertsError } from '../../errors.js';
import { withPollutedPrototype } from '../prototype-pollution.fixtures.js';

describe('VericertsError: Object.prototype 汚染下での own 限定読み取り', () => {
  test('context のみ渡す呼び出しで Object.prototype.cause の汚染値を .cause に採用しない', () => {
    const pollutedCause = new Error('attacker-controlled cause');
    const error = withPollutedPrototype(
      { cause: pollutedCause },
      () => new VericertsError(ErrorCodes.INVALID_MNEMONIC, { context: { wordCount: 15 } }),
    );
    expect(error.cause).toBeUndefined();
    expect(error.context).toEqual({ wordCount: 15 });
  });

  test('cause のみ渡す呼び出しで Object.prototype.context の汚染値を .context に採用しない', () => {
    const pollutedContext = { secret: 'attacker-controlled context' };
    const original = new Error('original');
    const error = withPollutedPrototype(
      { context: pollutedContext },
      () => new VericertsError(ErrorCodes.INVALID_MNEMONIC, { cause: original }),
    );
    expect(error.context).toBeUndefined();
    expect(error.cause).toBe(original);
  });

  test('options 省略時は Object.prototype.cause / .context のどちらも採用しない', () => {
    const error = withPollutedPrototype(
      { cause: new Error('attacker-controlled cause'), context: { secret: 'x' } },
      () => new VericertsError(ErrorCodes.INVALID_MNEMONIC),
    );
    expect(error.cause).toBeUndefined();
    expect(error.context).toBeUndefined();
  });
});
