/**
 * 呼び出し側から渡された相関 ID の検査。
 *
 * `isCorrelationContext` / `readCorrelationContext` は、SDK 内部で持ち回る前の唯一の防御線である
 * （呼び出し側のオブジェクトは `JSON.parse` を通らないため `parse-json.ts` のパース境界が効かない）。
 * 固定する不変条件は 2 つ:
 *
 * 1. 形の妥当な値だけを通す（`traceparent` は W3C Trace Context の形式まで見る）。
 * 2. メンバは **own 限定**で読む。鎖読みだと相関 ID を**渡していない**正当な呼び出しが
 *    汚染された `Object.prototype.traceparent` を引き継ぎ、全リクエストが攻撃者の選んだ
 *    トレースへ相関付けられる。
 */

import { describe, expect, it } from 'bun:test';
import { withPollutedPrototype } from '../../__tests__/prototype-pollution.fixtures.js';
import {
  createCorrelationContext,
  isCorrelationContext,
  readCorrelationContext,
} from '../correlation.js';

const VALID = createCorrelationContext({ requestId: 'popup-click-42' });

/** 形が壊れた相関 ID（型のない JS からの呼び出しでのみ到達する形も含む）。 */
const malformed: readonly (readonly [string, unknown])[] = [
  ['非オブジェクト', VALID.traceparent],
  ['null', null],
  ['配列', []],
  ['requestId 欠落', { traceparent: VALID.traceparent }],
  ['requestId が空白のみ', { ...VALID, requestId: '   ' }],
  ['traceparent が数値', { requestId: 'req-1', traceparent: 123 }],
  ['traceparent が W3C 形式でない', { requestId: 'req-1', traceparent: 'broken' }],
  ['tracestate が数値', { ...VALID, tracestate: 1 }],
];

describe('isCorrelationContext', () => {
  it('createCorrelationContext の戻り値を受理する（tracestate の有無を問わない）', () => {
    expect(isCorrelationContext(VALID)).toBe(true);
    expect(isCorrelationContext(createCorrelationContext({ tracestate: 'rojo=1' }))).toBe(true);
  });

  for (const [label, value] of malformed) {
    it(`${label} は受理しない`, () => {
      expect(isCorrelationContext(value)).toBe(false);
    });
  }

  it('プロトタイプ鎖のメンバは採用しない（own 限定）', () => {
    withPollutedPrototype(
      { requestId: 'attacker-request-id', traceparent: VALID.traceparent },
      () => {
        expect(isCorrelationContext({})).toBe(false);
      },
    );
  });
});

describe('readCorrelationContext', () => {
  it('own プロパティの妥当な相関 ID を返す', () => {
    expect(readCorrelationContext({ correlationContext: VALID })).toEqual(VALID);
  });

  it('未指定・形の壊れた値は undefined へ倒す（例外は投げない）', () => {
    expect(readCorrelationContext({})).toBeUndefined();
    expect(readCorrelationContext({ correlationContext: { traceparent: 123 } })).toBeUndefined();
  });

  it('Object.prototype 由来の correlationContext は拾わない', () => {
    withPollutedPrototype({ correlationContext: VALID }, () => {
      expect(readCorrelationContext({})).toBeUndefined();
    });
  });
});
