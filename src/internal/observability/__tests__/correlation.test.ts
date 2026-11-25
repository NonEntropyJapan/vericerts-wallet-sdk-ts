/**
 * `createCorrelationContext` / `correlationHeaders` の単位テスト。
 *
 * 検証内容:
 * 1. 無入力時は W3C Trace Context 形式の `traceparent` と `X-Request-Id` を新規生成する。
 * 2. 上流から渡された正当な ID は書き換えずに引き継ぎ、不正な `traceparent` は例外を投げずに
 *    新しいトレースへ倒す（fail-safe）。
 * 3. `tracestate` から `user.*` / `did:*` を含むエントリを strip する。
 * 4. ヘッダ化は `traceparent` / `X-Request-Id`（+ `tracestate`）だけを出す。
 */

import { describe, expect, it, spyOn } from 'bun:test';
import type { CorrelationContext } from '../correlation.js';
import { correlationHeaders, createCorrelationContext } from '../correlation.js';

/** W3C Trace Context `traceparent` の形（version-trace_id-parent_id-flags、小文字 hex）。 */
const TRACEPARENT_PATTERN = /^[0-9a-f]{2}-[0-9a-f]{32}-[0-9a-f]{16}-[0-9a-f]{2}$/;

/** `traceparent` を version / trace-id / parent-id / flags へ分解する。 */
function parseTraceparent(traceparent: string): {
  version: string;
  traceId: string;
  parentId: string;
  flags: string;
} {
  const fields = traceparent.split('-');
  return {
    version: fields[0] ?? '',
    traceId: fields[1] ?? '',
    parentId: fields[2] ?? '',
    flags: fields[3] ?? '',
  };
}

describe('createCorrelationContext（新規生成）', () => {
  it('W3C 形式の traceparent を生成する（version 00 / flags 01）', () => {
    const { traceparent } = createCorrelationContext();

    expect(traceparent).toMatch(TRACEPARENT_PATTERN);
    const { version, flags } = parseTraceparent(traceparent);
    expect(version).toBe('00');
    expect(flags).toBe('01');
  });

  it('trace-id / parent-id が全ゼロにならない（W3C が禁じる値）', () => {
    const { traceId, parentId } = parseTraceparent(createCorrelationContext().traceparent);

    expect(traceId).not.toMatch(/^0+$/);
    expect(parentId).not.toMatch(/^0+$/);
  });

  it('CSPRNG が全ゼロを返しても全ゼロの ID を出さない', () => {
    const spy = spyOn(crypto, 'getRandomValues').mockImplementation(
      <T extends ArrayBufferView | null>(array: T): T => {
        if (ArrayBuffer.isView(array)) {
          new Uint8Array(array.buffer, array.byteOffset, array.byteLength).fill(0);
        }
        return array;
      },
    );

    try {
      const { traceparent, requestId } = createCorrelationContext();
      const { traceId, parentId } = parseTraceparent(traceparent);

      expect(traceparent).toMatch(TRACEPARENT_PATTERN);
      expect(traceId).toBe('00000000000000000000000000000001');
      expect(parentId).toBe('0000000000000001');
      expect(requestId).not.toMatch(/^0+$/);
    } finally {
      spy.mockRestore();
    }
  });

  it('requestId を生成する（空でない小文字 hex）', () => {
    expect(createCorrelationContext().requestId).toMatch(/^[0-9a-f]{32}$/);
  });

  it('呼び出しごとに異なる trace-id / requestId になる', () => {
    const first = createCorrelationContext();
    const second = createCorrelationContext();

    expect(parseTraceparent(first.traceparent).traceId).not.toBe(
      parseTraceparent(second.traceparent).traceId,
    );
    expect(first.requestId).not.toBe(second.requestId);
  });

  it('tracestate 未指定ならプロパティ自体を持たない', () => {
    const context = createCorrelationContext();

    expect(Object.hasOwn(context, 'tracestate')).toBe(false);
  });
});

describe('createCorrelationContext（traceparent の引き継ぎ）', () => {
  const VALID = '00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01';

  it('正当な traceparent はそのまま引き継ぐ', () => {
    expect(createCorrelationContext({ traceparent: VALID }).traceparent).toBe(VALID);
  });

  it('version / flags が 00 以外でも形式が合っていれば引き継ぐ', () => {
    const other = 'ab-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-00';

    expect(createCorrelationContext({ traceparent: other }).traceparent).toBe(other);
  });

  it.each([
    ['形式不正', 'not-a-traceparent'],
    ['区切り不足', '00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7'],
    ['trace-id 桁数不足', '00-4bf92f3577b34da6a3ce929d0e473-00f067aa0ba902b7-01'],
    ['parent-id 桁数超過', '00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7ff-01'],
    ['大文字 hex', '00-4BF92F3577B34DA6A3CE929D0E0E4736-00F067AA0BA902B7-01'],
    ['trace-id が全ゼロ', '00-00000000000000000000000000000000-00f067aa0ba902b7-01'],
    ['parent-id が全ゼロ', '00-4bf92f3577b34da6a3ce929d0e0e4736-0000000000000000-01'],
    ['禁止 version ff（W3C §3.2.2.1）', 'ff-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01'],
    ['空文字', ''],
  ])('不正な traceparent（%s）は新しいトレースへ倒す', (_label, invalid) => {
    const { traceparent } = createCorrelationContext({ traceparent: invalid });

    expect(traceparent).not.toBe(invalid);
    expect(traceparent).toMatch(TRACEPARENT_PATTERN);
    expect(parseTraceparent(traceparent).traceId).not.toMatch(/^0+$/);
  });

  it('不正な入力でも例外を投げない（fail-safe）', () => {
    expect(() => createCorrelationContext({ traceparent: 'broken' })).not.toThrow();
  });
});

describe('createCorrelationContext（requestId の引き継ぎ）', () => {
  it('指定された requestId はそのまま使う', () => {
    expect(createCorrelationContext({ requestId: 'popup-click-42' }).requestId).toBe(
      'popup-click-42',
    );
  });

  it.each([
    ['空文字', ''],
    ['空白のみ', '   '],
  ])('%s の requestId は新規生成する', (_label, blank) => {
    expect(createCorrelationContext({ requestId: blank }).requestId).toMatch(/^[0-9a-f]{32}$/);
  });

  it('requestId を省略しても traceparent の指定は活きる', () => {
    const traceparent = '00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01';
    const context = createCorrelationContext({ traceparent });

    expect(context.traceparent).toBe(traceparent);
    expect(context.requestId).toMatch(/^[0-9a-f]{32}$/);
  });
});

describe('createCorrelationContext（tracestate の strip）', () => {
  it('user.* のエントリだけを落とし、他は残す', () => {
    const context = createCorrelationContext({
      tracestate: 'congo=t61rcWkgMzE,user.foo=bar,rojo=00f067aa0ba902b7',
    });

    expect(context.tracestate).toBe('congo=t61rcWkgMzE,rojo=00f067aa0ba902b7');
  });

  it('値が user.* のエントリも落とす', () => {
    expect(createCorrelationContext({ tracestate: 'vendor=user.alice,rojo=1' }).tracestate).toBe(
      'rojo=1',
    );
  });

  it('値が DID のエントリを落とす', () => {
    const context = createCorrelationContext({
      tracestate:
        'congo=t61rcWkgMzE,subject=did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK',
    });

    expect(context.tracestate).toBe('congo=t61rcWkgMzE');
  });

  it('値の途中に埋め込まれた DID も落とす', () => {
    expect(
      createCorrelationContext({ tracestate: 'vendor=trace-did:ethr:0xabc,rojo=1' }).tracestate,
    ).toBe('rojo=1');
  });

  it('キーが DID のエントリも落とす', () => {
    expect(createCorrelationContext({ tracestate: 'did:key:z6Mk=1,rojo=1' }).tracestate).toBe(
      'rojo=1',
    );
  });

  it('strip 後に何も残らなければ tracestate を持たない（空文字にしない）', () => {
    const context = createCorrelationContext({
      tracestate: 'user.id=alice,user.email=a@example.com',
    });

    expect(Object.hasOwn(context, 'tracestate')).toBe(false);
    expect(context.tracestate).toBeUndefined();
  });

  it('空文字の tracestate は持たない', () => {
    expect(Object.hasOwn(createCorrelationContext({ tracestate: '' }), 'tracestate')).toBe(false);
  });

  it('識別子を含まない tracestate は（前後の空白を除いて）そのまま残る', () => {
    expect(
      createCorrelationContext({ tracestate: ' congo=t61rcWkgMzE , rojo=1 ' }).tracestate,
    ).toBe('congo=t61rcWkgMzE,rojo=1');
  });
});

describe('createCorrelationContext（プロトタイプ汚染耐性）', () => {
  it('Object.prototype 由来の traceparent / requestId を引き継がない', () => {
    const pollutedTraceparent = '00-11111111111111111111111111111111-1111111111111111-01';
    Object.defineProperty(Object.prototype, 'traceparent', {
      value: pollutedTraceparent,
      configurable: true,
      writable: true,
    });
    Object.defineProperty(Object.prototype, 'requestId', {
      value: 'attacker-request-id',
      configurable: true,
      writable: true,
    });

    try {
      const context = createCorrelationContext({});

      expect(context.traceparent).not.toBe(pollutedTraceparent);
      expect(context.requestId).not.toBe('attacker-request-id');
    } finally {
      Reflect.deleteProperty(Object.prototype, 'traceparent');
      Reflect.deleteProperty(Object.prototype, 'requestId');
    }
  });
});

describe('correlationHeaders', () => {
  it('context 未指定なら空のヘッダを返す', () => {
    expect(correlationHeaders(undefined)).toEqual({});
  });

  it('traceparent と X-Request-Id だけを出す（tracestate 無し）', () => {
    const context: CorrelationContext = {
      requestId: 'req-1',
      traceparent: '00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01',
    };

    expect(correlationHeaders(context)).toEqual({
      traceparent: '00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01',
      'X-Request-Id': 'req-1',
    });
  });

  it('tracestate があれば 3 件を出す', () => {
    const context: CorrelationContext = {
      requestId: 'req-2',
      traceparent: '00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01',
      tracestate: 'congo=t61rcWkgMzE',
    };

    expect(Object.keys(correlationHeaders(context)).sort()).toEqual([
      'X-Request-Id',
      'traceparent',
      'tracestate',
    ]);
    expect(correlationHeaders(context).tracestate).toBe('congo=t61rcWkgMzE');
  });

  it('空文字の tracestate はヘッダに出さない', () => {
    const context: CorrelationContext = {
      requestId: 'req-3',
      traceparent: '00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01',
      tracestate: '',
    };

    expect(Object.hasOwn(correlationHeaders(context), 'tracestate')).toBe(false);
  });

  it('生成した context をそのままヘッダ化できる', () => {
    const context = createCorrelationContext();
    const headers = correlationHeaders(context);

    expect(headers.traceparent).toBe(context.traceparent);
    expect(headers['X-Request-Id']).toBe(context.requestId);
  });
});
