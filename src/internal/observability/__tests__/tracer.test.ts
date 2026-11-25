/**
 * `createTracer` の単位テスト。
 *
 * 検証内容:
 * 1. 未注入時（`createTracer(undefined)`）は no-op として例外なく呼べる。
 * 2. 注入時は `startSpan` と Span の全メソッド呼び出しがそのまま注入先へ委譲される
 *    （ロガーと違い加工層を挟まない）。
 */

import { describe, expect, it } from 'bun:test';
import type { Attributes, Span, SpanOptions, Tracer } from '../tracer.js';
import { createTracer } from '../tracer.js';

/** 記録した Span 操作 1 件（メソッド名と引数）。 */
type RecordedCall =
  | { readonly kind: 'setAttribute'; readonly key: string; readonly value: unknown }
  | { readonly kind: 'addEvent'; readonly name: string; readonly attrs: Attributes | undefined }
  | { readonly kind: 'recordException'; readonly error: Error }
  | { readonly kind: 'setStatus'; readonly status: 'ok' | 'error'; readonly description?: string }
  | { readonly kind: 'end' };

/** 記録した `startSpan` 1 件（Span 名・オプション・その Span への操作列）。 */
interface RecordedSpan {
  readonly name: string;
  readonly opts: SpanOptions | undefined;
  readonly calls: RecordedCall[];
}

/** 呼び出しを配列に貯めるだけの Tracer（注入先の代役）。 */
function recordingTracer(): { sink: Tracer; spans: RecordedSpan[] } {
  const spans: RecordedSpan[] = [];
  const sink: Tracer = {
    startSpan(name: string, opts?: SpanOptions): Span {
      const calls: RecordedCall[] = [];
      spans.push({ name, opts, calls });
      return {
        setAttribute: (key, value) => {
          calls.push({ kind: 'setAttribute', key, value });
        },
        addEvent: (eventName, attrs) => {
          calls.push({ kind: 'addEvent', name: eventName, attrs });
        },
        recordException: (error) => {
          calls.push({ kind: 'recordException', error });
        },
        setStatus: (status, description) => {
          calls.push({ kind: 'setStatus', status, description });
        },
        end: () => {
          calls.push({ kind: 'end' });
        },
      };
    },
  };
  return { sink, spans };
}

/** 1 件だけ記録されている前提でその Span を取り出す。 */
function onlySpan(spans: readonly RecordedSpan[]): RecordedSpan {
  expect(spans.length).toBe(1);
  const span = spans[0];
  expect(span).toBeDefined();
  return span as RecordedSpan;
}

describe('createTracer（未注入時の no-op）', () => {
  it('startSpan と Span の全メソッドが例外を投げない', () => {
    const tracer = createTracer(undefined);

    expect(() => {
      const span = tracer.startSpan('did.resolve', { attributes: { 'did.method': 'key' } });
      span.setAttribute('did.cache_hit', true);
      span.addEvent('resolved', { 'did.result': 'ok' });
      span.recordException(new Error('boom'));
      span.setStatus('error', 'failed');
      span.end();
    }).not.toThrow();
  });

  it('opts 省略の startSpan も Span を返す', () => {
    const tracer = createTracer(undefined);

    expect(() => {
      tracer.startSpan('vc.verify').end();
    }).not.toThrow();
  });
});

describe('createTracer（注入時の委譲）', () => {
  it('注入された Tracer をそのまま返す', () => {
    const { sink } = recordingTracer();

    expect(createTracer(sink)).toBe(sink);
  });

  it('Span 名とオプションがそのまま注入先へ渡る', () => {
    const { sink, spans } = recordingTracer();

    createTracer(sink).startSpan('did.resolve', { attributes: { 'did.method': 'ethr' } });

    const span = onlySpan(spans);
    expect(span.name).toBe('did.resolve');
    expect(span.opts).toEqual({ attributes: { 'did.method': 'ethr' } });
  });

  it('opts 未指定なら undefined のまま注入先へ渡る', () => {
    const { sink, spans } = recordingTracer();

    createTracer(sink).startSpan('vc.verify');

    expect(onlySpan(spans).opts).toBeUndefined();
  });

  it('Span の各メソッド呼び出しが順序どおり注入先へ委譲される', () => {
    const { sink, spans } = recordingTracer();
    const error = new Error('boom');

    const span = createTracer(sink).startSpan('oid4vci.issuance');
    span.setAttribute('oid4vci.flow', 'pre-authorized_code');
    span.addEvent('token_request', { 'oauth.grant_type': 'pre-authorized_code' });
    span.recordException(error);
    span.setStatus('error', 'token request failed');
    span.end();

    expect(onlySpan(spans).calls).toEqual([
      { kind: 'setAttribute', key: 'oid4vci.flow', value: 'pre-authorized_code' },
      {
        kind: 'addEvent',
        name: 'token_request',
        attrs: { 'oauth.grant_type': 'pre-authorized_code' },
      },
      { kind: 'recordException', error },
      { kind: 'setStatus', status: 'error', description: 'token request failed' },
      { kind: 'end' },
    ]);
  });

  it('省略可能な引数は undefined のまま渡る（既定値を捏造しない）', () => {
    const { sink, spans } = recordingTracer();

    const span = createTracer(sink).startSpan('storage.encrypt');
    span.addEvent('started');
    span.setStatus('ok');

    expect(onlySpan(spans).calls).toEqual([
      { kind: 'addEvent', name: 'started', attrs: undefined },
      { kind: 'setStatus', status: 'ok', description: undefined },
    ]);
  });

  it('startSpan ごとに独立した Span が返る', () => {
    const { sink, spans } = recordingTracer();
    const tracer = createTracer(sink);

    tracer.startSpan('did.resolve').end();
    tracer.startSpan('vc.verify').setAttribute('vc.format', 'sd-jwt');

    expect(spans.map((span) => span.name)).toEqual(['did.resolve', 'vc.verify']);
    expect(spans[0]?.calls).toEqual([{ kind: 'end' }]);
    expect(spans[1]?.calls).toEqual([{ kind: 'setAttribute', key: 'vc.format', value: 'sd-jwt' }]);
  });
});
