/**
 * did:plc 用の最小 DAG-CBOR エンコーダー。
 *
 * 署名・CID・DID がこの符号化のバイト列で決まるため、最短形の長さ・キー順（長さ優先 → バイト辞書順）・
 * 扱えない型の拒否をバイト列で固定する。
 */

import { describe, expect, it } from 'bun:test';
import { ErrorCodes } from '../../../errors.js';
import { encodeDagCbor } from '../dag-cbor.js';
import { expectVericertsError } from './plc.fixtures.js';

const hex = (bytes: Uint8Array): string => Buffer.from(bytes).toString('hex');

describe('encodeDagCbor', () => {
  it('文字列・null・配列を RFC 8949 の最短形で符号化する', () => {
    expect(hex(encodeDagCbor('a'))).toBe('6161');
    expect(hex(encodeDagCbor(''))).toBe('60');
    expect(hex(encodeDagCbor(null))).toBe('f6');
    expect(hex(encodeDagCbor([]))).toBe('80');
    expect(hex(encodeDagCbor(['a', null]))).toBe('826161f6');
  });

  it('長さの引数は 23 / 24 / 255 / 256 / 65536 で畳み幅が変わる', () => {
    expect(hex(encodeDagCbor('x'.repeat(23))).slice(0, 2)).toBe('77');
    expect(hex(encodeDagCbor('x'.repeat(24))).slice(0, 4)).toBe('7818');
    expect(hex(encodeDagCbor('x'.repeat(255))).slice(0, 4)).toBe('78ff');
    expect(hex(encodeDagCbor('x'.repeat(256))).slice(0, 6)).toBe('790100');
    expect(hex(encodeDagCbor('x'.repeat(65536))).slice(0, 10)).toBe('7a00010000');
  });

  it('マップのキーは長さ優先・同長はバイト辞書順に並べ、入力の順序に依存しない', () => {
    // {"a": "", "b": "", "aa": null} → a, b, aa
    const expected = 'a3616160616260626161f6';
    expect(hex(encodeDagCbor({ aa: null, b: '', a: '' }))).toBe(expected);
    expect(hex(encodeDagCbor({ a: '', b: '', aa: null }))).toBe(expected);
  });

  it('キー順は UTF-16 のコード単位ではなく UTF-8 のバイト列で決める（長さが先）', () => {
    // U+FF5E は UTF-8 で 3 バイト、U+1F600 は 4 バイト。JS の sort() では U+1F600（サロゲート 0xD83D）が先になる。
    const encoded = hex(encodeDagCbor({ '\u{1F600}': null, '\uFF5E': null }));
    expect(encoded).toBe(`a263${'efbd9e'}f664${'f09f9880'}f6`);
  });

  it('入れ子（操作と同じ形）を再帰的に符号化し、prev: null を値として含める', () => {
    // キーは prev（4 バイト）→ services（8 バイト）の順。
    expect(hex(encodeDagCbor({ services: {}, prev: null }))).toBe(
      `a2${'6470726576'}f6${'68'}${Buffer.from('services').toString('hex')}a0`,
    );
  });

  it.each([
    ['数値', 1],
    ['真偽値', true],
    ['undefined', undefined],
    ['対のないサロゲート（値）', '\uD800'],
    ['関数', () => 1],
  ])('%s は符号化せず 2001 で拒否する', async (_label, value) => {
    await expectVericertsError(
      async () => encodeDagCbor(value),
      ErrorCodes.INVALID_DID,
      'plc_operation_invalid',
    );
  });

  it('対のないサロゲートを含むキーを拒否する', async () => {
    await expectVericertsError(
      async () => encodeDagCbor({ '\uDC00': null }),
      ErrorCodes.INVALID_DID,
    );
  });

  it('深すぎる入れ子を拒否する', async () => {
    let nested: unknown = null;
    for (let i = 0; i < 20; i += 1) {
      nested = [nested];
    }
    await expectVericertsError(async () => encodeDagCbor(nested), ErrorCodes.INVALID_DID);
  });
});
