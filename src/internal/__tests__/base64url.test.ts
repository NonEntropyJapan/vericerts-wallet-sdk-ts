/**
 * `base64urlText`（UTF-8 文字列 → パディングなし base64url）の単体テスト。
 *
 * 本関数の出力は JWS / JWT / SD-JWT の signing-input そのものであり、1 文字でも変われば
 * 本 SDK が発行する全ての署名値が変わる。したがってここでは「正しく動くこと」ではなく
 * 「現在の出力から一切変わらないこと」を固定するのが目的である。
 *
 * 検証内容:
 * - 往復: `base64urlnopad.decode` で元の UTF-8 バイト列に戻る（ASCII / 日本語 / 絵文字 / 空文字）。
 * - 既知ベクタ: RFC 7515 A.1 の JWS ヘッダを含む固定入力が、期待どおりの文字列を返す。
 * - 字母: パディング `=` を付けず、base64 標準アルファベットの `+` / `/` を使わない
 *   （バイト長 mod 3 が 1 / 2 の入力＝本来パディングが付く長さでも同様）。
 *
 * 公開バレルからは到達できない内部ヘルパのため、実装モジュールを直接 import する。
 */

import { describe, expect, it } from 'bun:test';
import { base64urlnopad } from '@scure/base';
import { base64urlText } from '../base64url.js';

/** 往復検証に使う入力（ASCII / 多バイト日本語 / サロゲートペア絵文字 / 空文字）。 */
const ROUND_TRIP_INPUTS: readonly string[] = [
  '',
  'abc',
  'The quick brown fox jumps over the lazy dog.',
  'こんにちは、世界',
  '🎉🇯🇵👨‍👩‍👧‍👦',
  '{"vct":"https://example.com/身分証","name":"山田 太郎"}',
];

/**
 * 現行実装の出力から採取した固定ベクタ（変更検知用）。
 *
 * 先頭は RFC 7515 Appendix A.1 の JWS Protected Header。残りは本 SDK が実際に組み立てる
 * ヘッダ形と、パディング境界（バイト長 mod 3 = 1 / 2）を跨ぐ短い入力である。
 */
const KNOWN_VECTORS: readonly (readonly [input: string, expected: string])[] = [
  ['{"typ":"JWT",\r\n "alg":"HS256"}', 'eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9'],
  ['{"alg":"ES256","typ":"vc+sd-jwt"}', 'eyJhbGciOiJFUzI1NiIsInR5cCI6InZjK3NkLWp3dCJ9'],
  ['こんにちは', '44GT44KT44Gr44Gh44Gv'],
  ['🎉', '8J-OiQ'],
  ['~~~???>>>', 'fn5-Pz8_Pj4-'],
  ['', ''],
];

/** バイト長 mod 3 が 1 / 2 になる入力（誤ったエンコーダなら `=` パディングが現れる長さ）。 */
const UNPADDED_INPUTS: readonly string[] = [
  'a', // 1 バイト（mod 3 = 1）
  'ab', // 2 バイト（mod 3 = 2）
  'ÿ', // UTF-8 で 2 バイト（mod 3 = 2）
  'ÿÿ', // UTF-8 で 4 バイト（mod 3 = 1）
  '🎉', // UTF-8 で 4 バイト（mod 3 = 1）
  'あ', // UTF-8 で 3 バイト（mod 3 = 0、対照）
];

describe('base64urlText', () => {
  it('base64urlnopad.decode で元の UTF-8 バイト列に戻る', () => {
    for (const input of ROUND_TRIP_INPUTS) {
      const decoded = base64urlnopad.decode(base64urlText(input));
      expect(decoded).toEqual(new TextEncoder().encode(input));
      expect(new TextDecoder().decode(decoded)).toBe(input);
    }
  });

  it('既知ベクタと完全一致する（署名値を変えないための固定）', () => {
    for (const [input, expected] of KNOWN_VECTORS) {
      expect(base64urlText(input)).toBe(expected);
    }
  });

  it('パディング `=` と base64 標準アルファベット `+` / `/` を出力しない', () => {
    for (const input of UNPADDED_INPUTS) {
      const encoded = base64urlText(input);
      expect(encoded).not.toContain('=');
      expect(encoded).not.toContain('+');
      expect(encoded).not.toContain('/');
      expect(encoded).toMatch(/^[A-Za-z0-9_-]*$/);
    }
  });

  it('`+` / `/` を生む 6 ビット並びを `-` / `_` に写す', () => {
    // '~~~???>>>' は base64 標準では "fn5+Pz8/Pj4+" になる（`+` と `/` を両方含む）。
    // base64url では同じ 6 ビット並びが `-` / `_` に写らなければならない。
    const encoded = base64urlText('~~~???>>>');
    expect(encoded).toContain('-');
    expect(encoded).toContain('_');
  });
});
