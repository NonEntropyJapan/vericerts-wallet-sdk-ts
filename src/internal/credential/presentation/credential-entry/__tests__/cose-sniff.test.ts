/**
 * `looksLikeCoseSign1` の単体テスト。
 *
 * 本関数は「未実装の `vc+cose` を JWT として読ませない」ためだけの外形判定であり、正誤の
 * 両方向に実害がある:
 * - 取りこぼすと COSE_Sign1 が JWT-VC 経路へ落ち、署名検証をしていないのに `SIG_INVALID`
 *   （3010）という誤った診断コードが返る。
 * - 過検知すると、単に壊れているだけの文字列まで `VC_SCHEMA_INVALID`（3002）に化け、
 *   既存の診断が変わってしまう。
 *
 * そのため「COSE_Sign1 だと確信できる形」だけを true にすることを両側から表明する。
 */

import { describe, expect, it } from 'bun:test';
import { base64urlnopad } from '@scure/base';
import { looksLikeCoseSign1 } from '../cose-sniff.js';

/** CBOR の byte string（長さ 23 以下）を組み立てる。 */
function bstr(...bytes: readonly number[]): readonly number[] {
  return [0x40 | bytes.length, ...bytes];
}

/** COSE_Sign1 の本体（4 要素配列: protected / unprotected / payload / signature）。 */
const COSE_SIGN1_BODY = [
  0x84, // array(4)
  ...bstr(0xa1, 0x01, 0x26), // protected: bstr（中身は解釈されない）
  0xa0, // unprotected: map(0)
  ...bstr(0x01, 0x02, 0x03, 0x04), // payload
  ...bstr(0x05, 0x06, 0x07), // signature
] as const;

/** バイト列を padding なし base64url に載せる。 */
function encode(bytes: readonly number[]): string {
  return base64urlnopad.encode(Uint8Array.from(bytes));
}

describe('looksLikeCoseSign1（vc+cose の外形判定）', () => {
  it('タグ 18（COSE_Sign1）で包まれた 4 要素配列を COSE と見なす', () => {
    expect(looksLikeCoseSign1(encode([0xd2, ...COSE_SIGN1_BODY]))).toBe(true);
  });

  it('タグなしの 4 要素配列も COSE と見なす（RFC 9052 はタグ省略を許す）', () => {
    expect(looksLikeCoseSign1(encode([...COSE_SIGN1_BODY]))).toBe(true);
  });

  it('JWT 形（`.` を含む）は COSE と見なさない', () => {
    expect(looksLikeCoseSign1('eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJhIn0.c2ln')).toBe(false);
  });

  it('SD-JWT 形（`~` を含む）は COSE と見なさない', () => {
    expect(looksLikeCoseSign1('eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJhIn0.c2ln~WyJzIl0~')).toBe(false);
  });

  it('base64url としてデコードできない文字列は COSE と見なさない', () => {
    expect(looksLikeCoseSign1('not-a-jws')).toBe(false);
    expect(looksLikeCoseSign1('!!!not base64!!!')).toBe(false);
  });

  it('空文字列は COSE と見なさない', () => {
    expect(looksLikeCoseSign1('')).toBe(false);
  });

  it('要素数が 4 でない CBOR 配列は COSE と見なさない', () => {
    // array(3): COSE_* は必ず 4 要素（RFC 9052 §2）。
    expect(looksLikeCoseSign1(encode([0x83, 0x40, 0xa0, 0x40]))).toBe(false);
  });

  it('COSE_Sign1 以外のタグ（17 = COSE_Mac0）は COSE_Sign1 と見なさない', () => {
    expect(looksLikeCoseSign1(encode([0xd1, ...COSE_SIGN1_BODY]))).toBe(false);
  });

  it('タグの直後が途切れている入力は例外にせず false を返す', () => {
    expect(looksLikeCoseSign1(encode([0xd2]))).toBe(false);
  });

  it('CBOR 配列でも map でもない先頭（byte string）は COSE と見なさない', () => {
    expect(looksLikeCoseSign1(encode([...bstr(0x01, 0x02, 0x03, 0x04)]))).toBe(false);
  });
});
