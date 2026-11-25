/**
 * tag 付き・不定長の COSE が payload をログに残さないことの回帰テスト。
 *
 * RFC 9052 の COSE_Sign1 / COSE_Mac0 は CBOR tag 付き（`d2 84 …` = tag 18、`d1 84 …` = tag 17）で
 * 流通する。`redactCosePayload` が先頭の array(4) しか受理しないと、tag 付き・不定長 payload / 配列の
 * COSE が丸ごと素通しされ、payload（PII）が hex のままログに残っていた。
 */

import { describe, expect, it } from 'bun:test';
import { base64nopad, base64urlnopad, hex } from '@scure/base';
import { maskLogAttributes } from '../../logger.js';

const SECRET = new TextEncoder().encode('SECRET-PAYLOAD-PII-12345');
const SECRET_HEX = hex.encode(SECRET);
const REDACTED_PAYLOAD = new TextEncoder().encode('[REDACTED]');

const PROTECTED = Uint8Array.of(0x43, 0xa1, 0x01, 0x26); // bstr(3) `{1:-7}`
const UNPROTECTED = Uint8Array.of(0xa0);
const SIGNATURE = Uint8Array.of(0x41, 0x99);

function concat(...parts: readonly Uint8Array[]): Uint8Array {
  return Uint8Array.from(parts.flatMap((part) => [...part]));
}

/** 定長 byte string（24..255 バイトは 2 バイト head）。 */
function bstr(payload: Uint8Array): Uint8Array {
  const head = payload.length <= 23 ? [0x40 | payload.length] : [0x58, payload.length];
  return concat(Uint8Array.from(head), payload);
}

/** 不定長 byte string（`5f` + 定長チャンク + `ff`）。 */
function indefiniteBstr(payload: Uint8Array): Uint8Array {
  const mid = Math.floor(payload.length / 2);
  return concat(
    Uint8Array.of(0x5f),
    bstr(payload.slice(0, mid)),
    bstr(payload.slice(mid)),
    Uint8Array.of(0xff),
  );
}

/** 4 要素 COSE 本体（定長配列 / 不定長配列）。 */
function body(payloadItem: Uint8Array, indefiniteArray = false): Uint8Array {
  const items = [PROTECTED, UNPROTECTED, payloadItem, SIGNATURE];
  return indefiniteArray
    ? concat(Uint8Array.of(0x9f), ...items, Uint8Array.of(0xff))
    : concat(Uint8Array.of(0x84), ...items);
}

/** 期待値: 同じ構造で payload だけ `[REDACTED]`（定長）に差し替わった COSE。 */
function expected(tag: readonly number[], indefiniteArray = false): Uint8Array {
  return concat(Uint8Array.from(tag), body(bstr(REDACTED_PAYLOAD), indefiniteArray));
}

const TAG18 = [0xd2];
const TAG18_TWO_BYTE = [0xd8, 0x12];
const TAG17 = [0xd1];
const NO_TAG: number[] = [];

const CASES: ReadonlyArray<readonly [string, Uint8Array, Uint8Array]> = [
  ['untagged Sign1（従来）', concat(body(bstr(SECRET))), expected(NO_TAG)],
  ['tag 18 Sign1', concat(Uint8Array.from(TAG18), body(bstr(SECRET))), expected(TAG18)],
  [
    'tag 18（d8 12）',
    concat(Uint8Array.from(TAG18_TWO_BYTE), body(bstr(SECRET))),
    expected(TAG18_TWO_BYTE),
  ],
  ['tag 17 Mac0', concat(Uint8Array.from(TAG17), body(bstr(SECRET))), expected(TAG17)],
  ['不定長 payload', concat(Uint8Array.from(TAG18), body(indefiniteBstr(SECRET))), expected(TAG18)],
  ['不定長配列', concat(Uint8Array.from(TAG18), body(bstr(SECRET), true)), expected(TAG18, true)],
  ['不定長配列（tag なし）', body(bstr(SECRET), true), expected(NO_TAG, true)],
  [
    '不定長配列 + 不定長 payload',
    concat(Uint8Array.from(TAG18), body(indefiniteBstr(SECRET), true)),
    expected(TAG18, true),
  ],
  ['tag の入れ子', concat(Uint8Array.of(0xd2, 0xd2), body(bstr(SECRET))), expected([0xd2, 0xd2])],
];

const ENCODINGS: ReadonlyArray<readonly [string, (bytes: Uint8Array) => string]> = [
  ['hex', (bytes) => hex.encode(bytes)],
  ['base64', (bytes) => base64nopad.encode(bytes)],
  ['base64url', (bytes) => base64urlnopad.encode(bytes)],
];

function maskValue(value: string): string {
  return maskLogAttributes({ blob: value }).blob as string;
}

describe('tag 付き・不定長 COSE の payload マスキング', () => {
  for (const [caseName, input, want] of CASES) {
    for (const [encName, encode] of ENCODINGS) {
      it(`${caseName} / ${encName}: payload が落ち、他は元のまま`, () => {
        const masked = maskValue(encode(input));
        // `+` `/` と `-` `_` の両方を含まない base64url 入力は base64 と判別できず、base64 で
        // 再エンコードされ得る（既存の基数判定の取り決め）。基数差は同一視して比較する。
        const unify = (text: string): string => text.replaceAll('+', '-').replaceAll('/', '_');
        expect(unify(masked)).toBe(unify(encode(want)));
        expect(masked.includes(SECRET_HEX)).toBe(false);
      });
    }
  }

  it('COSE でない tag 付き CBOR（配列長 3）は素通しする（誤検知しない）', () => {
    const notCose = hex.encode(
      concat(Uint8Array.of(0xd2, 0x83), PROTECTED, UNPROTECTED, bstr(SECRET)),
    );
    expect(maskValue(notCose)).toBe(notCose);
  });

  it('不定長配列が 4 要素で終わらなければ COSE とみなさず素通しする', () => {
    const fiveItems = hex.encode(
      concat(
        Uint8Array.of(0x9f),
        PROTECTED,
        UNPROTECTED,
        bstr(SECRET),
        SIGNATURE,
        SIGNATURE,
        Uint8Array.of(0xff),
      ),
    );
    expect(maskValue(fiveItems)).toBe(fiveItems);
  });

  it('壊れた入力（break 欠落・tag だけ）でも例外を投げず素通しする', () => {
    const truncated = hex.encode(concat(Uint8Array.of(0xd2, 0x9f), PROTECTED, UNPROTECTED));
    expect(maskValue(truncated)).toBe(truncated);
    expect(maskValue('d2')).toBe('d2');
  });
});
