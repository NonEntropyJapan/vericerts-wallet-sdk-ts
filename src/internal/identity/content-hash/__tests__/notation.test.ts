/**
 * contentHash 表記のパース・正規化の検証。
 *
 * hex / base64url / multibase / multibase multihash の表記差が同じ正規化結果へ
 * 落ちること、未対応アルゴリズム・不正表記が fail-closed で拒否されることを確認する。
 */

import { describe, expect, it } from 'bun:test';
import { sha256 } from '@noble/hashes/sha2.js';
import { base32nopad, base58, base64, base64urlnopad, hex } from '@scure/base';
import { ErrorCodes, VericertsError } from '../../../errors.js';
import { formatContentHash, parseContentHash } from '../notation.js';

const CONTENT = new TextEncoder().encode('vericerts artifact');
const DIGEST = sha256(CONTENT);
const HEX = hex.encode(DIGEST);
const CANONICAL = `sha2-256-${HEX}`;

/** `parseContentHash` が投げた VericertsError のコードを取り出す。 */
function codeOf(fn: () => unknown): string {
  try {
    fn();
  } catch (error) {
    expect(error).toBeInstanceOf(VericertsError);
    return (error as VericertsError).code;
  }
  throw new Error('例外が発生しませんでした');
}

describe('parseContentHash: アルゴリズム名の表記ゆれ', () => {
  it.each([
    ['sha256'],
    ['sha-256'],
    ['sha2-256'],
    ['SHA256'],
    ['SHA-256'],
  ])('%s- プレフィックスを sha2-256 へ正規化する', (alias) => {
    const parsed = parseContentHash(`${alias}-${HEX}`);
    expect(parsed.algorithm).toBe('sha2-256');
    expect(parsed.notation).toBe(CANONICAL);
    expect(parsed.digest).toEqual(DIGEST);
  });
});

describe('parseContentHash: ダイジェスト表記の吸収', () => {
  it('小文字 hex を受理する', () => {
    expect(parseContentHash(`sha256-${HEX}`).notation).toBe(CANONICAL);
  });

  it('大文字 hex を受理する', () => {
    expect(parseContentHash(`sha256-${HEX.toUpperCase()}`).notation).toBe(CANONICAL);
  });

  it('padding なし base64url を受理する', () => {
    expect(parseContentHash(`sha256-${base64urlnopad.encode(DIGEST)}`).notation).toBe(CANONICAL);
  });

  it('padding あり base64url を受理する', () => {
    const padded = `${base64urlnopad.encode(DIGEST)}=`;
    expect(parseContentHash(`sha256-${padded}`).notation).toBe(CANONICAL);
  });

  it('multibase base16（f）を受理する', () => {
    expect(parseContentHash(`sha256-f${HEX}`).notation).toBe(CANONICAL);
  });

  it('multibase base32（b）を受理する', () => {
    const body = base32nopad.encode(DIGEST).toLowerCase();
    expect(parseContentHash(`sha256-b${body}`).notation).toBe(CANONICAL);
  });

  it('multibase base58btc（z）を受理する', () => {
    expect(parseContentHash(`sha256-z${base58.encode(DIGEST)}`).notation).toBe(CANONICAL);
  });

  it('multibase base64pad（M）を受理する', () => {
    expect(parseContentHash(`sha256-M${base64.encode(DIGEST)}`).notation).toBe(CANONICAL);
  });
});

describe('parseContentHash: multibase multihash 表記', () => {
  const multihash = Uint8Array.from([0x12, 0x20, ...DIGEST]);

  it('base64url multibase の multihash を受理する', () => {
    const parsed = parseContentHash(`u${base64urlnopad.encode(multihash)}`);
    expect(parsed.notation).toBe(CANONICAL);
  });

  it('base58btc multibase の multihash を受理する', () => {
    const parsed = parseContentHash(`z${base58.encode(multihash)}`);
    expect(parsed.notation).toBe(CANONICAL);
  });

  it('未対応の multihash コード（sha3-256 = 0x16）は 1030 で拒否する', () => {
    const unsupported = Uint8Array.from([0x16, 0x20, ...DIGEST]);
    expect(codeOf(() => parseContentHash(`z${base58.encode(unsupported)}`))).toBe(
      ErrorCodes.UNSUPPORTED_ALGORITHM,
    );
  });

  it('宣言長とダイジェスト長が食い違う multihash は 2016 で拒否する', () => {
    const broken = Uint8Array.from([0x12, 0x1f, ...DIGEST]);
    expect(codeOf(() => parseContentHash(`z${base58.encode(broken)}`))).toBe(
      ErrorCodes.CONTENT_HASH_FORMAT_INVALID,
    );
  });

  it('非 canonical varint の multihash は拒否する', () => {
    // 0x12 を [0x92, 0x00] と冗長にエンコードした非 canonical 表現。
    const nonCanonical = Uint8Array.from([0x92, 0x00, 0x20, ...DIGEST]);
    expect(() => parseContentHash(`z${base58.encode(nonCanonical)}`)).toThrow(VericertsError);
  });
});

describe('parseContentHash: fail-closed', () => {
  it('未対応アルゴリズム名（md5）は 1030 で拒否する', () => {
    expect(codeOf(() => parseContentHash(`md5-${'ab'.repeat(16)}`))).toBe(
      ErrorCodes.UNSUPPORTED_ALGORITHM,
    );
  });

  it('未対応アルゴリズム名（sha3-256）は 1030 で拒否する', () => {
    expect(codeOf(() => parseContentHash(`sha3-256-${HEX}`))).toBe(
      ErrorCodes.UNSUPPORTED_ALGORITHM,
    );
  });

  it('prohibited な sha-1 を受理しない', () => {
    expect(() => parseContentHash(`sha-1-${'ab'.repeat(20)}`)).toThrow(VericertsError);
  });

  it('空文字は 2016 で拒否する', () => {
    expect(codeOf(() => parseContentHash(''))).toBe(ErrorCodes.CONTENT_HASH_FORMAT_INVALID);
  });

  it('ダイジェスト長が足りない hex は 2016 で拒否する', () => {
    expect(codeOf(() => parseContentHash(`sha256-${HEX.slice(0, 62)}`))).toBe(
      ErrorCodes.CONTENT_HASH_FORMAT_INVALID,
    );
  });

  it('hex に見えない不正文字列は 2016 で拒否する', () => {
    expect(codeOf(() => parseContentHash(`sha256-${'z'.repeat(64)}`))).toBe(
      ErrorCodes.CONTENT_HASH_FORMAT_INVALID,
    );
  });
});

describe('parseContentHash: プロトタイプ汚染耐性', () => {
  it.each([
    ['constructor'],
    ['toString'],
    ['__proto__'],
    ['valueOf'],
    ['hasOwnProperty'],
  ])('アルゴリズム名 %s は対応表にヒットしない', (name) => {
    expect(() => parseContentHash(`${name}-${HEX}`)).toThrow(VericertsError);
  });

  it('multibase プレフィックスに Object.prototype のキーは使えない', () => {
    // `constructor` の先頭 1 文字 `c` は対応表に無いプレフィックス。
    expect(() => parseContentHash(`sha256-c${HEX}`)).toThrow(VericertsError);
  });
});

describe('formatContentHash', () => {
  it('canonical 表記を組み立てる', () => {
    expect(formatContentHash('sha2-256', DIGEST)).toBe(CANONICAL);
  });

  it('canonical 表記は再パースできる（ラウンドトリップ）', () => {
    expect(parseContentHash(formatContentHash('sha2-256', DIGEST)).digest).toEqual(DIGEST);
  });
});
