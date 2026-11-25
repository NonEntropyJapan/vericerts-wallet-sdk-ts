/**
 * 署名側 `jti` の入口検証 `resolveProofJti` のテスト。
 *
 * 仕様は `jti` を UUIDv4（32〜36 文字、version / variant nibble まで検査）とし、不適合を
 * `4013 NONCE_MALFORMED` とする。境界は「受理する正準形・ハイフンなし形」と「長さ・version・variant・
 * 文字種のどれか 1 つだけが外れた値」の対で固定する。
 */

import { describe, expect, test } from 'bun:test';
import { ErrorCodes, VericertsError } from '../../errors.js';
import { resolveProofJti } from '../proof-jti.js';

const V4 = '3b241101-e2bb-4255-8caf-4136c566a962';
const V4_COMPACT = '3b241101e2bb42558caf4136c566a962';

function codeOf(value: unknown): string | undefined {
  try {
    resolveProofJti(value);
  } catch (e) {
    expect(e).toBeInstanceOf(VericertsError);
    return (e as VericertsError).code;
  }
  return undefined;
}

describe('resolveProofJti: 指定値の検査', () => {
  test.each([
    ['正準形 36 文字', V4],
    ['大文字の正準形', V4.toUpperCase()],
    ['ハイフンなし 32 文字', V4_COMPACT],
    ['variant a', '3b241101-e2bb-4255-aaaf-4136c566a962'],
    ['variant 9', '3b241101-e2bb-4255-9caf-4136c566a962'],
    ['variant b', '3b241101-e2bb-4255-bcaf-4136c566a962'],
  ])('%s は受理して同じ値を返す', (_label, jti) => {
    expect(resolveProofJti(jti)).toBe(jti);
  });

  test.each([
    ['空文字', ''],
    ['固定の短い値', 'jti-1'],
    ['nil UUID', '00000000-0000-0000-0000-000000000000'],
    ['nil UUID（ハイフンなし）', '00000000000000000000000000000000'],
    ['UUIDv1', 'c232ab00-9414-11ec-b3c8-9f6bdeced846'],
    ['version 5', '3b241101-e2bb-5255-8caf-4136c566a962'],
    ['variant 7（RFC 4122 外）', '3b241101-e2bb-4255-7caf-4136c566a962'],
    ['variant c', '3b241101-e2bb-4255-ccaf-4136c566a962'],
    ['ハイフンなしで version 1', '3b241101e2bb12558caf4136c566a962'],
    ['ハイフンなしで variant 7', '3b241101e2bb42557caf4136c566a962'],
    ['base64url(16B) の 22 文字', 'AbCdEfGhIjKlMnOpQrStUv'],
    ['31 文字', V4_COMPACT.slice(0, 31)],
    ['33 文字', `${V4_COMPACT}0`],
    ['35 文字（ハイフン 1 つ欠落）', V4.replace('-', '')],
    ['37 文字', `${V4}0`],
    ['16 進以外の文字', '3b241101-e2bb-4255-8caf-4136c566a96g'],
    ['末尾の改行', `${V4}\n`],
    ['前後の空白', ` ${V4}`],
    ['ハイフン位置のずれ', '3b2411-01e2bb-4255-8caf-4136c566a962'],
  ])('%s は 4013 で拒否する', (_label, jti) => {
    expect(codeOf(jti)).toBe(ErrorCodes.NONCE_MALFORMED);
  });

  test.each([
    ['null', null],
    ['数値', 123],
    ['オブジェクト', { jti: V4 }],
    ['配列', [V4]],
    ['真偽値', true],
  ])('文字列以外（%s）は 4013 で拒否する（未指定として扱わない）', (_label, jti) => {
    expect(codeOf(jti)).toBe(ErrorCodes.NONCE_MALFORMED);
  });

  test('例外メッセージに jti の値を含めない', () => {
    const secret = 'secret-jti-value';
    try {
      resolveProofJti(secret);
      expect.unreachable();
    } catch (e) {
      expect((e as VericertsError).message).not.toContain(secret);
    }
  });
});

describe('resolveProofJti: 未指定', () => {
  test('undefined は UUIDv4 を新規に生成し、呼び出しごとに異なる', () => {
    const first = resolveProofJti(undefined);
    const second = resolveProofJti(undefined);
    expect(resolveProofJti(first)).toBe(first);
    expect(first).toHaveLength(36);
    expect(first).not.toBe(second);
  });
});
