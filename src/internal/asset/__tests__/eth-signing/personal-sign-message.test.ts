/**
 * `personalSignMessageBytes`（`personal_sign` の `params[0]` → 署名対象メッセージのバイト列、の唯一の正規化）のテスト。
 * 署名時のガード（`personalSignPayload`）と extension の承認前検証・表示が同じバイト列を読むための境界条件を固定する。
 */

import { describe, expect, test } from 'bun:test';
import { personalSignPayload } from '../../eth-signing.js';
import { personalSignMessageBytes } from '../../personal-sign-message.js';

const utf8 = (text: string) => Array.from(new TextEncoder().encode(text));

describe('personalSignMessageBytes', () => {
  test.each([
    ['小文字 hex', '0x68656c6c6f', utf8('hello')],
    ['大文字の hex 桁', '0x68656C6C6F', utf8('hello')],
    ['0x のみ（空メッセージ）', '0x', []],
    ['BOM 付き hex は BOM を落とさない', '0xefbbbf62', [0xef, 0xbb, 0xbf, 0x62]],
    ['不正 UTF-8 の hex もそのままバイト列', '0xff', [0xff]],
  ])('%s: hex をバイト列として読む', (_name, data, expected) => {
    expect(Array.from(personalSignMessageBytes(data))).toEqual(expected);
  });

  test.each([
    ['平文', 'hello'],
    ['奇数長の 0x', '0xabc'],
    ['0X 接頭辞（大文字 X は hex ではない）', '0X68656c6c6f'],
    ['hex でない 0x', '0xzz'],
    ['接頭辞なしの hex 桁', '68656c6c6f'],
    ['BOM 付き平文', '\ufeffhello'],
  ])('%s: 文字列そのものを UTF-8 で読む', (_name, data) => {
    expect(Array.from(personalSignMessageBytes(data))).toEqual(utf8(data));
  });

  test('personalSignPayload はこの正規化の結果に EIP-191 の接頭辞を付けたものを署名対象にする', () => {
    for (const data of ['hello', '0x68656C6C6F', '0X68656c6c6f', '0xabc', '0x']) {
      const message = personalSignMessageBytes(data);
      const prefix = utf8(`\x19Ethereum Signed Message:\n${message.length}`);
      expect(Array.from(personalSignPayload(data))).toEqual([...prefix, ...message]);
    }
  });
});
