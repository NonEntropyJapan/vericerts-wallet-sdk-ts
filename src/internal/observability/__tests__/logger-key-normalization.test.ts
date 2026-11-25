/**
 * `maskLogAttributes` のキー名正規化の単位テスト。
 *
 * キー名は小文字化し英数字以外を除いた形で照合するため、snake_case / kebab-case / 空白区切りの
 * 同義キーも camelCase と同じ強制マスク規則に当たる。
 */

import { describe, expect, it } from 'bun:test';
import { maskLogAttributes } from '../logger.js';

describe('maskLogAttributes のキー名正規化', () => {
  it('強制削除対象は snake_case / kebab-case / 大文字 / 空白区切りでもキーごと落とす', () => {
    expect(
      maskLogAttributes({
        private_key: 'abc',
        'private-key': 'x',
        PRIVATE_KEY: 'y',
        'Private Key': 'z',
        mnemonic_phrase: 'abandon',
        duration_ms: 3,
      }),
    ).toEqual({ duration_ms: 3 });
  });

  it('[REDACTED] 対象は区切り文字の違いに関わらず値を置換する', () => {
    expect(
      maskLogAttributes({
        credential_subject: { name: 'a' },
        'credential-subject': 'q',
        CREDENTIAL_SUBJECT: 'r',
        'document-number': 'P1',
        'Document Number': 'P2',
        document_number: 'P3',
      }),
    ).toEqual({
      credential_subject: '[REDACTED]',
      'credential-subject': '[REDACTED]',
      CREDENTIAL_SUBJECT: '[REDACTED]',
      'document-number': '[REDACTED]',
      'Document Number': '[REDACTED]',
      document_number: '[REDACTED]',
    });
  });
});
