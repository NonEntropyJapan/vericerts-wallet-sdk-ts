/**
 * Transaction Data 抽出のユニットテスト。
 */

import { describe, expect, test } from 'bun:test';
import { base64urlnopad } from '@scure/base';
import type { VericertsError } from '../../../errors.js';
import { extractTransactionData } from '../extract.js';
import { TRANSACTION_DATA_HASH_ALG } from '../types.js';

/** JSON オブジェクトを OID4VP `transaction_data` 要素の base64url 文字列にエンコードする。 */
function encode(obj: Record<string, unknown>): string {
  return base64urlnopad.encode(new TextEncoder().encode(JSON.stringify(obj)));
}

function codeOf(fn: () => unknown): string {
  try {
    fn();
  } catch (err) {
    return (err as VericertsError).code;
  }
  throw new Error('expected throw');
}

describe('extractTransactionData', () => {
  test('type / credential_ids を含む要素を正規化する', () => {
    const encoded = encode({
      type: 'payment',
      credential_ids: ['pid'],
      amount: '100.00',
      recipient: 'ACME',
    });
    const [entry, ...rest] = extractTransactionData([encoded]);
    expect(rest).toHaveLength(0);
    expect(entry?.type).toBe('payment');
    expect(entry?.credentialIds).toEqual(['pid']);
    expect(entry?.encoded).toBe(encoded);
    // 種別固有フィールドは claims に保持される（同意提示 UI 用）。
    expect(entry?.claims.amount).toBe('100.00');
    expect(entry?.claims.recipient).toBe('ACME');
  });

  test('transaction_data_hashes_alg 省略時は sha-256 既定', () => {
    const [entry] = extractTransactionData([encode({ type: 'payment', credential_ids: ['pid'] })]);
    expect(entry?.hashAlgorithms).toEqual([TRANSACTION_DATA_HASH_ALG]);
  });

  test('明示された transaction_data_hashes_alg を保持する', () => {
    const [entry] = extractTransactionData([
      encode({
        type: 'payment',
        credential_ids: ['pid'],
        transaction_data_hashes_alg: ['sha-256'],
      }),
    ]);
    expect(entry?.hashAlgorithms).toEqual(['sha-256']);
  });

  test('複数要素を順序を保って抽出する', () => {
    const entries = extractTransactionData([
      encode({ type: 'a', credential_ids: ['c1'] }),
      encode({ type: 'b', credential_ids: ['c2'] }),
    ]);
    expect(entries.map((e) => e.type)).toEqual(['a', 'b']);
  });

  test('undefined / 空配列は Transaction Data 要求なし（空配列）', () => {
    expect(extractTransactionData(undefined)).toEqual([]);
    expect(extractTransactionData([])).toEqual([]);
  });

  test('type 欠落は 8030', () => {
    expect(codeOf(() => extractTransactionData([encode({ credential_ids: ['pid'] })]))).toBe(
      '8030',
    );
  });

  test('credential_ids 欠落 / 空配列は 8030', () => {
    expect(codeOf(() => extractTransactionData([encode({ type: 'payment' })]))).toBe('8030');
    expect(
      codeOf(() => extractTransactionData([encode({ type: 'payment', credential_ids: [] })])),
    ).toBe('8030');
  });

  test('未対応ハッシュアルゴリズム（sha-256 を含まない）は 8030', () => {
    expect(
      codeOf(() =>
        extractTransactionData([
          encode({
            type: 'payment',
            credential_ids: ['pid'],
            transaction_data_hashes_alg: ['sha-512'],
          }),
        ]),
      ),
    ).toBe('8030');
  });

  test('base64url でない / JSON でない要素は 8030', () => {
    expect(codeOf(() => extractTransactionData(['!!!not-base64!!!']))).toBe('8030');
    const notJson = base64urlnopad.encode(new TextEncoder().encode('not-json'));
    expect(codeOf(() => extractTransactionData([notJson]))).toBe('8030');
  });

  test('JSON 配列（オブジェクトでない）要素は 8030', () => {
    const arr = base64urlnopad.encode(new TextEncoder().encode('[1,2,3]'));
    expect(codeOf(() => extractTransactionData([arr]))).toBe('8030');
  });
});
