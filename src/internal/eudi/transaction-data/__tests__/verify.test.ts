/**
 * 受領 KB-JWT の `transaction_data_hashes` 突合のテスト。
 *
 * 実鍵・実 SD-JWT・実 KB-JWT を用い、モックは使わない。公開バレル（`exports/eudi.js`）越しに
 * 到達できることを含め、Verifier 側の突合が値・件数・順序の相違を検知することを確認する。
 * アルゴリズムの fail-closed / 要求側制約は `verify.alg.test.ts` を参照。
 */

import { describe, expect, test } from 'bun:test';
import * as eudiExports from '../../../../exports/eudi.js';
import { extractTransactionData } from '../extract.js';
import { verifyTransactionDataHashes } from '../verify.js';
import {
  encodeTd,
  expect10402,
  PAYMENT_TD,
  present,
  presentationBase,
  presentWithKbPayload,
  receivedHashes,
  SHIPPING_TD,
  verifyKbPayload,
} from './verify.fixtures.js';

describe('verifyTransactionDataHashes: 正常系', () => {
  test('要求した Transaction Data に束縛された提示を受理する', () => {
    expect(() =>
      verifyTransactionDataHashes({
        requested: extractTransactionData([PAYMENT_TD]),
        presentation: present([PAYMENT_TD]),
      }),
    ).not.toThrow();
  });

  test('複数要素でも要求順どおりなら受理する', () => {
    expect(() =>
      verifyTransactionDataHashes({
        requested: extractTransactionData([PAYMENT_TD, SHIPPING_TD]),
        presentation: present([PAYMENT_TD, SHIPPING_TD]),
      }),
    ).not.toThrow();
  });

  test('`transaction_data_hashes_alg` 不在は OID4VP 既定の sha-256 として受理する', () => {
    const bound = present([PAYMENT_TD]);
    // 本 SDK は常に alg を書き出すため、不在は他実装の提示を模した手組み KB-JWT で再現する。
    const presentation = presentWithKbPayload({
      nonce: 'nonce-1',
      aud: 'did:example:verifier',
      iat: 1_767_225_600,
      sd_hash: 'not-verified-by-this-helper',
      transaction_data_hashes: receivedHashes(bound),
    });
    expect(() =>
      verifyTransactionDataHashes({
        requested: extractTransactionData([PAYMENT_TD]),
        presentation,
      }),
    ).not.toThrow();
  });
});

describe('verifyTransactionDataHashes: 内容・件数・順序の相違', () => {
  test('要求内容が異なれば 10402（改竄検知）', () => {
    const tampered = encodeTd({
      type: 'payment',
      credential_ids: ['pid'],
      amount: '9900',
      payee: 'ACME Store',
    });
    expect10402(() =>
      verifyTransactionDataHashes({
        requested: extractTransactionData([tampered]),
        presentation: present([PAYMENT_TD]),
      }),
    );
  });

  test('同一 2 要素でも順序が入れ替わっていれば 10402', () => {
    // 2 要素は内容が異なるため、入れ替えるとハッシュ列の並びが変わる。
    expect10402(() =>
      verifyTransactionDataHashes({
        requested: extractTransactionData([SHIPPING_TD, PAYMENT_TD]),
        presentation: present([PAYMENT_TD, SHIPPING_TD]),
      }),
    );
  });

  test('2 件の提示を 1 件の要求で突合すると 10402（件数相違）', () => {
    expect10402(() =>
      verifyTransactionDataHashes({
        requested: extractTransactionData([PAYMENT_TD]),
        presentation: present([PAYMENT_TD, SHIPPING_TD]),
      }),
    );
  });

  test('1 件の提示を 2 件の要求で突合すると 10402（件数相違・逆方向）', () => {
    expect10402(() =>
      verifyTransactionDataHashes({
        requested: extractTransactionData([PAYMENT_TD, SHIPPING_TD]),
        presentation: present([PAYMENT_TD]),
      }),
    );
  });
});

describe('verifyTransactionDataHashes: 入力・KB-JWT の不備', () => {
  test('要求が空なら 10402（暗黙の成功を許さない）', () => {
    expect10402(
      () => verifyTransactionDataHashes({ requested: [], presentation: present([PAYMENT_TD]) }),
      'transaction_data_absent',
    );
  });

  test('KB-JWT が無い提示は 10402', () => {
    expect10402(
      () =>
        verifyTransactionDataHashes({
          requested: extractTransactionData([PAYMENT_TD]),
          presentation: presentationBase(),
        }),
      'key_binding_missing',
    );
  });

  const INVALID: readonly (readonly [string, Record<string, unknown>])[] = [
    ['クレーム自体が無い', {}],
    ['配列でない', { transaction_data_hashes: 'not-an-array' }],
    ['非文字列が混ざる', { transaction_data_hashes: [42] }],
    ['空配列', { transaction_data_hashes: [] }],
  ];
  for (const [label, overrides] of INVALID) {
    test(`\`transaction_data_hashes\` が${label}なら 10402`, () => {
      expect10402(() => verifyKbPayload(overrides), 'transaction_data_hashes_invalid');
    });
  }
});

describe('verifyTransactionDataHashes: 公開バレルからの到達性', () => {
  test('`exports/eudi.js` から突合・アルゴリズム指定計算に到達できる', () => {
    expect(typeof eudiExports.verifyTransactionDataHashes).toBe('function');
    expect(typeof eudiExports.computeTransactionDataHashesWithAlg).toBe('function');
    expect(() =>
      eudiExports.verifyTransactionDataHashes({
        requested: eudiExports.extractTransactionData([PAYMENT_TD]),
        presentation: present([PAYMENT_TD]),
      }),
    ).not.toThrow();
  });
});
