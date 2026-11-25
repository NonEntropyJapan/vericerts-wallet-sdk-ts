/**
 * `verifyTransactionDataHashes` のハッシュアルゴリズム検証。
 *
 * 未対応アルゴリズムの fail-closed 拒否（プロトタイプ汚染回帰を含む）と、採用アルゴリズムを
 * 要求側 Authorization Request の宣言集合に制約する検査を固定する。共有 helper は
 * `verify.fixtures.ts`、突合本体のテストは `verify.test.ts`。
 */

import { describe, test } from 'bun:test';
import { extractTransactionData } from '../extract.js';
import { computeTransactionDataHashesWithAlg } from '../hashes.js';
import type { TransactionDataEntry } from '../types.js';
import { verifyTransactionDataHashes } from '../verify.js';
import {
  expect10402,
  PAYMENT_TD,
  present,
  SHIPPING_TD,
  verifyKbPayload,
} from './verify.fixtures.js';

describe('verifyTransactionDataHashes: ハッシュアルゴリズムは fail-closed', () => {
  const transaction_data_hashes = ['ZmFrZS1oYXNo'];

  // `transaction_data_hashes_alg` は受領 KB-JWT 由来＝攻撃者が自由に指定できる。ここで働く
  // 防御線は `verify.ts` の `assertAlgRequested`（要求側 `requested[]` の宣言集合による制約）
  // であり、以下の値は `sha-256` しか宣言していない要求側の集合に無いため、`hashes.ts` の
  // アルゴリズム対応表へ到達する前に 10402 で弾かれる。`''` と `256` はさらに手前の
  // `resolveHashAlg`（非空文字列を要求）で弾かれる。
  // したがって本 describe は対応表の実装（`Object.create(null)` か通常のオブジェクトリテラルか）
  // には依存しない。対応表の null プロトタイプ防御そのものの回帰テストは、要求側の制約を
  // 経由しない公開 API を直接呼ぶ下の describe が担う。
  const UNSUPPORTED: readonly unknown[] = [
    'sha-512',
    256,
    '',
    'constructor',
    'toString',
    'valueOf',
    '__proto__',
  ];
  for (const alg of UNSUPPORTED) {
    test(`alg=${JSON.stringify(alg)} は未対応として 10402 で拒否される`, () => {
      expect10402(
        () => verifyKbPayload({ transaction_data_hashes, transaction_data_hashes_alg: alg }),
        'transaction_data_hashes_alg_unsupported',
      );
    });
  }
});

describe('computeTransactionDataHashesWithAlg: 対応表は Object.prototype 由来の鍵を引かない', () => {
  // プロトタイプ汚染回帰テスト。本関数は `exports/eudi.ts` から公開されており、
  // 任意の文字列 alg を**そのまま**対応表の添字として受け取る（`assertAlgRequested` のような
  // 要求側宣言集合による事前の絞り込みが無い）ため、null プロトタイプ防御はここで load-bearing。
  // `hashes.ts` の対応表を `Object.create(null)` ではなく通常のオブジェクトリテラルで作ると、
  // 以下の鍵が `Object.prototype` のプロパティ（関数など非 undefined 値）にヒットし、
  // 「表に無ければ拒否」という fail-closed をすり抜けて本テストは FAIL する
  // （`constructor` は `Object` が digest としてそのまま通り例外なし、`valueOf` / `toString` /
  // `hasOwnProperty` は `VericertsError` ではない TypeError 等になる）。
  const entries = extractTransactionData([PAYMENT_TD]);
  const PROTOTYPE_KEYS: readonly string[] = [
    'constructor',
    'toString',
    'valueOf',
    'hasOwnProperty',
    'isPrototypeOf',
    'propertyIsEnumerable',
    '__proto__',
  ];
  for (const alg of PROTOTYPE_KEYS) {
    test(`alg=${JSON.stringify(alg)} は未対応として 10402 で拒否される`, () => {
      expect10402(
        () => computeTransactionDataHashesWithAlg(entries, alg),
        'transaction_data_hashes_alg_unsupported',
      );
    });
  }
});

describe('verifyTransactionDataHashes: alg は要求側の宣言集合に制約される', () => {
  // `sha-256` を宣言しない要求要素。`normalizeHashAlgorithms` が `sha-256` 非包含を拒否するため
  // `extractTransactionData` では作れず、公開 IF の型（`TransactionDataEntry`）を直接組む。
  const sha512Only = (encoded: string): TransactionDataEntry => ({
    type: 'payment',
    credentialIds: ['pid'],
    hashAlgorithms: ['sha-512'],
    claims: {},
    encoded,
  });

  /** 要求側が宣言していない alg として 10402 で拒否されることを確認する。 */
  const expectAlgRejected = (
    requested: readonly TransactionDataEntry[],
    encoded: readonly string[],
  ): void =>
    expect10402(
      () => verifyTransactionDataHashes({ requested, presentation: present(encoded) }),
      'transaction_data_hashes_alg_unsupported',
    );

  // KB-JWT 側に `sha-512` を載せる形は回帰テストにならない: 対応表に無いため
  // `computeTransactionDataHashesWithAlg` が同じ 10402 を投げ、要求側での制約が無くても
  // テストが通ってしまう。そこで KB-JWT は `sha-256`（ハッシュも期待値と一致する）とし、
  // 要求側だけが `sha-256` を宣言していない状況を作る。制約を外すと受理され FAIL する。
  test('要求要素が宣言していない alg は 10402', () => {
    expectAlgRejected([sha512Only(PAYMENT_TD)], [PAYMENT_TD]);
  });

  test('1 要素でも宣言していなければ 10402（全要素での宣言が必要）', () => {
    const declared = extractTransactionData([PAYMENT_TD])[0] as TransactionDataEntry;
    expectAlgRejected([declared, sha512Only(SHIPPING_TD)], [PAYMENT_TD, SHIPPING_TD]);
  });
});
