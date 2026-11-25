/**
 * Transaction Data と Dashboard の公開関数を検証する。
 * 公開バレルから各関数と引数型に到達でき、関数の引数の数・順序・型が
 * Transaction Data の抽出、ハッシュ計算、検証、同意の記録に対応することを確認する。
 */

import { describe, expect, test } from 'bun:test';
import * as sdk from '../../index.js';

/**
 * 型レベルのシグネチャ固定。
 *
 * `fn.length` は引数の数しか見ないため、引数の**並べ替え**や型変更（例:
 * `addKeyBindingWithTransactionData(signer, sdJwt, opts)` への変更）を素通しする。
 * 下の代入で各関数の引数順と型を検査するため、順序や型が
 * 変わると `bun run typecheck` が落ちる（テスト実行時ではなく型検査で検出する）。
 */
type Expect<Actual extends Expected, Expected> = Actual;
type _PinSignatures = [
  Expect<typeof sdk.extractTransactionData, (transactionData: readonly string[]) => unknown>,
  Expect<
    typeof sdk.addKeyBindingWithTransactionData,
    (sdJwt: string, signer: never, opts: never) => string
  >,
  Expect<typeof sdk.verifyTransactionDataHashes, (opts: never) => void>,
  Expect<typeof sdk.logPresentationEvent, (event: never) => unknown>,
  // `DashboardLog` を利用者が構築するには storage 契約型も公開されている必要がある。
  Expect<sdk.DashboardLogStorage, sdk.DashboardLogStorage>,
  // recordTransactionDataConsent の第 1 引数型 `DashboardLog` が公開型として解決できることの固定。
  // 非公開のままだと利用者は第 1 引数を組み立てられない。
  Expect<
    typeof sdk.recordTransactionDataConsent,
    (log: sdk.DashboardLog, i: never, s: never) => unknown
  >,
];

/**
 * Transaction Data を扱う公開関数と、その引数の数。
 *
 * `exportDashboardLog` / `importDashboardLog` は Wallet のメソッドとして公開する。
 */
const PUBLIC_FUNCTION_ARITIES: readonly (readonly [string, number])[] = [
  // extractTransactionData(transactionData)
  ['extractTransactionData', 1],
  // addKeyBindingWithTransactionData(sdJwt, signer, opts) — 提示 API
  ['addKeyBindingWithTransactionData', 3],
  // recordTransactionDataConsent(log, input, signer)
  ['recordTransactionDataConsent', 3],
  // verifyTransactionDataHashes({ requested, presentation }) — 単一 options オブジェクト
  ['verifyTransactionDataHashes', 1],
  // logPresentationEvent(event) — 単一 event オブジェクト
  ['logPresentationEvent', 1],
] as const;

describe('公開エクスポート: Transaction Data / Dashboard', () => {
  for (const [name, arity] of PUBLIC_FUNCTION_ARITIES) {
    test(`${name} が SDK エントリポイントから import できる`, () => {
      expect(typeof (sdk as unknown as Record<string, unknown>)[name]).toBe('function');
    });

    // 引数の数のみの検査。並べ替え・型変更は上の `_PinSignatures` が型検査で捕捉する。
    test(`${name} の引数の数が期待値と一致する`, () => {
      const fn = (sdk as unknown as Record<string, unknown>)[name] as (...a: unknown[]) => unknown;
      expect(fn.length).toBe(arity);
    });
  }

  // 公開 API の引数型がすべて公開されていること。`DashboardLog` は
  // `recordTransactionDataConsent` の第 1 引数型であり、値（クラス）として構築できる必要がある。
  test('DashboardLog が SDK エントリポイントから構築できる（引数型の到達可能性）', async () => {
    const log = new sdk.DashboardLog(new sdk.MemoryStorage());
    expect(await log.list()).toEqual([]);
  });

  // 10601 は「SSOT に定義があるのに送出箇所が 0 件」だったコードであり、関連 API 列が
  // 実在しない API（`updateDID` / `issueCredential`）を指していたことが根因だった。
  test('エラー 10601 の発生元として登録した関数がすべて実在する', () => {
    const origins = ['createDidWebVh', 'updateDidWebVh', 'assertNoSpecialCategoryOnChain'];
    for (const name of origins) {
      expect(typeof (sdk as unknown as Record<string, unknown>)[name]).toBe('function');
    }
  });

  // 仕様が実在しない関数を発生元として参照していた状態への回帰を防ぐ。
  test('エラー 10402 の発生元として登録した関数がすべて実在する', () => {
    const origins = [
      'addKeyBindingWithTransactionData',
      'verifyTransactionDataHashes',
      'computeTransactionDataHashesWithAlg',
    ];
    for (const name of origins) {
      expect(typeof (sdk as unknown as Record<string, unknown>)[name]).toBe('function');
    }
  });
});
