import { describe, expect, test } from 'bun:test';
import { readFileSync } from 'node:fs';
import { ErrorCodes } from '../errors.js';

// 公開正本（schemas/error-codes.json）から見た「実装に反映されていないコード」を
// 検査する。隣接する errors.schema-consistency.test.ts は ErrorCodes → SSOT の一方向
// （ErrorCodes の各定数が SSOT の名前と一致するか）と、個別コードの廃番決定の固定を担う。
// 本ファイルはその逆方向（SSOT → ErrorCodes）だけを対象にする。
const ERROR_CODES_SCHEMA = JSON.parse(
  readFileSync(new URL('../../../schemas/error-codes.json', import.meta.url), 'utf8'),
) as {
  codes: {
    code: string;
    name: string;
    category: string;
    description: string;
    related_apis: string[];
  }[];
};

describe('ErrorCodes → SSOT の関連 API ドリフト検知', () => {
  // 上の describe は「SSOT に関連 API 付きで載っているのに `ErrorCodes` に無い」方向しか見ない。
  // その裏返し —— **`ErrorCodes` に在り実装が送出しているのに、SSOT の `related_apis` が空**
  // （関連 API 欄を `（未実装）` などバッククォート無しの表記に書き換えた結果、抽出結果が空配列に
  // なった）—— は素通りする。どちらか片方だけの検知では「片側を空にして黙らせる」逃げ道が残る。
  //
  // `related_apis` が空でも正当なコードはある: `aa` カテゴリの 7xxx はコントラクト側の revert を
  // SDK と名前で共有しているだけで TypeScript からは送出しない（CONTRACT_SIDE_CODES）。
  //
  // 対して UNRESOLVED_EMPTY_RELATED_APIS は**未解消のドリフトの棚卸し**であり、増やしてはならない。
  // 公開正本（schemas/error-codes.json）を直したら、ここから消すこと。
  // 2026-09-20 時点で**空**である。実装が現に送出している
  // `1003`（`keymanager/ecdsa` / `keymanager/ed25519` / `identity/ipid/gateway.ts` ほか）と
  // `3081`（`auth/oid4vci/oid4vci.ts` の `generateProofJWT`）の関連 API を復活させた。
  const CONTRACT_SIDE_CODES: readonly string[] = [
    '7010',
    '7020',
    '7050',
    '7051',
    '7101',
    '7102',
    '7103',
    '7201',
    '7202',
    '7203',
  ];
  const UNRESOLVED_EMPTY_RELATED_APIS: readonly string[] = [];

  // 「未実装 / 予約」と注記したコードは、定数だけ先に置いて実装が送出しないので関連 API も空が正しい
  // 番号を予約するたびに下の一覧へ足すのは棚卸しの意味を薄めるため、注記で除く。
  const isReserved = (description: string) => description.includes('未実装 / 予約');

  test('ErrorCodes に在るのに SSOT の関連 API が空のコードは既知の一覧と完全一致する', () => {
    const errorCodeValues = new Set<string>(Object.values<string>(ErrorCodes));
    const emptyRelatedApis = ERROR_CODES_SCHEMA.codes
      .filter(
        (c) =>
          errorCodeValues.has(c.code) && c.related_apis.length === 0 && !isReserved(c.description),
      )
      .map((c) => c.code)
      .sort();

    // 差分が出た場合: 増えていれば新しいドリフト（関連 API 欄を空にしたが実装は送出したまま）、
    // 減っていれば解消済みなので上の一覧から該当要素を削除する。
    expect(emptyRelatedApis).toEqual(
      [...CONTRACT_SIDE_CODES, ...UNRESOLVED_EMPTY_RELATED_APIS].sort(),
    );
  });
});

describe('SSOT → ErrorCodes の逆方向ドリフト検知', () => {
  // errors.schema-consistency.test.ts の「定数名整合」は ErrorCodes → SSOT の一方向しか見ないため、
  // 「SSOT には関連 API 付きで載っているのに ErrorCodes に無い（= どの API からも送出できない）」
  // ドリフトを検知できない。ここでは許可リスト方式でその集合をスナップショットし、新規発生を検知する。
  //
  // 判定は `related_apis.length > 0` で絞るため、関連 API 欄のバッククォートを付け忘れたコードは
  // 空配列になって対象外になる。`ErrorCodes` に在るものは上の describe が受け止めるので、穴が残る
  // のは「`ErrorCodes` に無く、かつバッククォートを落とした」= 実装が送出しないコードに限られる。
  //
  // KNOWN_UNTHROWN_WITH_RELATED_APIS は「既知の未解消ドリフトの棚卸し」であり、増やしてはならない。
  // 解消した（Deprecated 化して related_apis を空にした、または ErrorCodes へ追加して実際に送出する
  // ようにした）場合は、該当要素をこのリストから削除すること。
  // 2026-09-19 時点で**空**である。`ErrorCodes` に無いのに関連 API を
  // 持っていた 16 コードを「（未実装 / 予約）」注記 + バッククォート無しの `X（未実装）` 表記へ
  // 揃えた（`4062` は `4030` との重複により Deprecated 化）結果、未解消ドリフトは 0 件になった。
  // 空のまま維持すること — 要素が増えるのは「SSOT に関連 API を書いたが実装が送出しない」の
  // 新規発生であり、そのときは SSOT 側を直す（この一覧に足して見逃さない）。
  const KNOWN_UNTHROWN_WITH_RELATED_APIS: readonly string[] = [];

  test('ErrorCodes に無いのに関連 API を持つ SSOT コードは既知の一覧と完全一致する', () => {
    const errorCodeValues = new Set<string>(Object.values<string>(ErrorCodes));
    const unthrownWithRelatedApis = ERROR_CODES_SCHEMA.codes
      .filter((c) => !errorCodeValues.has(c.code) && c.related_apis.length > 0)
      .map((c) => c.code)
      .sort();

    // 差分が出た場合: 増えていれば新しいドリフト（SSOT に関連 API を書いたが実装が送出しない）、
    // 減っていれば解消済みなので上の許可リストから該当要素を削除する。
    expect(unthrownWithRelatedApis).toEqual([...KNOWN_UNTHROWN_WITH_RELATED_APIS].sort());
  });

  // 回帰テスト: 上の検査は `ErrorCodes` に**無い**コードだけを見るため、定数はあるのに
  // 実装が送出しない「未実装 / 予約」コードが素通りしていた。SSOT を見た利用者が
  // `catch (e) { if (e.code === 1012) … }` の分岐を書いても、その分岐には到達しない
  // （実際は status 戻り値や別コードで返る）。
  //
  // 予約であることは description に「未実装 / 予約」と書く規約なので、そう書いたコードは
  // 関連 API 欄をバッククォート無し（= `related_apis` が空）にすることを固定する。
  test('「未実装 / 予約」と注記したコードは関連 API を持たない', () => {
    const reservedWithRelatedApis = ERROR_CODES_SCHEMA.codes
      .filter((c) => c.description.includes('未実装 / 予約') && c.related_apis.length > 0)
      .map((c) => `${c.code} ${c.name}: ${c.related_apis.join(', ')}`)
      .sort();

    // 差分が出た場合: SSOT の関連 API 欄からバッククォートを外す（`X（本コードは未送出）`）か、
    // 実装が実際に送出するようにして「未実装 / 予約」の注記を外す。
    expect(reservedWithRelatedApis).toEqual([]);
  });
});

describe('(Deprecated) 印の付いたコードの棚卸し', () => {
  // errors.schema-consistency.test.ts の `DEPRECATED_CODES` は廃番理由を文書として残したいコード
  // だけを持つ（現在 3 件）。表に載っていない `(Deprecated)` コードは `ErrorCodes` へ戻しても
  // 既存の検査を素通りする（定数名の照合は名前だけを見るうえ、SSOT は番号を予約として残す）。
  const deprecated = ERROR_CODES_SCHEMA.codes.filter((c) => c.description.includes('(Deprecated)'));
  const deprecatedCodes = deprecated.map((c) => c.code);
  const errorCodeValues = new Set<string>(Object.values<string>(ErrorCodes));

  // 現在 `(Deprecated)` 印を持つコードの全件。**下限ではなく完全一致で固定する。**
  // `toBeGreaterThan(3)` のような緩い下限だと、「廃番行の黙った
  // 削除」が 8 件起きてもこの検査を素通りしてしまう（実数は 12 件なので下限 3 に余裕があり過ぎた）。
  // 廃番を増やす / 減らすときは `schemas/error-codes.json`を
  // 直したうえで、この一覧も同じコミットで更新すること。
  const KNOWN_DEPRECATED_CODES: readonly string[] = [
    '1006',
    '1007',
    '2004',
    '2011',
    '2012',
    '2013',
    '2014',
    '2015',
    '2020',
    '2040',
    '3005',
    '4062',
    '5020',
    '5021',
    '5030',
    '10304',
    '10307',
  ];

  test('印の付いたコードが既知の一覧と完全一致する = 黙った増減が無い', () => {
    expect([...deprecatedCodes].sort()).toEqual([...KNOWN_DEPRECATED_CODES].sort());
  });

  test.each(deprecatedCodes)('%s は ErrorCodes に持たず関連 API も空である', (code) => {
    expect(errorCodeValues.has(code)).toBe(false);
    expect(deprecated.find((c) => c.code === code)?.related_apis).toEqual([]);
  });
});
