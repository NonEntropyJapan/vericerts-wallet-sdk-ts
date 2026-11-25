/**
 * 「値が非空の文字列か」を判定する横断ユーティリティ。
 *
 * 同等のヘルパが SDK 内の 10 ファイルに 10 件の名前付き定義として重複し、さらに **15 ファイルの
 * 18 箇所**（`oid4vci/par/response.ts` / `oid4vci-token-http.ts` / `eudi/pseudonym/siop.ts` が
 * 各 2 箇所、`oid4vci-offer.ts` / `credential/chain/edges.ts` /
 * `credential/evidence-tou/evidence.ts` / `credential/refresh/refresh-endpoint.ts` /
 * `delegation/delegation-grant-verify.ts` / `delegation/policy.ts` / `eudi/wua/wua.ts` /
 * `gdpr/well-known-discovery.ts` / `identity/webvh/codec.ts` / `keymanager/kms/provider.ts` /
 * `trust/arf/catalogue.ts` / `trust/federation/statement/statement.ts` が各 1 箇所）は、共有ヘルパを使わずに
 * 同じ判定をローカルへ書いていた。大半は `filter` / `every` / 三項演算子や `if` ガードの中に
 * 直接置いたインライン式で、残りはそのファイル限りの小さな名前付き関数の本体である
 * （`oid4vci/par/response.ts` / `oid4vci-token-http.ts` の `toNonEmptyString`、`eudi/wua/wua.ts` の
 * `stringClaim`、`gdpr/well-known-discovery.ts` の `optionalString` の 4 箇所）。しかもシグネチャは
 * 5 種類に分かれていた: `(value: unknown): value is string` 6 件 /
 * `(value: string): boolean` 1 件 / `(value: string | undefined): value is string` 1 件 /
 * `(value: unknown): boolean` 1 件 / `(value: unknown): string | undefined` 1 件。
 * 呼び出し側と SD-JWT 層で、空文字の扱いを揃える。
 *
 * 受け取る型は**広い側の `unknown`** に統一する。`string | undefined` や `string` で受けると
 * 型上は到達不能な防御になり、JSDoc が意図する「型の無い JS 呼び出し側から来る非文字列も
 * 『未指定』として弾く」挙動と型が食い違う。値そのものを返していた
 * `(value: unknown): string | undefined` 版（旧 `credential/issuer-key-revocation.ts` の
 * `asNonEmptyString`）は、型ガードと三項演算子の組み合わせ
 * （`isNonEmptyString(v) ? v : undefined`）として呼び出し側に残す。
 *
 * 判定の意味論は 2 つあり（旧定義の内訳は `length` ベース 7 件 / `trim` ベース 3 件）、
 * 名前で区別する。
 *
 * - {@link isNonEmptyString}: `length > 0`。空文字だけを弾く。オプションの期待値
 *   （`audience` / `nonce` 等）と外部 JSON の必須文字列フィールドはこちら。
 * - {@link isNonBlankString}: `trim().length > 0`。空白のみの文字列も弾く。Credential Manifest の
 *   識別子・表示名のように「空白だけの値を有意な値として採用してはならない」入力はこちら。
 */

/**
 * 値が長さ 1 以上の文字列か。
 *
 * @param value 判定対象（型の無い呼び出し側から来る任意の値）。
 * @returns 文字列かつ空文字でなければ `true`。
 */
export function isNonEmptyString(value: unknown): value is string {
  return typeof value === 'string' && value.length > 0;
}

/**
 * 値が空白のみでない文字列か（{@link isNonEmptyString} より厳しい）。
 *
 * `String.prototype.trim` は U+00A0（NBSP）や U+3000（全角スペース）も空白として除去するため、
 * 非 ASCII 空白のみで構成された文字列も弾く。
 *
 * @param value 判定対象（型の無い呼び出し側から来る任意の値）。
 * @returns 文字列かつ前後の空白を除いて 1 文字以上残れば `true`。
 */
export function isNonBlankString(value: unknown): value is string {
  return isNonEmptyString(value) && value.trim().length > 0;
}

/** 数値文字列・有限数のみを number に正規化する。範囲外・非数は `null`。 */
export function toFiniteNumber(value: unknown): number | null {
  const numeric = typeof value === 'number' ? value : isNonBlankString(value) ? Number(value) : NaN;
  return Number.isFinite(numeric) ? numeric : null;
}
