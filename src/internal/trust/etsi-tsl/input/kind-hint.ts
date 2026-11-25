/**
 * `loadTrustedList` の `options.kind` 検証（trust/etsi-tsl）。
 *
 * `etsi-tsl.ts` から切り出したのは Linterly の 1 ファイル 300 行上限に収めるためで、責務自体は
 * 単純（ユニオン外の値の検出 + フォールバック）だが独立してテストしやすい単位でもある
 * （`now-seconds.ts` と同じ切り出し方針）。
 *
 * `options.kind` は `TrustedListKind`（`'lotl' | 'tsl' | 'auto'`）として型付けされているが、呼び
 * 出し側が型を無視して任意の文字列を注入できる（`options` は外部入力に由来し得るため）。未検証の
 * まま下流へ流すと以下が起こる:
 *
 * 1. `etsi-tsl.ts` の `extractResult` は `kind === 'lotl'` かどうかで分岐するだけなので、`'lotl'`
 *    に一致しない任意の値（例: 誤字 `'tls'`）が無言のまま TSL 解析経路（else 節）に落ちる。実際の
 *    XML が LOTL であれば `extractQtspCertificates` が空配列を返すだけで済むが、意図しない解析経路を
 *    通ること自体が「挙動が保証されていない」状態である。
 * 2. `storeTrustedListCache` が書き込む `TrustedListCache.type`（本来 `'lotl' | 'tsl'`）にも不正な
 *    値がそのまま永続化され、以降の `resolveWithFailOpen` の種別一致判定（`cached.type !== kindHint`）
 *    が汚染値同士の比較になる。
 *
 * 不正値は例外（fail-closed）ではなく自動判定（`auto`）へフォールバックする。`kind` は元々省略可能で
 * `auto` が既定のため、ユニオン外の値も「未指定」と同等に扱うのが一貫している（`now-seconds.ts` と
 * 同じ「型不正値は既定へフォールバック」の規律）。
 */

import { ownProperty } from '../../../prototype-safety/own-property.js';
import type { TrustedListKind } from '../etsi-tsl.js';

/** `options.kind`（`TrustedListKind`）として許可された値。 */
const VALID_TRUSTED_LIST_KINDS: ReadonlySet<TrustedListKind> = new Set(['lotl', 'tsl', 'auto']);

/** `value` がユニオン内の値（`TrustedListKind`）かを判定する。 */
function isTrustedListKind(value: unknown): value is TrustedListKind {
  return typeof value === 'string' && VALID_TRUSTED_LIST_KINDS.has(value as TrustedListKind);
}

/**
 * `options.kind` を検証する。`'lotl' | 'tsl' | 'auto'` 以外の値（型を無視した不正な注入）は
 * 自動判定（`auto`）へフォールバックする。
 *
 * 引数は `unknown` で受ける（`options.kind` の own プロパティ値を未検証のまま渡してよい）。
 * 呼び出し側が型キャストで検証を済ませたことにしてしまうと、ユニオン外の値をそのまま
 * `TrustedListKind` として扱う経路が復活するため。
 *
 * @param kind `options.kind` の own プロパティ値（`ownProperty` で読んだもの）。
 * @returns 検証済みの種別。未指定・ユニオン外の値は `'auto'`。
 */
export function validKindHint(kind: unknown): TrustedListKind {
  return isTrustedListKind(kind) ? kind : 'auto';
}

/**
 * FO-5 で再利用してよいキャッシュ済みエントリの `type` / `xml` を返す。使えなければ `undefined`（対象外 = fail-closed）。
 *
 * `type` / `xml` は own 限定で読み（`TrustedListCache` を手組みで格納した呼び出し側が省略したキーを、
 * `Object.prototype` の汚染値で補って検証・信頼アンカー抽出に回さない）、種別を明示した呼び出し（`kindHint` が `'auto'` 以外）は
 * エントリの実際の種別との一致を、`explicitInvalidKind`（ユニオン外の明示値）は常に不一致を要求する。
 */
export function acceptedCachedEntry(
  cached: object,
  kindHint: TrustedListKind,
  explicitInvalidKind: boolean,
): { readonly type: 'lotl' | 'tsl'; readonly xml: string } | undefined {
  const type = ownProperty<unknown>(cached, 'type');
  const xml = ownProperty<unknown>(cached, 'xml');
  if (typeof xml !== 'string' || (type !== 'tsl' && type !== 'lotl')) {
    return undefined;
  }
  if (explicitInvalidKind || (kindHint !== 'auto' && type !== kindHint)) {
    return undefined;
  }
  return { type, xml };
}
