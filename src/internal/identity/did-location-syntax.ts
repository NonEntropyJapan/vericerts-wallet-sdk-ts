/**
 * did:web / did:webvh の `domain` / `path` セグメントの文字種検証（共通ヘルパ）。
 *
 * メソッド固有 ID を `:` → `/` で URL に組み立てる解決系（`didWebToUrl` / `webVhLogUrl`）が、
 * `? # @ \` や `.` / `..`（`%2e` 含む）を URL の構造として解釈させ、DID 文字列が示す場所と
 * 別の場所を取得してしまうのを防ぐ。生成系（`assertDidLocation`）と同じ
 * 定数を共有し、「生成側が拒否する DID を解決側が受理する」非対称を作らない。
 *
 * 許可するのは次だけで、`%XX` は host のポート区切り `%3A` を除いて拒否する
 * （`%2e` / `%2f` / `%5c` 等でパス構造を偽装させない）。
 * - host: DNS ラベルを `.` で連結した名前（IDN は punycode 済み）＋任意の `%3A<port>`（`%3A` は大文字のみ、port は 1〜65535）
 * - path の各セグメント: `[A-Za-z0-9._~-]+`（`.` / `..` は不可）
 *
 * 例外メッセージ・`context` に DID・domain・path を含めない。
 */

import { ErrorCodes, VericertsError } from '../errors.js';

/** ポート番号 1〜65535（先頭ゼロ・`0`・65536 以上は不可）。 */
const PORT_PATTERN = '[1-9]\\d{0,3}|[1-5]\\d{4}|6[0-4]\\d{3}|65[0-4]\\d{2}|655[0-2]\\d|6553[0-5]';

/**
 * ホスト部（DNS ラベルを `.` で連結。IDN は punycode 済みであること）と任意のポート（`%3A` 区切り）。
 *
 * 区切りは**大文字 `%3A` のみ**（小文字 `%3a` は不可）。許すと同じ場所を指す別表記の DID 文字列が成立し、
 * DID は文字列比較のため別 DID になる。
 */
export const DOMAIN_PATTERN = new RegExp(
  `^((?:[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?\\.)*[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?)(?:%3A(${PORT_PATTERN}))?$`,
);

/** path の 1 セグメント（unreserved 文字のみ。`.` / `..` は {@link isValidPathSegment} が別途拒否）。 */
const PATH_SEGMENT_PATTERN = /^[A-Za-z0-9._~-]+$/;

/** path の 1 セグメントが許可する文字種のみで、かつドットセグメント（`.` / `..`）でないか。 */
export function isValidPathSegment(segment: string): boolean {
  return PATH_SEGMENT_PATTERN.test(segment) && segment !== '.' && segment !== '..';
}

/**
 * `%3A` デコード**前**の `domain` と path セグメントが許可する文字種だけかを検証する。
 *
 * @throws 不適合の場合（VericertsError、code `2001`）。
 */
export function assertDidLocationSyntax(domain: string, pathSegments: readonly string[]): void {
  if (!DOMAIN_PATTERN.test(domain) || !pathSegments.every(isValidPathSegment)) {
    throw new VericertsError(ErrorCodes.INVALID_DID);
  }
}
