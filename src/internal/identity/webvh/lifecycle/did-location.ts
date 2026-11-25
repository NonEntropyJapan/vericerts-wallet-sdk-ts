/**
 * did:webvh の生成時入力（`domain` / `path`）を resolver の解釈と一致させる共有ガード。
 *
 * SCID が `domain` / `path` を含むため、解決不能な DID や意図と別の場所を指す DID を生成すると、
 * 公開後に直せず DID ごと作り直しになる。
 * 生成予定の DID を実際に `parseWebVh` → `webVhLogUrl` に通し、意図した host / port / path の
 * URL に往復することを確認する。
 *
 * 例外メッセージ・`context` に domain / path を含めない。
 */

import { ErrorCodes, VericertsError } from '../../../errors.js';
import { DID_WEBVH_PREFIX, parseWebVh, webVhLogUrl } from '../did-url.js';

/** 往復検証にだけ使う SCID の代役（実 SCID と同じ 46 文字の base58btc）。 */
const PROBE_SCID = `Qm${'P'.repeat(44)}`;

/**
 * 生成する DID の `domain` / `path` が、resolver の URL 解釈と一致することを検証する。
 *
 * - `domain`: DID 文字列上の表記（パーセントエンコード済みの ASCII）。`host` または `host%3Aport`。
 *   ポート区切りは大文字 `%3A` のみ（仕様は producer に大文字を要求する。小文字を許すと同じ場所を指す別表記の
 *   DID が成立し、DID は文字列比較のため別 DID になる）。国際化ドメイン名は UTF-8 をパーセントエンコードして渡す。
 * - `path`: `:` 区切りの各セグメント（パーセントエンコード済み）。未指定または空文字は「path なし」
 *   （`/.well-known/did.jsonl`）。
 * - いずれも `parseWebVh` が受理する（ABNF・デコード後の規則・IP ホスト拒否）こと。
 *
 * @param domain 呼び出し側指定の domain（型は保証されない）。
 * @param path 呼び出し側指定の path（型は保証されない）。
 * @throws 構文不正、または resolver が DID と別の場所へ解決する場合（VericertsError、code `2001`）。
 */
export function assertDidLocation(domain: unknown, path: unknown): asserts domain is string {
  if (
    typeof domain !== 'string' ||
    (path !== undefined && typeof path !== 'string') ||
    /%3a/.test(domain)
  ) {
    throw new VericertsError(ErrorCodes.INVALID_DID);
  }
  const segments = path === undefined || path.length === 0 ? [] : path.split(':');
  const probeDid = `${DID_WEBVH_PREFIX}${PROBE_SCID}:${domain}${segments.map((s) => `:${s}`).join('')}`;
  const parsed = parseWebVh(probeDid);
  // 往復: DID 文字列の区切りを変えるような値（`:` を含む path など）は、分割後の構造が入力と一致しない。
  if (parsed.domain !== domain || parsed.pathSegments.join(':') !== segments.join(':')) {
    throw new VericertsError(ErrorCodes.INVALID_DID);
  }
  const url = new URL(webVhLogUrl(parsed));
  if (url.username !== '' || url.password !== '' || url.search !== '' || url.hash !== '') {
    throw new VericertsError(ErrorCodes.INVALID_DID);
  }
}
