/**
 * did:webvh の `domain` / path セグメント → HTTPS URL 変換。
 *
 * spec: DIF didwebvh v1.0「Method-Specific Identifier」（ABNF・domain / path の検証）と
 * 「The DID to HTTPS Transformation」。
 *
 * - `domain`: `label 1*("." label)`（label = `ALPHA / DIGIT / "-" / pct-encoded`）＋任意の `%3A<port>`
 *   （`%3A` は大文字のみ・ポートは先頭ゼロなしの 1〜65535。ABNF より厳密にして、同じ場所を指す別表記の DID を作らない）。パーセントエンコードは**ちょうど 1 回**デコードし、
 *   Unicode 正規化（NFC）と IDNA（WHATWG URL の UTS46、punycode）を適用して、IPv4 / IPv6（非正規表記を含む）を拒否する。
 * - path セグメント: `1*idchar`。1 回デコードした値が `.` / `..` / 空でなく、`/` `\\` U+0000 を含まず、前後が空白でないこと。
 *   URL へは RFC 3986 に従って大文字 16 進で再エンコードする。
 *
 * DID Core の idchar に非 ASCII は無いため、生の Unicode（仕様の例 `jp納豆.例.jp:用户`）は ABNF 違反として拒否する
 * （DID 文字列は `jp%E7%B4%8D...` の形で表す）。
 *
 * 例外メッセージ・`context` に domain / path を含めない。
 */

import { ErrorCodes, VericertsError } from '../../errors.js';

/** 空でない `ALPHA / DIGIT / "-" / pct-encoded` の並び（`.` 区切りで 2 ラベル以上）。 */
const ENCODED_DOMAIN_NAME =
  /^(?:[A-Za-z0-9-]|%[0-9A-Fa-f]{2})+(?:\.(?:[A-Za-z0-9-]|%[0-9A-Fa-f]{2})+)+$/;

/** `idchar`（DID Core）の並び。 */
const PATH_SEGMENT = /^(?:[A-Za-z0-9._-]|%[0-9A-Fa-f]{2})+$/;

/** domain 全体の中の `%3A`。 */
const PORT_SEPARATOR = /%3A/g;

/** 末尾の `%3A<port>`（先頭ゼロなしの 1〜5 桁。範囲は別に検査する）。 */
const TRAILING_PORT = /^(.*)%3A([1-9][0-9]{0,4})$/;

/** デコード後の host に現れてはならない文字（URL の構造を変える・空白・制御文字）。 */
// biome-ignore lint/suspicious/noControlCharactersInRegex: 制御文字の拒否が目的
const FORBIDDEN_HOST_CHARS = /[\s\u0000-\u001f\u007f/?#@:[\]\\%]/;

/** 1 ラベルの最大長（IDNA 処理後、オクテット）と、ドメイン名全体の最大長（RFC 1035）。 */
const MAX_LABEL_OCTETS = 63;
const MAX_DOMAIN_OCTETS = 253;

/** RFC 1123 のラベル（英数字とハイフン。先頭・末尾はハイフン不可）。 */
const LDH_LABEL = /^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/;

/** 小数点区切りの IPv4 リテラル（URL パーサの正規化後）。 */
const IPV4_LITERAL = /^\d+\.\d+\.\d+\.\d+$/;

function invalidDid(): VericertsError {
  return new VericertsError(ErrorCodes.INVALID_DID);
}

/** `%XX` を 1 回だけデコードする（UTF-8 として不正なら拒否）。 */
function decodeOnce(text: string): string {
  try {
    return decodeURIComponent(text);
  } catch {
    throw invalidDid();
  }
}

/** 解決先の host（IDNA 済み ASCII）と任意のポート。 */
export interface WebVhHost {
  readonly host: string;
  readonly port: number | undefined;
}

/**
 * DID の domain 成分（`host` / `host%3Aport`、パーセントエンコード済み）を、取得先の host / port へ変換する。
 *
 * @throws ABNF 違反・ポート範囲外・デコード後の値が不正・IP アドレス・IDNA 失敗・ラベル / 全体長超過の場合（VericertsError、code `2001`）。
 */
export function resolveWebVhHost(domain: string): WebVhHost {
  // 区切りは大文字 `%3A` のみ。ABNF は小文字 `%3a` も許すが、仕様は producer に大文字を求めており、同じ場所を指す別表記の DID
  // 文字列（DID は文字列比較）を成立させない。ポートの先頭ゼロも同じ理由で拒否する。
  if (domain.includes('%3a')) {
    throw invalidDid();
  }
  const separators = domain.match(PORT_SEPARATOR)?.length ?? 0;
  let name = domain;
  let port: number | undefined;
  if (separators > 0) {
    const split = separators === 1 ? TRAILING_PORT.exec(domain) : null;
    if (split === null) {
      throw invalidDid();
    }
    name = split[1] as string;
    port = Number(split[2]);
    if (port < 1 || port > 65_535) {
      throw invalidDid();
    }
  }
  if (!ENCODED_DOMAIN_NAME.test(name)) {
    throw invalidDid();
  }
  const decoded = decodeOnce(name).normalize('NFC');
  if (FORBIDDEN_HOST_CHARS.test(decoded)) {
    throw invalidDid();
  }
  let hostname: string;
  try {
    hostname = new URL(`https://${decoded}/`).hostname;
  } catch {
    throw invalidDid();
  }
  if (
    hostname.length === 0 ||
    hostname.length > MAX_DOMAIN_OCTETS ||
    IPV4_LITERAL.test(hostname) ||
    hostname.startsWith('[') ||
    !hostname
      .split('.')
      .every(
        (label) => label.length > 0 && label.length <= MAX_LABEL_OCTETS && LDH_LABEL.test(label),
      )
  ) {
    throw invalidDid();
  }
  return { host: hostname, port };
}

/**
 * DID の path セグメント（パーセントエンコード済み）を、URL の path セグメントへ変換する。
 *
 * @throws ABNF 違反・デコード後の値が不正（空 / `.` / `..` / `/` `\\` U+0000 を含む / 前後が空白）の場合（VericertsError、code `2001`）。
 */
export function encodeWebVhPathSegment(segment: string): string {
  if (!PATH_SEGMENT.test(segment)) {
    throw invalidDid();
  }
  const decoded = decodeOnce(segment);
  if (
    decoded.length === 0 ||
    decoded === '.' ||
    decoded === '..' ||
    decoded.includes('/') ||
    decoded.includes('\\') ||
    decoded.includes('\u0000') ||
    decoded.trim() !== decoded
  ) {
    throw invalidDid();
  }
  return encodeURIComponent(decoded);
}
