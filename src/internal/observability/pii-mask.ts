/**
 * ログ属性の**値**に対する PII マスキング。
 *
 * JWT / SD-JWT / COSE として認識した値から payload を取り除く処理
 * を担う。キー名による判定（`logger.ts`）では `token` や `assertion` のような無害な名前に
 * 載った資格情報を取りこぼすため、値そのものの構造からも検出する。
 *
 * 全体の方針:
 * - 構造だと確信できない文字列はマスクしない。誤検知で無関係なログを壊す方が実害が大きい。
 * - どの経路でも例外を投げない。マスキングは設定変更不可の強制ポリシーであり、ログ出力が
 *   アプリケーションを落とすことは許されない。
 */

import { concatBytes } from '@noble/hashes/utils.js';
import { base64nopad, base64urlnopad, hex } from '@scure/base';
import { CBOR_MAJOR, encodeCborHeader, readCborHeader } from '../cbor.js';
import { CBOR_BREAK, CBOR_MAX_NESTING_DEPTH, skipCborItem, skipCborItems } from './cbor-skip.js';

/** マスキング後の値（`[REDACTED]`）。キー名規則と値規則で同じ表記を使う。 */
export const REDACTED = '[REDACTED]';

/**
 * JWT / SD-JWT / COSE の値構造を検出し、header だけ残して残りを `[REDACTED]` にする。
 *
 * @param value ログ属性に載っていた文字列。
 * @returns マスク後の文字列。いずれの構造にも当たらなければ `value` をそのまま返す。
 */
export function maskStructuredValue(value: string): string {
  return maskSdJwt(value) ?? maskJwt(value) ?? maskCose(value) ?? value;
}

/** JWT compact serialization（`header.payload.signature`）の骨格。 */
const JWT_PATTERN = /^([A-Za-z0-9_-]+)\.([A-Za-z0-9_-]+)\.([A-Za-z0-9_-]+)$/;

/** base64url（padding なし）としてデコードできるか。 */
function isDecodableBase64Url(segment: string): boolean {
  try {
    base64urlnopad.decode(segment);
    return true;
  } catch {
    return false;
  }
}

/** base64url セグメントが JSON オブジェクトへほどけるか（JOSE header であることの裏付け）。 */
function decodesToJsonObject(segment: string): boolean {
  try {
    const text = new TextDecoder('utf-8', { fatal: true }).decode(base64urlnopad.decode(segment));
    const json: unknown = JSON.parse(text);
    return typeof json === 'object' && json !== null && !Array.isArray(json);
  } catch {
    return false;
  }
}

/**
 * JWT の header セグメントを取り出す。
 *
 * 3 セグメントすべてが base64url であることに加え、先頭が JSON オブジェクトへデコードできる
 * ことまで要求する。`1.20.3` や `sdk.internal.example` のような無関係な文字列を JWT と
 * 誤認して読めなくしないための歯止めである。
 *
 * @param candidate JWT かもしれない文字列。
 * @returns header セグメント。JWT でなければ `undefined`。
 */
function parseJwtHeader(candidate: string): string | undefined {
  const match = JWT_PATTERN.exec(candidate);
  if (match === null) {
    return undefined;
  }
  const [, header, payload, signature] = match;
  if (header === undefined || payload === undefined || signature === undefined) {
    return undefined;
  }
  if (!isDecodableBase64Url(payload) || !isDecodableBase64Url(signature)) {
    return undefined;
  }
  return decodesToJsonObject(header) ? header : undefined;
}

/** ヘッダに続けてペイロードを伏せたことを示す表記。 */
function redactedJwt(header: string): string {
  return `${header}.${REDACTED}`;
}

/** JWT 全体なら payload 以降（署名を含む）を落とす。 */
function maskJwt(value: string): string | undefined {
  const header = parseJwtHeader(value);
  return header === undefined ? undefined : redactedJwt(header);
}

/**
 * SD-JWT（`<issuer-jwt>~<disclosure>~…~<kb-jwt>?`）なら issuer JWT の header だけ残す。
 *
 * disclosure と KB-JWT は選択的開示の中身そのものなので、`~` 以降はまとめて落とす。
 * JWT より先に試すのは、`~` を含む文字列は `JWT_PATTERN` に当たらず素通りしてしまうため。
 */
function maskSdJwt(value: string): string | undefined {
  const tildeIndex = value.indexOf('~');
  if (tildeIndex === -1) {
    return undefined;
  }
  const header = parseJwtHeader(value.slice(0, tildeIndex));
  return header === undefined ? undefined : redactedJwt(header);
}

/** COSE の直列化表記。入力と同じ基数で返すために覚えておく。 */
type CoseEncoding = 'hex' | 'base64' | 'base64url';

/**
 * COSE 候補文字列の基数を推定する。
 *
 * 英数字だけの文字列は hex にも base64 にも読めるため hex を優先する（任意の取り決めだが、
 * 一貫させることで同じ入力が常に同じ結果になる）。判定できない字種は `undefined`。
 */
function detectCoseEncoding(value: string): CoseEncoding | undefined {
  if (value.length === 0) {
    return undefined;
  }
  if (/^[0-9a-fA-F]+$/.test(value)) {
    // 奇数長の hex はバイト列にならない。base64 として読み直さず fail-closed に倒す。
    return value.length % 2 === 0 ? 'hex' : undefined;
  }
  if (value.includes('-') || value.includes('_')) {
    return /^[A-Za-z0-9_-]+=*$/.test(value) ? 'base64url' : undefined;
  }
  return /^[A-Za-z0-9+/]+=*$/.test(value) ? 'base64' : undefined;
}

/** base64 系の `=` padding を除去する。 */
function stripBase64Padding(text: string): string {
  return text.replace(/=+$/, '');
}

/** 推定した基数でバイト列へ戻す。デコードできなければ `undefined`。 */
function decodeCoseBytes(value: string, encoding: CoseEncoding): Uint8Array | undefined {
  try {
    switch (encoding) {
      case 'hex':
        return hex.decode(value.toLowerCase());
      case 'base64':
        return base64nopad.decode(stripBase64Padding(value));
      case 'base64url':
        return base64urlnopad.decode(stripBase64Padding(value));
    }
  } catch {
    return undefined;
  }
}

/**
 * 差し替え後のバイト列を元の基数で書き戻す。
 *
 * 入力が padding 付きでも出力は常に nopad に揃える。ログの表記を一定にするための意図的な
 * 正規化であり、元の文字列との一致は要件ではない（復元できないことこそが目的）。
 */
function encodeCoseBytes(bytes: Uint8Array, encoding: CoseEncoding): string {
  switch (encoding) {
    case 'hex':
      return hex.encode(bytes);
    case 'base64':
      return base64nopad.encode(bytes);
    case 'base64url':
      return base64urlnopad.encode(bytes);
  }
}

/** COSE_* は常に 4 要素の CBOR 配列（RFC 9052 §2）。 */
const COSE_ELEMENT_COUNT = 4;

/** COSE の先頭 2 要素（protected header bstr / unprotected header map）はそのまま残す。 */
const COSE_HEADER_ELEMENT_COUNT = 2;

/**
 * 先頭の CBOR tag（major 6）を読み飛ばし、tag の直後（COSE 本体の先頭）の位置を返す。
 *
 * RFC 9052 §2 の COSE_Sign1 / COSE_Mac0 等は tag 付き（`d2 84 …` = tag 18、tag 17 など）で流通するのが
 * 標準で、`cose-sniff.ts` も tag 18 を許容している。tag が無ければ 0。tag 番号は限定せず、入れ子の
 * 上限は `CBOR_MAX_NESTING_DEPTH`。読み切れない tag は `undefined`。
 */
function skipLeadingTags(bytes: Uint8Array): number | undefined {
  let pos = 0;
  for (let depth = 0; depth <= CBOR_MAX_NESTING_DEPTH; depth += 1) {
    if (bytes[pos] === CBOR_INDEFINITE_ARRAY) {
      // `readCborHeader` は不定長 head を解析できないため、不定長配列はここで COSE 本体として返す。
      return pos;
    }
    const head = readCborHeader(bytes, pos);
    if (head === undefined) {
      return undefined;
    }
    if (head.majorType !== CBOR_MAJOR.tag) {
      return pos;
    }
    pos += head.headerLen;
  }
  return undefined;
}

/** 不定長配列の先頭バイト（`0x9f`）。 */
const CBOR_INDEFINITE_ARRAY = 0x9f;

/**
 * COSE 本体（4 要素配列）の先頭から、3 番目の要素（payload）の開始位置を求める。
 *
 * 配列は定長・不定長（`9f … ff`）のどちらも受理する。不定長は要素がちょうど 4 つで break に至る
 * ものだけを COSE とみなす。COSE の形でなければ `undefined`。
 */
function coseBodyPayloadStart(bytes: Uint8Array, bodyStart: number): number | undefined {
  if (bytes[bodyStart] === CBOR_INDEFINITE_ARRAY) {
    const payloadStart = skipCborItems(bytes, bodyStart + 1, 1, COSE_HEADER_ELEMENT_COUNT);
    const payloadEnd = payloadStart === undefined ? undefined : skipCborItem(bytes, payloadStart);
    const lastEnd = payloadEnd === undefined ? undefined : skipCborItem(bytes, payloadEnd);
    return lastEnd !== undefined && bytes[lastEnd] === CBOR_BREAK ? payloadStart : undefined;
  }
  const top = readCborHeader(bytes, bodyStart);
  if (top === undefined || top.majorType !== CBOR_MAJOR.array || top.value !== COSE_ELEMENT_COUNT) {
    return undefined;
  }
  return skipCborItems(bytes, bodyStart + top.headerLen, 1, COSE_HEADER_ELEMENT_COUNT);
}

/**
 * COSE メッセージの payload（3 番目の要素）を `[REDACTED]` の byte string へ差し替える。
 *
 * header 2 要素と 4 番目の要素（署名 / 受信者）はバイト列のまま残す。
 * 先頭の CBOR tag（tag 18 の COSE_Sign1・tag 17 の COSE_Mac0 など）は読み飛ばしてそのまま残し、
 * 配列・payload の byte string・header は定長・不定長のどちらも扱う。payload が不定長
 * byte string（`5f … ff`）でも、定長の `[REDACTED]` 1 つに差し替わる。
 * COSE の形をしていない場合、および payload が detached（CBOR `null`）で落とす中身が
 * そもそも無い場合は `undefined` を返し、元の値を素通しさせる。
 *
 * @param bytes COSE かもしれない CBOR バイト列。
 * @returns payload を差し替えたバイト列。COSE でなければ `undefined`。
 */
function redactCosePayload(bytes: Uint8Array): Uint8Array | undefined {
  const bodyStart = skipLeadingTags(bytes);
  const payloadStart = bodyStart === undefined ? undefined : coseBodyPayloadStart(bytes, bodyStart);
  const payloadHead = payloadStart === undefined ? undefined : bytes[payloadStart];
  // payload は byte string（定長 `0x40..0x5b` / 不定長 `0x5f`）でなければ COSE の payload ではない。
  if (payloadStart === undefined || payloadHead === undefined) {
    return undefined;
  }
  if (payloadHead >> 5 !== CBOR_MAJOR.byteString) {
    return undefined;
  }
  const payloadEnd = skipCborItem(bytes, payloadStart);
  if (payloadEnd === undefined) {
    return undefined;
  }
  const marker = new TextEncoder().encode(REDACTED);
  return concatBytes(
    bytes.slice(0, payloadStart),
    encodeCborHeader(CBOR_MAJOR.byteString, marker.length),
    marker,
    bytes.slice(payloadEnd),
  );
}

/**
 * hex / base64 / base64url で載った COSE なら payload を `[REDACTED]` に差し替える。
 *
 * COSE の形（4 要素配列）と判定できた後に解析が例外（`skipCborItem` の入れ子深さ超過など）で
 * 失敗した場合は、payload を落とせないまま素通しさせず値全体を `[REDACTED]` にする（fail-closed）。
 * マスキングは例外を外へ出さず、かつ漏らさない。
 * COSE ではないと判定できた入力（`undefined`）だけが素通しになる。
 */
function maskCose(value: string): string | undefined {
  const encoding = detectCoseEncoding(value);
  if (encoding === undefined) {
    return undefined;
  }
  const bytes = decodeCoseBytes(value, encoding);
  if (bytes === undefined) {
    return undefined;
  }
  try {
    const redacted = redactCosePayload(bytes);
    return redacted === undefined ? undefined : encodeCoseBytes(redacted, encoding);
  } catch {
    return REDACTED;
  }
}
