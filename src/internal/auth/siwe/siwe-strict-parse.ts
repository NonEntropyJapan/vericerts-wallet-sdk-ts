/**
 * EIP-4361（SIWE）メッセージの厳密な行単位パーサ。SDK の `parseSiweMessage` と拡張で
 * 同じ依存ゼロの実装を使う。
 *
 * 従来 SDK は viem の `parseSiweMessage`（先頭アンカー無しの正規表現と `split('Resources:')`）と
 * 日時用の正規表現を使っており、(a) statement に `URI: ` を並べるだけで二次時間のバックトラックに入る、
 * (b) statement / URI に `Resources:` を入れるだけで署名対象の Resources ブロックが `[]` に隠れる、
 * (c) `scheme` を捨てる、という欠陥があった。本モジュールは正規表現を行内の単純な文字クラス検査に限り
 * （バックトラックなし）、メッセージを `\n` で分割して ABNF 順に 1 行ずつ消費する状態機械で、
 * 全体を O(メッセージ長) で処理する。ABNF に合わない入力は例外ではなく `null`（呼び出し側が fail-closed に
 * 変換する）。
 *
 * 行位置で値を決めるため、statement / URI / Request ID に予約語が入っても署名対象の別ブロックを
 * 見落とさない。加えて、寛容な下流パーサ（viem 等の最初一致 `split('Resources:')`）が解釈を食い違わせる
 * 余地を残さないよう、`Resources:` は本物の Resources 行 1 か所以外に一切現れてはならない。
 */

/** 受理するメッセージ長の上限（UTF-16 code unit）。未認証入力に対する計算量の上限。 */
export const MAX_SIWE_MESSAGE_LENGTH = 16 * 1024;
/** 受理する `Resources:` 項目数の上限。 */
export const MAX_SIWE_RESOURCES = 64;

/** 厳密パースの結果（検証前の生値。日時は文字列のまま、address は形式のみ確認済み）。 */
export interface StrictSiweFields {
  /** `scheme://` の scheme 部（無ければ undefined。`domain` には含めない）。 */
  readonly scheme?: string;
  readonly domain: string;
  readonly address: string;
  readonly statement?: string;
  readonly uri: string;
  readonly version: string;
  readonly chainId: number;
  readonly nonce: string;
  readonly issuedAt: string;
  readonly expirationTime?: string;
  readonly notBefore?: string;
  readonly requestId?: string;
  readonly resources?: readonly string[];
}

const HEADER_SUFFIX = ' wants you to sign in with your Ethereum account:';
const SCHEME_SEPARATOR = '://';
const RESOURCES_LABEL = 'Resources:';
const RESOURCE_ITEM_PREFIX = '- ';
/** 改行（`\n`）以外の制御文字・Unicode 行区切り。これらを含む入力は行分割の解釈がパーサ間でずれる。 */
// biome-ignore lint/suspicious/noControlCharactersInRegex: 制御文字の検出が目的
const FORBIDDEN_CHARS = /[\u0000-\u0009\u000b-\u001f\u007f\u2028\u2029]/;
/** RFC 3986 scheme（ALPHA *( ALPHA / DIGIT / "+" / "-" / "." )）。 */
const SCHEME_PATTERN = /^[A-Za-z][A-Za-z0-9+.-]*$/;
/** RFC 3986 authority に現れうる文字のみ（空白・`/`・`?`・`#` を含まない）。 */
const AUTHORITY_PATTERN = /^[A-Za-z0-9\-._~%!$&'()*+,;=:@[\]]+$/;
const ADDRESS_PATTERN = /^0x[0-9a-fA-F]{40}$/;
const NONCE_PATTERN = /^[A-Za-z0-9]+$/;
const CHAIN_ID_PATTERN = /^[0-9]{1,15}$/;

/** ヘッダ後に ABNF 順で並ぶ単一値フィールドのラベル（`Resources:` は別処理）。 */
const FIELD_LABELS = [
  'URI: ',
  'Version: ',
  'Chain ID: ',
  'Nonce: ',
  'Issued At: ',
  'Expiration Time: ',
  'Not Before: ',
  'Request ID: ',
] as const;
/** 先頭からこの個数までは必須（URI, Version, Chain ID, Nonce, Issued At）。 */
const REQUIRED_FIELD_COUNT = 5;

/** `scheme://authority` 形式のヘッダ先頭部を `{ scheme?, domain }` に分解する。不正は null。 */
function parseOrigin(origin: string): { scheme?: string; domain: string } | null {
  const separator = origin.indexOf(SCHEME_SEPARATOR);
  const scheme = separator === -1 ? undefined : origin.slice(0, separator);
  const domain = separator === -1 ? origin : origin.slice(separator + SCHEME_SEPARATOR.length);
  if (scheme !== undefined && !SCHEME_PATTERN.test(scheme)) {
    return null;
  }
  if (!AUTHORITY_PATTERN.test(domain)) {
    return null;
  }
  return scheme === undefined ? { domain } : { scheme, domain };
}

/**
 * SIWE メッセージを EIP-4361 ABNF に沿って厳密にパースする。構造が一致しなければ `null`。
 *
 * 行構成: ヘッダ（`[scheme://]domain wants you ...` / address / 空行）→ `[statement 空行]`（空行 1 つ分の
 * ブロック）→ URI → Version → Chain ID → Nonce → Issued At → [Expiration Time] → [Not Before] →
 * [Request ID] → [`Resources:` と 1 行以上の `- uri`]。順序違反・重複・未知行・末尾余剰行・空値は `null`。
 */
export function parseSiweStrict(message: string): StrictSiweFields | null {
  if (
    typeof message !== 'string' ||
    message.length > MAX_SIWE_MESSAGE_LENGTH ||
    FORBIDDEN_CHARS.test(message)
  ) {
    return null;
  }
  const lines = message.split('\n');

  const header = lines[0] ?? '';
  if (!header.endsWith(HEADER_SUFFIX)) {
    return null;
  }
  const origin = parseOrigin(header.slice(0, header.length - HEADER_SUFFIX.length));
  const address = lines[1] ?? '';
  if (origin === null || !ADDRESS_PATTERN.test(address) || lines[2] !== '') {
    return null;
  }

  // `address LF LF [statement LF] LF URI`: statement 無しは空行が 2 つ、有りは statement（単一行）の次が空行。
  let index = 4;
  let statement: string | undefined;
  if (lines[3] === undefined) {
    return null;
  }
  if (lines[3] !== '') {
    statement = lines[3];
    if (lines[4] !== '') {
      return null;
    }
    index = 5;
  }

  const values: (string | undefined)[] = [];
  let next = 0; // FIELD_LABELS 上で次に許される最小位置
  while (index < lines.length && lines[index] !== RESOURCES_LABEL) {
    const line = lines[index] as string;
    const position = FIELD_LABELS.findIndex(
      (label, labelIndex) => labelIndex >= next && line.startsWith(label),
    );
    // 任意フィールドは飛ばせるが、必須フィールドは飛ばせない。
    if (position === -1 || (next < REQUIRED_FIELD_COUNT && position !== next)) {
      return null;
    }
    const value = line.slice((FIELD_LABELS[position] as string).length);
    if (value === '') {
      return null;
    }
    values[position] = value;
    next = position + 1;
    index += 1;
  }
  if (next < REQUIRED_FIELD_COUNT) {
    return null;
  }

  const resources: string[] = [];
  if (lines[index] === RESOURCES_LABEL) {
    for (index += 1; index < lines.length; index += 1) {
      const line = lines[index] as string;
      if (!line.startsWith(RESOURCE_ITEM_PREFIX) || line.length === RESOURCE_ITEM_PREFIX.length) {
        return null;
      }
      resources.push(line.slice(RESOURCE_ITEM_PREFIX.length));
    }
    if (resources.length === 0 || resources.length > MAX_SIWE_RESOURCES) {
      return null;
    }
  }
  if (index !== lines.length) {
    return null;
  }
  // 本物の Resources 行以外に `Resources:` があると、最初一致の下流パーサが Resources ブロックを読み違える。
  const firstLabel = message.indexOf(RESOURCES_LABEL);
  if (
    firstLabel !== message.lastIndexOf(RESOURCES_LABEL) ||
    (resources.length === 0 && firstLabel !== -1)
  ) {
    return null;
  }

  const [uri, version, chainIdRaw, nonce, issuedAt, expirationTime, notBefore, requestId] = values;
  if (
    uri === undefined ||
    version === undefined ||
    chainIdRaw === undefined ||
    nonce === undefined ||
    issuedAt === undefined ||
    !CHAIN_ID_PATTERN.test(chainIdRaw) ||
    !NONCE_PATTERN.test(nonce)
  ) {
    return null;
  }
  return {
    ...origin,
    address,
    uri,
    version,
    chainId: Number(chainIdRaw),
    nonce,
    issuedAt,
    ...(statement !== undefined ? { statement } : {}),
    ...(expirationTime !== undefined ? { expirationTime } : {}),
    ...(notBefore !== undefined ? { notBefore } : {}),
    ...(requestId !== undefined ? { requestId } : {}),
    ...(resources.length > 0 ? { resources } : {}),
  };
}
