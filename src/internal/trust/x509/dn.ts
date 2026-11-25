/**
 * DistinguishedName（RDNSequence）の正規化（RFC 5280 §4.1.2.4 / §7.1）。
 *
 * **なぜ必要か。** nameConstraints の directoryName 照合（`name-constraints.ts`）は「base の RDN 列が
 * 候補の RDN 列の先頭一致か」を判定する。ここをバイト列一致で済ませると、攻撃者は同じ名前を
 * **別の文字列型**（PrintableString ↔ UTF8String）・別の大小・余分な空白で書き直すだけで
 * `excludedSubtrees` を素通りできる。DER 上は別バイト列だが、人が読む名前としては同一なので、
 * 「違うバイト列＝違う名前」と読む実装は制約を事実上無効化する。
 *
 * **なぜ完全な準備をしないか。** RFC 5280 §7.1 が参照する RFC 4518 の文字列準備（Unicode 正規化・
 * マッピング・禁止文字）は実装しない。代わりに**扱える表現を絞り、扱えない表現は「一致しない」では
 * なく「評価不能」（`undefined`）に倒す**。評価不能は呼び出し側で拒否になるので、未対応の文字列型を
 * 使った回避経路は生じない。
 *
 * セキュリティ上の注意:
 * - 例外を投げず、読めない DN は `undefined` を返す（fail-closed）。
 * - 戻り値は照合キーであり、ログ・例外・エラーメッセージへ出さない（DN そのものを含むため）。
 */

import { type Asn1Node, decodeOid, readChildren, readNode } from '../asn1.js';

/** SEQUENCE / SET / OID の DER タグ。 */
const TAG_SEQUENCE = 0x30;
const TAG_SET = 0x31;
const TAG_OID = 0x06;

/**
 * 正規化して比較できる DirectoryString 系のタグ。
 *
 * UTF8String(0x0c) / PrintableString(0x13) / IA5String(0x16) / NumericString(0x12) /
 * VisibleString(0x1a)。いずれも UTF-8 か ASCII 互換のオクテット列なので同じ手順で畳める。
 * BMPString(0x1e) / UniversalString(0x1c) / TeletexString(0x14) は別のエンコーディングを持つため
 * 対象外とし、評価不能に倒す。
 */
const NORMALIZABLE_STRING_TAGS: ReadonlySet<number> = new Set([0x0c, 0x13, 0x16, 0x12, 0x1a]);

/** 連続する空白（DER 上は保持されるが名前としては等価）。 */
const WHITESPACE_RUN = /\s+/g;

/** 同一 RDN 内の属性を連結する区切り（LDAP の多値 RDN 表記にならう）。 */
const MULTI_VALUE_SEPARATOR = '+';

/**
 * UTF-8 デコーダ（**fatal**。不正バイト列はデコード例外になり、評価不能へ倒す）。
 *
 * 非 fatal だと不正バイトがすべて U+FFFD へ潰れるため、**実体の違う名前どうしが一致する**。
 * `excludedSubtrees` の base と subject が別物なのに一致して配下が落ちる方向にも、
 * `permittedSubtrees` の base に一致して通ってしまう方向にも働く。正規化キーは
 * 「読めたバイト列だけを畳む」ものに限る。
 */
const decoder = new TextDecoder('utf-8', { fatal: true });

/**
 * DN(DER) を RDN ごとの正規化済み文字列の配列にする。
 *
 * 各 RDN は `SET OF AttributeTypeAndValue` で順序に意味を持たないため、`"<oid>=<値>"` を**ソートして**
 * `+` で連結した 1 つの文字列に畳む。RDN 列そのものの順序は意味を持つので配列の順を保つ。
 *
 * @param dnDer Name（RDNSequence）の DER バイト列全体。
 * @returns 正規化した RDN 列。読めない / 未対応の表現を含む場合は `undefined`（評価不能）。
 */
export function normalizedRdns(dnDer: Uint8Array): readonly string[] | undefined {
  let node: Asn1Node;
  try {
    node = readNode(dnDer);
  } catch {
    return undefined;
  }
  // 末尾に余分なバイトが続く DN は、読み方によって別の名前に見え得るので受け付けない。
  if (node.tag !== TAG_SEQUENCE || node.totalLength !== dnDer.length) {
    return undefined;
  }
  let rdns: readonly Asn1Node[];
  try {
    rdns = readChildren(node);
  } catch {
    return undefined;
  }
  const out: string[] = [];
  for (const rdn of rdns) {
    const normalized = normalizeRdn(rdn);
    if (normalized === undefined) {
      return undefined;
    }
    out.push(normalized);
  }
  return out;
}

/** `RelativeDistinguishedName ::= SET SIZE (1..MAX) OF AttributeTypeAndValue` を畳む。 */
function normalizeRdn(rdn: Asn1Node): string | undefined {
  if (rdn.tag !== TAG_SET) {
    return undefined;
  }
  let attributes: readonly Asn1Node[];
  try {
    attributes = readChildren(rdn);
  } catch {
    return undefined;
  }
  if (attributes.length === 0) {
    return undefined;
  }
  const parts: string[] = [];
  for (const attribute of attributes) {
    const part = normalizeAttribute(attribute);
    if (part === undefined) {
      return undefined;
    }
    parts.push(part);
  }
  return parts.sort().join(MULTI_VALUE_SEPARATOR);
}

/** `AttributeTypeAndValue ::= SEQUENCE { type OID, value ANY }` を `"<oid>=<値>"` にする。 */
function normalizeAttribute(attribute: Asn1Node): string | undefined {
  if (attribute.tag !== TAG_SEQUENCE) {
    return undefined;
  }
  let fields: readonly Asn1Node[];
  try {
    fields = readChildren(attribute);
  } catch {
    return undefined;
  }
  // **要素数まで確かめる。** `AttributeTypeAndValue ::= SEQUENCE { type, value }` は 2 要素ちょうど
  // であり、3 つ目を足した DN を先頭 2 要素だけ見て畳むと、バイト列の異なる 2 つの DN が同じ
  // 照合キーに衝突する（`permittedSubtrees` が 1 段緩む）。余剰要素の fail-closed は
  // `ca-constraints.ts` の `readPathLenConstraint`（`children.length > 2`）と同じ方針である。
  if (fields.length !== 2) {
    return undefined;
  }
  const [typeNode, valueNode] = fields;
  if (typeNode === undefined || valueNode === undefined || typeNode.tag !== TAG_OID) {
    return undefined;
  }
  if (!NORMALIZABLE_STRING_TAGS.has(valueNode.tag)) {
    return undefined;
  }
  let type: string;
  try {
    type = decodeOid(typeNode.content);
  } catch {
    return undefined;
  }
  let decoded: string;
  try {
    decoded = decoder.decode(valueNode.content);
  } catch {
    // UTF-8 として読めない属性値。U+FFFD へ潰して別名と一致させるより評価不能に倒す。
    return undefined;
  }
  // **属性型の照合規則に関わらず小文字化する（意図的な逸脱）。** RFC 4519 の属性型には
  // `caseIgnoreMatch` だけでなく `caseExactMatch`（例: `serialNumber` の一部プロファイル）も
  // あり、後者を小文字化すると本来別名のはずの 2 つが一致する = `permittedSubtrees` が
  // 1 段緩む（`excludedSubtrees` 側は逆に広く当たるので締まる方向）。型ごとに照合規則表を
  // 持たないのは、RFC 4518 の完全な準備処理が本ファイルの範囲外だからである（冒頭参照）。
  // 到達経路は nameConstraints の照合だけで、そこでは base も同じ規則で正規化される。
  const value = decoded.trim().replace(WHITESPACE_RUN, ' ').toLowerCase();
  return `${type}=${value}`;
}
