/**
 * RP Access Certificate（ETSI TS 119 475）の X.509 識別情報・拡張パース（trust/rp-access）。
 *
 * ETSI TS 119 475 は Relying Party の属性（法人名・識別子・所在国・サービス URI と、アクセスを
 * 認可された属性 / 目的 / カテゴリ）を X.509 v3 証明書に載せる。本モジュールは検証（署名・チェーン・
 * 有効期間）に必要なフィールドに加え、RP の識別情報と「認可された属性集合」を DER から抽出する。
 *
 * 認可属性は RFC 5280 の SubjectDirectoryAttributes 拡張（OID 2.5.29.9）に格納される想定とする
 * （ETSI TS 119 475 は RP に「関する」属性を SubjectDirectoryAttributes で表現する）。個々の属性型
 * OID は最新版 ETSI TS 119 475 で定義されるため、本実装は特定の架空 OID を正規とはせず、
 * `RP_ACCESS_ATTR_OIDS` に既知の型 OID をマッピングしつつ、未知の型は raw のまま保持する。
 *
 * 署名検証に必要な低レベルフィールド（tbsBytes / spki / signature 等）は etsi-tsl の
 * `parseCertificate` を再利用し、本モジュールはその上に「識別情報 + 認可拡張」を重ねる。
 * 拡張の走査と SubjectAltName の展開は `trust/x509`（`certificateExtensions` /
 * `subjectAltNameUris`）へ委ねる — 同じ読み取りを Issuer 証明書側（`wallet/issuer-trust`）も
 * 必要とし、複製すると片方だけ GeneralName の扱いがずれて SAN 偽装の余地が生まれるためである
 *
 * セキュリティ上の注意:
 * - 例外メッセージ・context に証明書本文 / DN / 鍵素材を含めない。
 * - パース失敗はすべて `Asn1Error` を投げ、呼び出し側で RP_ACCESS_CERT_* に正規化する。
 */

import { Asn1Error, type Asn1Node, decodeOid, readChildren, readNode } from '../asn1.js';
import { type ParsedCertificate, parseCertificate } from '../etsi-tsl/x509.js';
import { certificateExtensions, OID_SUBJECT_DIR_ATTRS, subjectAltNameUris } from '../x509/index.js';

/** OID / SEQUENCE / SET の DER タグ。 */
const TAG_OID = 0x06;
const TAG_SEQUENCE = 0x30;
const TAG_SET = 0x31;
/** context-specific [0] explicit（TBSCertificate.version）。extensions[3] の走査は `trust/x509` が担う。 */
const TAG_CONTEXT_0 = 0xa0;

/** Subject DN の属性型 OID（RFC 4519 / ETSI EN 319 412）。 */
const OID_ORGANIZATION_NAME = '2.5.4.10';
const OID_ORGANIZATION_IDENTIFIER = '2.5.4.97';
const OID_COUNTRY_NAME = '2.5.4.6';
const OID_COMMON_NAME = '2.5.4.3';

/**
 * ETSI TS 119 475 で RP のアクセス認可を表す SubjectDirectoryAttributes 内の属性型 OID。
 *
 * 具体的な OID は最新版 ETSI TS 119 475 で規定されるため、本マップは既知の型を意味づけするための
 * ヒントであり、未知の型 OID を持つ属性は `rawOid` 付きで `unknown` として保持する。
 */
export const RP_ACCESS_ATTR_OIDS = {
  /** 認可された claim（属性）識別子の集合。 */
  authorizedAttributes: '0.4.0.194121.1.1',
  /** 認可された提示目的（purpose）の集合。 */
  authorizedPurposes: '0.4.0.194121.1.2',
  /** 認可された属性カテゴリの集合。 */
  authorizedCategories: '0.4.0.194121.1.3',
} as const;

/** RP の識別情報（証明書 Subject / SAN から抽出）。 */
export interface RpIdentity {
  /** 法人名（organizationName / 無ければ commonName）。 */
  readonly legalName: string;
  /** 法人識別子（organizationIdentifier・例 LEI / EUID / VAT）。無ければ空文字。 */
  readonly legalId: string;
  /** 所在国（countryName・ISO 3166-1 alpha-2）。無ければ空文字。 */
  readonly country: string;
  /** RP サービス URI（SubjectAltName の URI）。無ければ空文字。 */
  readonly origin: string;
}

/** SubjectDirectoryAttributes から抽出した RP の認可スコープ。 */
export interface RpAuthorizedScope {
  /** 認可された claim（属性）識別子。 */
  readonly attributes: readonly string[];
  /** 認可された提示目的（purpose）。 */
  readonly purposes: readonly string[];
  /** 認可された属性カテゴリ。 */
  readonly categories: readonly string[];
}

/** パース済み RP Access Certificate。署名検証用の低レベルフィールドと識別情報・認可スコープを持つ。 */
export interface ParsedRpAccessCertificate {
  /** 署名検証・チェーン照合用の低レベルフィールド（etsi-tsl 由来）。 */
  readonly base: ParsedCertificate;
  /** 証明書シリアル番号（16 進・失効照合キー）。 */
  readonly serialHex: string;
  /** RP 識別情報。 */
  readonly identity: RpIdentity;
  /** RP の認可スコープ（SubjectDirectoryAttributes 由来）。 */
  readonly scope: RpAuthorizedScope;
}

/** TBSCertificate から version[0] の有無を見て serialNumber 以降の開始インデックスを求める。 */
function tbsStartIndex(children: readonly Asn1Node[]): number {
  return children[0]?.tag === TAG_CONTEXT_0 ? 1 : 0;
}

/** DER の INTEGER content を（先頭の符号 0x00 を除いた）16 進文字列にする。 */
function integerToHex(content: Uint8Array): string {
  let start = 0;
  while (start < content.length - 1 && content[start] === 0x00) {
    start++;
  }
  let out = '';
  for (let i = start; i < content.length; i++) {
    out += (content[i] as number).toString(16).padStart(2, '0');
  }
  return out === '' ? '00' : out;
}

/** AttributeTypeAndValue（SEQUENCE{ type OID, value ANY }）から type→文字列値を取り出す。 */
function readNameAttribute(atv: Asn1Node): { type: string; value: string } | undefined {
  const [typeNode, valueNode] = readChildren(atv);
  if (typeNode === undefined || valueNode === undefined || typeNode.tag !== TAG_OID) {
    return undefined;
  }
  return { type: decodeOid(typeNode.content), value: new TextDecoder().decode(valueNode.content) };
}

/** Name（RDNSequence）から DN 属性型→値のマップを構築する。 */
function collectNameAttributes(name: Asn1Node): Map<string, string> {
  const out = new Map<string, string>();
  for (const rdn of readChildren(name)) {
    if (rdn.tag !== TAG_SET) {
      continue;
    }
    for (const atv of readChildren(rdn)) {
      const attr = readNameAttribute(atv);
      // 同一型が複数ある場合は最初の値を採用する。
      if (attr !== undefined && !out.has(attr.type)) {
        out.set(attr.type, attr.value);
      }
    }
  }
  return out;
}

/** SET OF UTF8String/IA5String を文字列配列にする（認可属性値の抽出）。 */
function readStringSet(valueSet: Asn1Node): string[] {
  const out: string[] = [];
  for (const item of readChildren(valueSet)) {
    const text = new TextDecoder().decode(item.content).trim();
    if (text.length > 0) {
      out.push(text);
    }
  }
  return out;
}

/**
 * SubjectDirectoryAttributes（SEQUENCE OF Attribute）から RP の認可スコープを抽出する。
 *
 * Attribute ::= SEQUENCE { type OID, values SET OF ANY }。既知の型 OID
 * （`RP_ACCESS_ATTR_OIDS`）を attributes / purposes / categories に振り分ける。
 *
 * **`extnValue` が SEQUENCE であることを確かめる。** SubjectDirectoryAttributes ::=
 * SEQUENCE SIZE (1..MAX) OF Attribute なので、SEQUENCE でない中身を Attribute の並びとして
 * 読んではならない。`readChildren`（`trust/asn1.ts`）は constructed ビットを見ずに content を
 * TLV 列として読み直すため、別の構造（OCTET STRING 等）の任意バイト列からタグ次第で
 * `authorizeClaims` 用の属性 / purposes / categories が生成され得る。SAN 側の同じ硬化
 * （`x509/san.ts` の `subjectAltNames` が `tag !== TAG_SEQUENCE` を `UNREADABLE_SAN` にする）と
 * 揃える。個々の Attribute も同じ理由で SEQUENCE を要求する。
 *
 * 読めない拡張は**空スコープ**に倒す（`ext === undefined` と同じ扱い）。認可は「スコープ内か」で
 * 判定されるので、空スコープは何も認可しない fail-closed である。
 */
function extractScope(ext: Asn1Node | undefined): RpAuthorizedScope {
  const attributes: string[] = [];
  const purposes: string[] = [];
  const categories: string[] = [];
  if (ext === undefined || ext.tag !== TAG_SEQUENCE) {
    return { attributes, purposes, categories };
  }
  for (const attr of readChildren(ext)) {
    if (attr.tag !== TAG_SEQUENCE) {
      continue;
    }
    const [typeNode, valueSet] = readChildren(attr);
    if (typeNode === undefined || valueSet === undefined || typeNode.tag !== TAG_OID) {
      continue;
    }
    const values = valueSet.tag === TAG_SET ? readStringSet(valueSet) : [];
    switch (decodeOid(typeNode.content)) {
      case RP_ACCESS_ATTR_OIDS.authorizedAttributes:
        attributes.push(...values);
        break;
      case RP_ACCESS_ATTR_OIDS.authorizedPurposes:
        purposes.push(...values);
        break;
      case RP_ACCESS_ATTR_OIDS.authorizedCategories:
        categories.push(...values);
        break;
      default:
        // 未知の属性型は認可スコープに影響させない（fail-closed）。
        break;
    }
  }
  return { attributes, purposes, categories };
}

/**
 * DER エンコードされた RP Access Certificate をパースする。
 *
 * @param der 証明書の DER バイト列。
 * @returns 署名検証用フィールド + RP 識別情報 + 認可スコープ。
 * @throws 構造不正 / 必須フィールド欠落の場合（Asn1Error）。
 */
export function parseRpAccessCertificate(der: Uint8Array): ParsedRpAccessCertificate {
  const base = parseCertificate(der);
  const cert = readNode(der);
  const tbs = readChildren(cert)[0];
  if (tbs === undefined || tbs.tag !== TAG_SEQUENCE) {
    throw new Asn1Error('DER: certificate missing tbsCertificate');
  }
  const tbsChildren = readChildren(tbs);
  const idx = tbsStartIndex(tbsChildren);
  const serialNode = tbsChildren[idx];
  const subject = tbsChildren[idx + 4];
  if (serialNode === undefined || subject === undefined) {
    throw new Asn1Error('DER: TBSCertificate missing subject/serial');
  }
  const nameAttrs = collectNameAttributes(subject);
  const extensions = certificateExtensions(tbsChildren);
  const identity: RpIdentity = {
    legalName: nameAttrs.get(OID_ORGANIZATION_NAME) ?? nameAttrs.get(OID_COMMON_NAME) ?? '',
    legalId: nameAttrs.get(OID_ORGANIZATION_IDENTIFIER) ?? '',
    country: nameAttrs.get(OID_COUNTRY_NAME) ?? '',
    origin: subjectAltNameUris(extensions)[0] ?? '',
  };
  return {
    base,
    serialHex: integerToHex(serialNode.content),
    identity,
    scope: extractScope(extensions.byOid.get(OID_SUBJECT_DIR_ATTRS)),
  };
}
