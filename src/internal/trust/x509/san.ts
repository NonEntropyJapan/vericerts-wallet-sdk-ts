/**
 * X.509 v3 拡張の取り出しと SubjectAltName（URI）の展開（RFC 5280 §4.2.1.6）。
 *
 * **なぜ `etsi-tsl/x509.ts` と別に置くか。** `x509.ts` は署名検証に必要な最小フィールド
 * （tbsBytes / spki / DN / 有効期間）と、発行連鎖の成立条件である CA 制約
 * （`ca-constraints.ts` に委譲）だけを扱う。一方、証明書を**識別子の
 * 主張**として読む経路 — RP Access Certificate の `client_id` 突き合わせ（`trust/rp-access`）と、
 * 受領した SD-JWT VC の `iss` 突き合わせ（`wallet/issuer-trust`）— は SubjectAltName を必要とする。
 * この読み取りが経路ごとに複製されると、片方だけ GeneralName の種別の扱いがずれ、
 * **一方の経路でだけ通る SAN 偽装**が生まれる。したがって拡張の走査と SAN の展開は
 * ここ 1 か所に置き、両経路から参照する。
 *
 * **GeneralName の走査も 1 か所に持つ。** URI だけを返す入口（{@link subjectAltNameUris}）と、
 * 名前制約の照合に「URI 以外を含んでいたか」まで要る入口（`name-constraints.ts` の `altNames`）は
 * 同じ走査を必要とする。両方が自前で SAN を読むと、片方だけ SEQUENCE 検査を落とすといった
 * 不揃いが生まれるので、走査は {@link subjectAltNames} だけが行う。
 *
 * セキュリティ上の注意:
 * - 戻り値・例外に証明書本文 / DN / 鍵素材を含めない。返すのは SAN のエントリ文字列だけである。
 * - パース不能な証明書は例外ではなく**空の SAN** として返す（fail-closed。呼び出し側は
 *   「SAN が 1 件も無い」= 突き合わせ不成立として拒否する）。
 * - 同一 OID の拡張が 2 つ以上ある証明書は例外にする（RFC 5280 §4.2 は重複を禁じる）。後勝ちで
 *   黙って上書きすると、検査対象の拡張を無害な複製で押し流せてしまう。
 */

import { Asn1Error, type Asn1Node, decodeOid, readChildren, readNode } from '../asn1.js';

/** OID / OCTET STRING / BOOLEAN / SEQUENCE の DER タグ。 */
const TAG_BOOLEAN = 0x01;
const TAG_OCTET_STRING = 0x04;
const TAG_OID = 0x06;
const TAG_SEQUENCE = 0x30;
/** context-specific [3] explicit（TBSCertificate.extensions）。 */
const TAG_CONTEXT_3 = 0xa3;
/** GeneralName [6] uniformResourceIdentifier（RFC 5280 §4.2.1.6）。 */
const TAG_SAN_URI = 0x86;

/** SubjectAltName 拡張の OID（RFC 5280 §4.2.1.6）。 */
export const OID_SUBJECT_ALT_NAME = '2.5.29.17';

/**
 * SubjectDirectoryAttributes 拡張の OID（RFC 5280 §4.2.1.8）。
 *
 * RP Access Certificate（ETSI TS 119 475）の認可属性がここに入り、`trust/rp-access/cert.ts` が
 * 値を読んで `authorizeClaims` の認可判断に使う。**値を読む以上、critical 判定側
 * （`critical.ts`）でも「解釈する拡張」に数える**ので、定義は 1 か所に置いて両者で共有する。
 */
export const OID_SUBJECT_DIR_ATTRS = '2.5.29.9';

/** SAN を 1 件も持たない（または読めなかった）ことを表す値。 */
const NO_SUBJECT_ALT_NAME_URIS: readonly string[] = [];

/** UTF-8 デコーダ（SAN のエントリ文字列用）。 */
const decoder = new TextDecoder();

/**
 * 証明書が持つ v3 拡張の一覧。
 *
 * `critical` を値と分けて持つのは、RFC 5280 §6.1.4 (f) の「解釈できない critical 拡張を持つ
 * 証明書は拒否する」をチェーン検証（`critical.ts` → `etsi-tsl/chain.ts`）で課すためである。
 * critical を読み捨てると、CA が「この制限は必ず守れ」と書いた拡張を SDK が黙って無視できてしまう。
 */
export interface CertificateExtensions {
  /** 拡張 OID → 拡張値（`extnValue` の OCTET STRING を 1 段ほどいた結果）。 */
  readonly byOid: ReadonlyMap<string, Asn1Node>;
  /** `critical` が TRUE の拡張 OID。 */
  readonly criticalOids: ReadonlySet<string>;
}

/** SubjectAltName の GeneralName 走査結果。 */
export interface SubjectAltNames {
  /** `uniformResourceIdentifier` [6] の値（出現順）。 */
  readonly uris: readonly string[];
  /** SAN 拡張そのものが存在したか。 */
  readonly present: boolean;
  /** SAN 拡張を GeneralName の並びとして読めたか（SEQUENCE でない / DER 不正なら `false`）。 */
  readonly readable: boolean;
  /** URI 以外の GeneralName 種別を含むか。 */
  readonly hasOtherNames: boolean;
}

/** SAN 拡張を持たない証明書の走査結果。 */
const NO_SAN: SubjectAltNames = {
  uris: NO_SUBJECT_ALT_NAME_URIS,
  present: false,
  readable: true,
  hasOtherNames: false,
};

/** SAN 拡張はあるが読めなかった証明書の走査結果。 */
const UNREADABLE_SAN: SubjectAltNames = {
  uris: NO_SUBJECT_ALT_NAME_URIS,
  present: true,
  readable: false,
  hasOtherNames: false,
};

/**
 * TBSCertificate の子要素から `extensions [3]` を {@link CertificateExtensions} にする。
 *
 * `Extension ::= SEQUENCE { extnID OID, critical BOOLEAN DEFAULT FALSE, extnValue OCTET STRING }`
 * の 3 要素を位置で読む（`critical` は DEFAULT なので省略され得る）。`extnValue`（OCTET STRING）の
 * 中身は DER なので、`readNode` で 1 段ほどいた結果を格納する。
 *
 * **要素の形を確かめてから読む。** 以前は値を `parts[parts.length - 1]` で取っていたため、
 * `extnID` しか持たない壊れた Extension では **OID の content を拡張値として読んで**いた。
 * OID / OCTET STRING のタグを確かめ、形が合わない Extension は読み飛ばす。
 *
 * @param tbsChildren `readChildren(tbs)` の結果。
 * @returns 拡張の一覧。拡張を持たない証明書では空。
 * @throws 同一 OID の拡張が 2 つ以上ある場合（`Error`。呼び出し側は fail-closed に畳む）。
 */
export function certificateExtensions(tbsChildren: readonly Asn1Node[]): CertificateExtensions {
  const byOid = new Map<string, Asn1Node>();
  const criticalOids = new Set<string>();
  const extsWrapper = tbsChildren.find((c) => c.tag === TAG_CONTEXT_3);
  if (extsWrapper === undefined) {
    return { byOid, criticalOids };
  }
  const seq = readChildren(extsWrapper)[0];
  if (seq === undefined || seq.tag !== TAG_SEQUENCE) {
    return { byOid, criticalOids };
  }
  for (const ext of readChildren(seq)) {
    const parts = readChildren(ext);
    const idNode = parts[0];
    if (idNode === undefined || idNode.tag !== TAG_OID) {
      continue;
    }
    const criticalNode = parts[1]?.tag === TAG_BOOLEAN ? parts[1] : undefined;
    const valueNode = criticalNode === undefined ? parts[1] : parts[2];
    if (valueNode === undefined || valueNode.tag !== TAG_OCTET_STRING) {
      continue;
    }
    const oid = decodeOid(idNode.content);
    if (byOid.has(oid)) {
      // RFC 5280 §4.2: 各拡張 OID は証明書内で 1 回しか現れてはならない。
      // 素の `Error` ではなく `Asn1Error` を投げる — 呼び出し側（`trust/rp-access/cert.ts`）は
      // 「パース失敗はすべて `Asn1Error`」を前提に失敗を正規化する。
      throw new Asn1Error('DER: duplicate certificate extension');
    }
    byOid.set(oid, readNode(valueNode.content));
    // DER の BOOLEAN TRUE は 0xff だが、非 DER な 0x01 等も TRUE として書かれ得る。
    if (criticalNode !== undefined && (criticalNode.content[0] ?? 0x00) !== 0x00) {
      criticalOids.add(oid);
    }
  }
  return { byOid, criticalOids };
}

/**
 * TBSCertificate の子要素から拡張を走査する。読めなければ `undefined`（呼び出し側で fail-closed）。
 *
 * 証明書 1 通につき走査は 1 回で足りる。以前は CA 制約 / データ署名可否 / nameConstraints / SAN の
 * 4 経路がそれぞれ走査していたため、全拡張を 4 回 DER パースしていた。
 *
 * @param tbsChildren `readChildren(tbs)` の結果。
 * @returns 拡張の一覧。DER 不正 / 重複 OID なら `undefined`。
 */
export function tryCertificateExtensions(
  tbsChildren: readonly Asn1Node[],
): CertificateExtensions | undefined {
  try {
    return certificateExtensions(tbsChildren);
  } catch {
    return undefined;
  }
}

/**
 * 拡張から SubjectAltName の GeneralName を走査する。
 *
 * **`extnValue` が SEQUENCE であることを確かめる。** SubjectAltName ::= GeneralNames ::=
 * SEQUENCE OF GeneralName なので、SEQUENCE でない中身を GeneralName の並びとして読むと、
 * 別の構造（OCTET STRING 等）のバイト列がタグ次第で URI SAN に化ける。
 *
 * @param extensions {@link certificateExtensions} の戻り値。
 * @returns URI の並びと、拡張の有無 / 可読性 / URI 以外の種別を含むか。
 */
export function subjectAltNames(extensions: CertificateExtensions): SubjectAltNames {
  const san = extensions.byOid.get(OID_SUBJECT_ALT_NAME);
  if (san === undefined) {
    return NO_SAN;
  }
  if (san.tag !== TAG_SEQUENCE) {
    return UNREADABLE_SAN;
  }
  let generalNames: readonly Asn1Node[];
  try {
    generalNames = readChildren(san);
  } catch {
    return UNREADABLE_SAN;
  }
  const uris: string[] = [];
  let hasOtherNames = false;
  for (const generalName of generalNames) {
    if (generalName.tag === TAG_SAN_URI) {
      uris.push(decoder.decode(generalName.content));
    } else {
      hasOtherNames = true;
    }
  }
  return { uris, present: true, readable: true, hasOtherNames };
}

/**
 * 拡張から SubjectAltName の `uniformResourceIdentifier` [6] を取り出す。
 *
 * **URI 以外の GeneralName 種別は黙って捨てる。** `dNSName` / `rfc822Name` / `iPAddress` 等は
 * 識別子の突き合わせ規約がそれぞれ異なる（ホスト名の正規化・大小無視・ワイルドカード）。
 * 規約を持たないまま候補として返すと、呼び出し側が種別を確かめずに比較する余地を残す。
 * RP Access Certificate（ETSI TS 119 475）も SD-JWT VC の Issuer 証明書
 * （draft-ietf-oauth-sd-jwt-vc）も識別子を URI SAN で示すと定めているため、URI だけを扱う。
 *
 * @param extensions {@link certificateExtensions} の戻り値。
 * @returns URI SAN の値（出現順）。SAN 拡張が無い / 読めない場合は空。
 */
export function subjectAltNameUris(extensions: CertificateExtensions): readonly string[] {
  return subjectAltNames(extensions).uris;
}

/**
 * 証明書 DER から SubjectAltName の `uniformResourceIdentifier` を取り出す。
 *
 * @param der 証明書の DER バイト列。
 * @returns URI SAN の値。SAN が無い / DER を読めない場合は空（fail-closed）。
 */
export function subjectAltNameUrisOfCertificate(der: Uint8Array): readonly string[] {
  try {
    const tbs = readChildren(readNode(der))[0];
    if (tbs === undefined || tbs.tag !== TAG_SEQUENCE) {
      return NO_SUBJECT_ALT_NAME_URIS;
    }
    return subjectAltNameUris(certificateExtensions(readChildren(tbs)));
  } catch {
    // DER 不正は「SAN が読めなかった」= 突き合わせ不成立として扱う（例外は伝播させない）。
    return NO_SUBJECT_ALT_NAME_URIS;
  }
}
