/**
 * nameConstraints 拡張の読み取り（RFC 5280 §4.2.1.10）。
 *
 * **なぜ必要か。** チェーン検証（`trust/etsi-tsl/chain.ts`）が nameConstraints を読まないと、
 * 「この名前空間の証明書しか発行してはならない」と CA 証明書自身に書かれた制限が無視される。
 * 発行範囲を絞って渡された中間 CA（例: 自社ドメインのみ発行可）を手に入れた者は、範囲外の
 * 識別子 — 他社の `origin` や Issuer の `iss` — を名乗る leaf を発行でき、`trust/rp-access` /
 * `wallet/issuer-trust` の突き合わせをそのまま通してしまう。CA 制約（`ca-constraints.ts`）が
 * 「発行してよいか」を確かめるのに対し、本モジュールは「**何に対して**発行してよいか」を読む
 * （読み取った制約と証明書の名前を突き合わせるのは `name-matching.ts`）。
 *
 * **なぜ directoryName と URI だけを評価するか。** SDK が証明書から読む識別子は URI SAN
 * （RP の `origin` 突き合わせ・SD-JWT VC の `iss` 突き合わせ）と subject DN（チェーン照合）だけで、
 * `dNSName` / `rfc822Name` / `iPAddress` は突き合わせ規約を持たない（`san.ts` が URI 以外の
 * GeneralName を捨てているのと同じ理由）。評価規約を持たない名前形式を「制約なし」と読むと、
 * CA が絞ったはずの名前空間が黙って開くので、**評価できないものは拒否側に倒す**。
 *
 * セキュリティ上の注意:
 * - 例外を投げず、真偽値・構造体で返す。戻り値・例外に証明書本文 / DN / 鍵素材を含めない。
 * - 読めない拡張は「制約なし」ではなく `evaluable:false`（配下ごと拒否）に倒す。拡張を壊すだけで
 *   制約を消せるようでは、制約を読む意味が無い。
 */

import { type Asn1Node, readChildren } from '../asn1.js';
import { normalizedRdns } from './dn.js';
import { type CertificateExtensions, subjectAltNames } from './san.js';

/** nameConstraints 拡張の OID（RFC 5280 §4.2.1.10）。 */
export const OID_NAME_CONSTRAINTS = '2.5.29.30';

/** SEQUENCE の DER タグ。 */
const TAG_SEQUENCE = 0x30;
/** permittedSubtrees [0] / excludedSubtrees [1]（IMPLICIT なので content が GeneralSubtree の並び）。 */
const TAG_PERMITTED_SUBTREES = 0xa0;
const TAG_EXCLUDED_SUBTREES = 0xa1;
/** GeneralName [4] directoryName（Name は CHOICE なので EXPLICIT）/ [6] URI。 */
const TAG_GN_DIRECTORY_NAME = 0xa4;
const TAG_GN_URI = 0x86;

/** `GeneralSubtree` が base だけを持つ（minimum / maximum を持たない）ときの子要素数。 */
const BASE_ONLY_CHILD_COUNT = 1;

/**
 * 1 つの GeneralSubtrees（permitted / excluded それぞれ）と、照合対象の URI SAN に許す件数の上限。
 *
 * 名前制約の照合は「証明書側の名前数 × base 数」の全対全比較で、どちらも x5c 由来＝攻撃者が件数を
 * 決められる。上限が無いと 1 MiB 以内の x5c で数秒〜十数秒停止する。実在する名前制約は
 * 数件〜数十件なので 128 で十分である。超過は評価不能として拒否側（fail-closed）に倒す。
 */
export const MAX_NAME_CONSTRAINT_ENTRIES = 128;

/** UTF-8 デコーダ。 */
const decoder = new TextDecoder();

/**
 * URI base として受け付ける形（ホスト、または先頭 `.` のサブドメイン指定）。
 *
 * `name-matching.ts` の `hostWithinBase` はホスト文字列としか突き合わせないため、スキームや
 * パスを含む base は**永久に一致しない**（= 制約が黙って全拒否になる）。形が合わない base は
 * 「一致しない」ではなく評価不能として扱い、fail-closed で配下ごと落とす。
 */
const HOST_FORM_BASE = /^\.?[a-z0-9]([a-z0-9.-]*[a-z0-9])?$/;

/** GeneralSubtrees から取り出した base の集合（この実装が評価できる GeneralName 種別ごと）。 */
export interface Subtrees {
  /** directoryName [4] の base。正規化済み RDN 列（`normalizedRdns` の形）。 */
  readonly directoryNames: readonly (readonly string[])[];
  /**
   * uniformResourceIdentifier [6] の base。小文字化済みのホスト（`example.com`）か、
   * 先頭 `.` のドメイン（`.example.com`）に限る。`HOST_FORM_BASE`（モジュール private）の形に
   * 合わない base（スキームやパスを含む完全な URI など）は照合しようがないので、`readSubtrees` が
   * そもそも評価不能（`undefined`）に倒す。
   */
  readonly uris: readonly string[];
}

/** nameConstraints 拡張の内容。 */
export interface NameConstraints {
  readonly permitted: Subtrees;
  readonly excluded: Subtrees;
  /** この実装で評価しきれるか。false なら配下のチェーンは fail-closed で落とす。 */
  readonly evaluable: boolean;
}

/** 名前制約の照合対象となる SubjectAltName。 */
export interface AltNames {
  /** uniformResourceIdentifier [6] の値（出現順）。 */
  readonly uris: readonly string[];
  /** 照合規約を持たない GeneralName 種別 / 読めない拡張を含むか。 */
  readonly hasUnevaluable: boolean;
}

/** base を 1 つも持たない subtrees（= その種別は無制約）。 */
const NO_SUBTREES: Subtrees = { directoryNames: [], uris: [] };

/** 読み取れなかった nameConstraints（配下をすべて拒否する）。 */
const UNEVALUABLE: NameConstraints = {
  permitted: NO_SUBTREES,
  excluded: NO_SUBTREES,
  evaluable: false,
};

/** SAN 拡張を持たない証明書。 */
const NO_ALT_NAMES: AltNames = { uris: [], hasUnevaluable: false };

/** SAN を読めなかった証明書（名前制約の下では通さない）。 */
const UNEVALUABLE_ALT_NAMES: AltNames = { uris: [], hasUnevaluable: true };

/**
 * 走査済みの拡張から nameConstraints を読む。
 *
 * @param extensions `tryCertificateExtensions` の戻り値（読めなければ `undefined`）。
 * @returns 制約。拡張が無ければ `undefined`（= 制約を課さない）。**拡張はあるが読めない場合は
 *   `undefined` ではなく `evaluable:false`** を返す（`undefined` に倒すと拡張を壊すだけで制約を
 *   消せてしまう）。拡張の走査ごと失敗した場合も同じく `evaluable:false` である — 制約の有無
 *   すら確かめられていないので「制約なし」とは読めない。
 */
export function nameConstraintsOf(
  extensions: CertificateExtensions | undefined,
): NameConstraints | undefined {
  if (extensions === undefined) {
    return UNEVALUABLE;
  }
  const node = extensions.byOid.get(OID_NAME_CONSTRAINTS);
  if (node === undefined) {
    return undefined;
  }
  return parseNameConstraints(node);
}

/**
 * `NameConstraints ::= SEQUENCE { permittedSubtrees [0] GeneralSubtrees OPTIONAL,
 * excludedSubtrees [1] GeneralSubtrees OPTIONAL }` を読む。
 */
function parseNameConstraints(node: Asn1Node): NameConstraints {
  if (node.tag !== TAG_SEQUENCE) {
    return UNEVALUABLE;
  }
  let children: readonly Asn1Node[];
  try {
    children = readChildren(node);
  } catch {
    return UNEVALUABLE;
  }
  // RFC 5280 §4.2.1.10 は「いずれかの subtree を必ず持つ」と定める。空の NameConstraints を
  // 「制約ゼロ = 全許可」と読むと、拡張の中身を空にするだけで制約を外せてしまう（fail-closed）。
  if (children.length === 0) {
    return UNEVALUABLE;
  }
  let permitted: Subtrees | undefined;
  let excluded: Subtrees | undefined;
  for (const child of children) {
    if (child.tag !== TAG_PERMITTED_SUBTREES && child.tag !== TAG_EXCLUDED_SUBTREES) {
      return UNEVALUABLE;
    }
    const subtrees = readSubtrees(child);
    if (subtrees === undefined) {
      return UNEVALUABLE;
    }
    // 同じタグが 2 度現れる拡張は構文違反。last-wins で黙って上書きすると、後ろに緩い
    // subtrees を足すだけで前の制約を消せる。
    if (child.tag === TAG_PERMITTED_SUBTREES) {
      if (permitted !== undefined) {
        return UNEVALUABLE;
      }
      permitted = subtrees;
    } else {
      if (excluded !== undefined) {
        return UNEVALUABLE;
      }
      excluded = subtrees;
    }
  }
  return {
    permitted: permitted ?? NO_SUBTREES,
    excluded: excluded ?? NO_SUBTREES,
    evaluable: true,
  };
}

/**
 * `GeneralSubtrees ::= SEQUENCE SIZE (1..MAX) OF GeneralSubtree` を読む。
 *
 * [0] / [1] は IMPLICIT タグなので、`node` の content がそのまま GeneralSubtree（SEQUENCE）の
 * 並びになる（内側に SEQUENCE のラッパは無い）。
 *
 * @returns 評価できる base の集合。0 要素 / 未対応の base / `minimum`・`maximum` 付きなら
 *   `undefined`（評価不能）。RFC 5280 §4.2.1.10 は `minimum` が 0 以外 / `maximum` が存在する
 *   証明書をエラーとして扱うべきと定める。本実装はさらに厳しく、**明示エンコードされた
 *   `minimum: 0`（DEFAULT なので DER では省略されるべき値）も含めて** base 以外の子を持つ
 *   GeneralSubtree を受け付けない — `minimum` を読んで 0 かどうか分岐する経路を持たないほうが、
 *   「読んだつもりで無視する」取り違えが起きない。
 */
function readSubtrees(node: Asn1Node): Subtrees | undefined {
  let subtrees: readonly Asn1Node[];
  try {
    subtrees = readChildren(node);
  } catch {
    return undefined;
  }
  if (subtrees.length === 0 || subtrees.length > MAX_NAME_CONSTRAINT_ENTRIES) {
    return undefined;
  }
  const directoryNames: (readonly string[])[] = [];
  const uris: string[] = [];
  for (const subtree of subtrees) {
    if (subtree.tag !== TAG_SEQUENCE) {
      return undefined;
    }
    let parts: readonly Asn1Node[];
    try {
      parts = readChildren(subtree);
    } catch {
      return undefined;
    }
    const base = parts[0];
    if (base === undefined || parts.length !== BASE_ONLY_CHILD_COUNT) {
      return undefined;
    }
    if (base.tag === TAG_GN_DIRECTORY_NAME) {
      // [4] は EXPLICIT なので content が RDNSequence の DER 全体になる。
      const rdns = normalizedRdns(base.content);
      if (rdns === undefined) {
        return undefined;
      }
      directoryNames.push(rdns);
    } else if (base.tag === TAG_GN_URI) {
      const uri = decoder.decode(base.content).trim().toLowerCase();
      if (!HOST_FORM_BASE.test(uri)) {
        return undefined;
      }
      uris.push(uri);
    } else {
      // 評価規約を持たない GeneralName 種別（dNSName / rfc822Name / iPAddress …）。
      return undefined;
    }
  }
  return { directoryNames, uris };
}

/**
 * 走査済みの拡張から、名前制約の照合対象となる SubjectAltName を読む。
 *
 * GeneralName の走査そのものは `san.ts` の `subjectAltNames` が行う（走査を 2 つ持つと、
 * 片方だけ SEQUENCE 検査を落とすような不揃いが生まれる）。本関数はその結果を
 * 「名前制約の下で通してよいか」の語彙へ翻訳するだけである。
 *
 * @param extensions `tryCertificateExtensions` の戻り値（読めなければ `undefined`）。
 * @returns URI SAN と、評価できない名前を含むかどうか。SAN 拡張が無ければ空（制約下でも通る）。
 */
export function altNamesOf(extensions: CertificateExtensions | undefined): AltNames {
  if (extensions === undefined) {
    return UNEVALUABLE_ALT_NAMES;
  }
  const san = subjectAltNames(extensions);
  if (!san.present) {
    return NO_ALT_NAMES;
  }
  if (!san.readable || san.uris.length > MAX_NAME_CONSTRAINT_ENTRIES) {
    return UNEVALUABLE_ALT_NAMES;
  }
  return { uris: san.uris, hasUnevaluable: san.hasOtherNames };
}
