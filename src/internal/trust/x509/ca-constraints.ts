/**
 * 証明書が「鍵をどう使ってよいか」を表す X.509 v3 拡張の読み取り
 * （basicConstraints RFC 5280 §4.2.1.9 / keyUsage §4.2.1.3）。
 *
 * 読むのは 2 つ。**他の証明書を発行してよい CA か**（{@link caConstraints}）と、**証明書 / CRL 以外の
 * データに署名してよい鍵か**（{@link allowsDataSignature}）である。どちらも keyUsage BIT STRING の
 * ビット位置の解釈を要するので、**ビット位置の知識を本モジュール 1 か所に閉じる**ために同居させる。
 * 解釈が複数箇所に散ると、片方だけがビットを取り違えても気付けない。
 *
 * **なぜ必要か。** チェーン検証（`trust/etsi-tsl/chain.ts`）が中間証明書を subject DN の一致だけで
 * 選ぶと、信頼済み QTSP が発行した**エンドエンティティ証明書**をそのまま中間 CA として使える。
 * 攻撃者は自分の正当な証明書（と対応する秘密鍵）で任意の leaf に署名し、その証明書を中間として
 * 添えるだけで「Trust Anchor へ連鎖する」チェーンを組み立てられてしまう。DN の連結と署名の検証は
 * どちらも成立するため、**CA であることを証明書自身が主張しているか**を確かめる以外に止める手段が
 * 無い。RFC 5280 §6.1.4 の path validation も同じ検査（basicConstraints の cA と keyUsage の
 * keyCertSign）で中間証明書を絞り込む。
 *
 * **拡張の走査を `san.ts` と共有する。** 経路ごとに拡張の読み方が分かれると、片方だけが通る
 * 偽装が生まれる（`san.ts` 冒頭の同じ理由）。走査は `certificateExtensions` に一本化し、本
 * モジュールは値の解釈だけを持つ。
 *
 * セキュリティ上の注意:
 * - 戻り値・例外に証明書本文 / DN / 鍵素材を含めない。返すのは真偽 2 つだけである。
 * - 読めない拡張は「CA ではない」に倒す（fail-closed）。
 */

import { type Asn1Node, readChildren } from '../asn1.js';
import type { CertificateExtensions } from './san.js';

/** basicConstraints 拡張の OID（RFC 5280 §4.2.1.9）。 */
export const OID_BASIC_CONSTRAINTS = '2.5.29.19';
/** keyUsage 拡張の OID（RFC 5280 §4.2.1.3）。 */
export const OID_KEY_USAGE = '2.5.29.15';

/** ASN.1 BOOLEAN / INTEGER / BIT STRING / SEQUENCE の DER タグ。 */
const TAG_BOOLEAN = 0x01;
const TAG_INTEGER = 0x02;
const TAG_BIT_STRING = 0x03;
const TAG_SEQUENCE = 0x30;

/**
 * pathLenConstraint として受け入れる INTEGER content の最大バイト数。
 *
 * 現実の CA 階層で 4 バイト（符号バイト込み）を超える段数はあり得ない。これより長い値は
 * 「読めない制約」として扱う（{@link readPathLenConstraint} の fail-closed）。
 */
const MAX_PATH_LEN_BYTES = 4;

/** INTEGER の最上位バイトに立っていれば負数を表すビット（DER の符号付き表現）。 */
const SIGN_BIT = 0x80;

/** BIT STRING の先頭バイト（未使用ビット数）が取り得る最大値（X.690 §8.6.2.2）。 */
const MAX_UNUSED_BITS = 7;

/**
 * keyUsage の `keyCertSign` のビット位置（RFC 5280 §4.2.1.3 の KeyUsage BIT STRING）。
 *
 * 0=digitalSignature, 1=nonRepudiation, 2=keyEncipherment, 3=dataEncipherment,
 * 4=keyAgreement, **5=keyCertSign**, 6=cRLSign, 7=encipherOnly。
 */
const KEY_CERT_SIGN_BIT = 5;

/**
 * 「証明書 / CRL 以外のデータへの署名」を許す keyUsage のビット位置
 * （`digitalSignature` = bit 0 / `nonRepudiation`（contentCommitment） = bit 1）。
 *
 * **なぜ 2 ビットとも受けるか。** どちらも「証明書 / CRL 以外のデータに署名してよい」を意味する
 * ビットであり、eIDAS の Qualified 証明書（署名用・シール用）は `nonRepudiation` だけを立てる
 * ものが普通にある。片方しか受けないと真正な QTSP 証明書を落としてしまう。ここで落としたいのは
 * `keyEncipherment` / `keyAgreement` / `keyCertSign` しか持たない証明書 — CA が「この鍵で任意の
 * データに署名してはならない」と明示した証明書 — である。
 */
const DATA_SIGNATURE_BITS: readonly number[] = [0, 1];

/** 証明書が他の証明書を発行してよいか（CA 制約）。 */
export interface CaConstraints {
  /** basicConstraints 拡張があり `cA` が TRUE か。拡張そのものが無ければ `false`。 */
  readonly isCa: boolean;
  /**
   * この CA の**下に**続けてよい中間 CA の最大数（RFC 5280 §4.2.1.9 の pathLenConstraint）。
   * `undefined` は無制約（拡張に pathLenConstraint が無い）を表す。
   *
   * CA でない証明書（`isCa:false`）では常に `undefined` になる。段数の判定
   * （`path-constraints.ts` の `withinPathLength`）に届く前に `canIssueCertificates` が
   * `isCa:false` で落とすため、この場合の値は観測されない。
   */
  readonly pathLenConstraint: number | undefined;
  /**
   * 証明書への署名が keyUsage で許されているか。
   *
   * keyUsage は任意拡張なので**存在しなければ `true`**（RFC 5280 §6.1.4 (n) も「拡張がある場合に
   * keyCertSign を要求する」と定める）。存在するのに keyCertSign が立っていなければ `false`。
   */
  readonly canSignCertificates: boolean;
}

/**
 * CA と主張していない証明書を表す値（拡張なし / 読めない拡張の fail-closed 先）。
 *
 * `pathLenConstraint` は {@link NOT_CA_BASIC} と同じ `undefined` にする。`isCa:false` の証明書は
 * `canIssueCertificates` が先に落とすため段数の判定へ届かず、ここに `0` を置いても観測されない
 * （2 つの定数で値が食い違っていると、到達しない fail-closed をあると誤読させる）。
 * 読めない pathLenConstraint を fail-closed に倒す仕事は {@link readPathLenConstraint} が担う。
 */
const NOT_A_CA: CaConstraints = {
  isCa: false,
  pathLenConstraint: undefined,
  canSignCertificates: false,
};

/**
 * 走査済みの拡張から CA 制約を読む。
 *
 * 拡張そのものを読めなかった証明書（`undefined`）は「CA ではない」として返す。ここで例外を
 * 投げると、拡張が 1 つでも壊れた証明書を**パースできない**ことにしてしまい、CA 制約とは
 * 無関係な経路（SAN 突き合わせ・署名検証）まで巻き添えで落ちる。CA 制約としては読めないこと
 * 自体が fail-closed である。
 *
 * @param extensions `tryCertificateExtensions` の戻り値（読めなければ `undefined`）。
 * @returns basicConstraints / keyUsage から読み取った CA 制約。
 */
export function caConstraintsOf(extensions: CertificateExtensions | undefined): CaConstraints {
  if (extensions === undefined) {
    return NOT_A_CA;
  }
  const basic = readBasicConstraints(extensions.byOid.get(OID_BASIC_CONSTRAINTS));
  return {
    isCa: basic.isCa,
    pathLenConstraint: basic.pathLenConstraint,
    canSignCertificates: allowsKeyCertSign(extensions.byOid.get(OID_KEY_USAGE)),
  };
}

/** CA でないと判明した証明書の basicConstraints 読み取り結果（pathLen は意味を持たない）。 */
const NOT_CA_BASIC: BasicConstraintsFields = { isCa: false, pathLenConstraint: undefined };

/** basicConstraints から読み取るフィールド。 */
interface BasicConstraintsFields {
  /** `cA` が TRUE か。 */
  readonly isCa: boolean;
  /** `pathLenConstraint`（無ければ `undefined` = 無制約）。 */
  readonly pathLenConstraint: number | undefined;
}

/**
 * `BasicConstraints ::= SEQUENCE { cA BOOLEAN DEFAULT FALSE, pathLenConstraint INTEGER OPTIONAL }`
 * を読む。
 *
 * `cA` と `pathLenConstraint` は同じ SEQUENCE にあるので 1 回の走査で両方読む（読み方が 2 経路に
 * 分かれると、片方だけが通る解釈の食い違いが生まれる）。
 */
function readBasicConstraints(node: Asn1Node | undefined): BasicConstraintsFields {
  if (node === undefined || node.tag !== TAG_SEQUENCE) {
    return NOT_CA_BASIC;
  }
  let children: readonly Asn1Node[];
  try {
    children = readChildren(node);
  } catch {
    return NOT_CA_BASIC;
  }
  const first = children[0];
  // `cA` は DEFAULT FALSE。省略された（= 先頭が pathLenConstraint か空）証明書は CA ではない。
  if (first === undefined || first.tag !== TAG_BOOLEAN) {
    return NOT_CA_BASIC;
  }
  // DER の BOOLEAN TRUE は 0xff だが、非 DER な 0x01 等も「TRUE」として書かれ得る。ここは
  // 「TRUE と読めるものを TRUE にする」方が安全側（CA でないものを CA と読む方向には働かない）。
  if ((first.content[0] ?? 0x00) === 0x00) {
    return NOT_CA_BASIC;
  }
  return { isCa: true, pathLenConstraint: readPathLenConstraint(children) };
}

/**
 * `BasicConstraints` の子要素列から `pathLenConstraint`（INTEGER・符号なし）を読む。
 *
 * 本当の「制約なし」（`undefined`）は、`cA` の次の要素が**存在しない**場合だけである。
 *
 * **fail-closed**: 要素はあるが INTEGER でない / 余分な要素が続く / content が空 /
 * {@link MAX_PATH_LEN_BYTES} 超 / 最上位ビットが立つ（= 負数）場合は最も厳しい `0` を返す。
 * 読めない制約を `undefined`（無制約）に倒すと、攻撃者は壊れた pathLenConstraint を書くだけで
 * 段数制限を外した CA 証明書を作れてしまう。
 */
function readPathLenConstraint(children: readonly Asn1Node[]): number | undefined {
  const node = children[1];
  if (node === undefined) {
    return undefined;
  }
  if (node.tag !== TAG_INTEGER || children.length > 2) {
    return 0;
  }
  const bytes = node.content;
  if (
    bytes.length === 0 ||
    bytes.length > MAX_PATH_LEN_BYTES ||
    ((bytes[0] as number) & SIGN_BIT) !== 0
  ) {
    return 0;
  }
  let value = 0;
  for (const byte of bytes) {
    value = value * 0x100 + byte;
  }
  return value;
}

/** KeyUsage ::= BIT STRING の `keyCertSign`（bit 5）を読む。拡張が無ければ制限なし。 */
function allowsKeyCertSign(node: Asn1Node | undefined): boolean {
  return allowsAnyKeyUsage(node, [KEY_CERT_SIGN_BIT]);
}

/**
 * 走査済みの拡張から「この鍵で証明書 / CRL 以外のデータに署名してよいか」を読む
 * （{@link DATA_SIGNATURE_BITS} のいずれかが立っているか）。
 *
 * keyUsage は任意拡張なので**存在しなければ `true`**（{@link CaConstraints.canSignCertificates} と
 * 同じ扱い）。存在するのに読めない場合、および拡張そのものを読めなかった場合（`undefined`）は
 * `false`（fail-closed。{@link caConstraintsOf} と同じ理由でここでも例外は投げない）。
 *
 * @param extensions `tryCertificateExtensions` の戻り値（読めなければ `undefined`）。
 * @returns データ署名が許されていれば `true`。
 */
export function allowsDataSignatureOf(extensions: CertificateExtensions | undefined): boolean {
  if (extensions === undefined) {
    return false;
  }
  return allowsAnyKeyUsage(extensions.byOid.get(OID_KEY_USAGE), DATA_SIGNATURE_BITS);
}

/**
 * KeyUsage ::= BIT STRING の `bits` のいずれかが立っているか。
 *
 * keyUsage は任意拡張なので、拡張そのものが無ければ「制限なし」で `true` を返す。名乗りながら
 * 読めない（BIT STRING でない / 未使用ビット数すら無い / 未使用ビット数が 0..7 の範囲外）場合は
 * 許可を確認できないので `false`。末尾の未使用ビットに入る位置のビットは「立っていない」として扱う。
 *
 * ビットは BIT STRING の MSB-first 規約で並ぶ（RFC 5280 §4.2.1.3 の KeyUsage は bit 0 =
 * 先頭バイトの最上位ビット）ので、`bit` 番目は `content[bit/8]` の `7 - (bit % 8)` 桁目にある。
 */
function allowsAnyKeyUsage(node: Asn1Node | undefined, bits: readonly number[]): boolean {
  if (node === undefined) {
    return true;
  }
  if (node.tag !== TAG_BIT_STRING || node.content.length < 2) {
    // keyUsage を名乗りながら読めない = 許可を確認できないので拒否する。
    return false;
  }
  const unusedBits = node.content[0] as number;
  if (unusedBits > MAX_UNUSED_BITS) {
    // BIT STRING の未使用ビット数は 0..7（X.690 §8.6.2.2）。範囲外は読めない拡張である。
    return false;
  }
  const content = node.content.subarray(1);
  const available = content.length * 8 - unusedBits;
  return bits.some((bit) => {
    if (available <= bit) {
      return false;
    }
    const byte = content[Math.floor(bit / 8)] as number;
    return ((byte >> (7 - (bit % 8))) & 1) === 1;
  });
}
