/**
 * X.509 証明書のパースと署名アルゴリズム識別（trust/etsi-tsl）。
 *
 * ETSI TS 119 612 Trusted List の Qualified Certificate チェーン検証に必要な最小フィールドのみを
 * 抽出する。証明書の署名検証（WebCrypto）は `verify.ts` が担い、本モジュールは DER → 構造体への
 * 変換に専念する。ASN.1 の読み取りは `trust/asn1.ts` の小さな DER リーダを用いる。
 *
 * X.509 v3（RFC 5280）Certificate ::= SEQUENCE {
 *   tbsCertificate       TBSCertificate,        -- 署名対象
 *   signatureAlgorithm   AlgorithmIdentifier,
 *   signatureValue       BIT STRING }
 *
 * セキュリティ上の注意:
 * - 例外メッセージ・context に証明書本文 / DN / 鍵素材を含めない。
 */

import { Asn1Error, type Asn1Node, decodeOid, readChildren, readNode } from '../asn1.js';
import {
  allowsDataSignatureOf,
  type CaConstraints,
  caConstraintsOf,
} from '../x509/ca-constraints.js';
import { hasUnrecognizedCriticalExtension } from '../x509/critical.js';
import type { AltNames, NameConstraints } from '../x509/name-constraints.js';
import { altNamesOf, nameConstraintsOf } from '../x509/name-constraints.js';
import { tryCertificateExtensions } from '../x509/san.js';

/** SEQUENCE / SET / BIT STRING / INTEGER / OID の DER タグ。 */
const TAG_INTEGER = 0x02;
const TAG_BIT_STRING = 0x03;
const TAG_OID = 0x06;
const TAG_SEQUENCE = 0x30;
/** context-specific [0] explicit（TBSCertificate.version）。 */
const TAG_CONTEXT_0 = 0xa0;

/** 対応する証明書署名アルゴリズム（OID → WebCrypto 検証パラメータ）。 */
export type CertSignatureAlg = 'RSASSA-PKCS1-v1_5-SHA256' | 'ECDSA-P256-SHA256';

/** OID → 対応アルゴリズム。ETSI TSL で一般的な sha256WithRSA / ecdsa-with-SHA256 を対象とする。 */
const SIG_ALG_BY_OID: Readonly<Record<string, CertSignatureAlg>> = {
  // sha256WithRSAEncryption
  '1.2.840.113549.1.1.11': 'RSASSA-PKCS1-v1_5-SHA256',
  // ecdsa-with-SHA256
  '1.2.840.10045.4.3.2': 'ECDSA-P256-SHA256',
};

/** パース済み X.509 証明書（検証に必要なフィールドのみ）。 */
export interface ParsedCertificate {
  /** 署名対象バイト列（tbsCertificate 全体・DER）。署名検証の入力。 */
  readonly tbsBytes: Uint8Array;
  /** 証明書の署名アルゴリズム（未対応なら undefined）。 */
  readonly signatureAlg: CertSignatureAlg | undefined;
  /** 署名値（BIT STRING の中身、先頭の未使用ビット数バイトを除く）。 */
  readonly signature: Uint8Array;
  /** subjectPublicKeyInfo 全体（SPKI・DER）。WebCrypto の importKey('spki') に渡す。 */
  readonly spki: Uint8Array;
  /** issuer DN の DER バイト列（チェーン照合用）。 */
  readonly issuerDer: Uint8Array;
  /** subject DN の DER バイト列（チェーン照合用）。 */
  readonly subjectDer: Uint8Array;
  /** notBefore（Unix 秒）。 */
  readonly notBefore: number;
  /** notAfter（Unix 秒）。 */
  readonly notAfter: number;
  /**
   * CA 制約（basicConstraints / keyUsage）。チェーン検証が中間証明書を選ぶときに使う。
   *
   * 本モジュールは署名検証に要る最小フィールドだけを扱うが、**他の証明書を発行してよいか**は
   * 発行連鎖の成立条件そのものなので例外的にここで持つ（読み取りは `trust/x509/ca-constraints.ts`。
   * 分けて後から読むと、チェーン検証が制約を確かめ忘れても型で気付けない）。
   */
  readonly ca: CaConstraints;
  /**
   * この証明書の鍵で証明書 / CRL 以外のデータに署名してよいか（keyUsage の `digitalSignature` /
   * `nonRepudiation`。読み取りは `trust/x509/ca-constraints.ts`）。
   *
   * leaf の鍵は必ず JWS 署名の検証鍵として使われるので、**`ca` と同じ理由** — 発行連鎖・鍵用途の
   * 成立条件であり、確かめ忘れても型で気付けるように — でここに持つ。
   */
  readonly canSignData: boolean;
  /**
   * この証明書が配下へ課す nameConstraints（拡張が無ければ `undefined`。読み取りは
   * `trust/x509/name-constraints.ts`）。発行してよい**名前空間**の限定も発行連鎖の成立条件なので、
   * `ca` と同じ理由 — 確かめ忘れても型で気付けるように — でここに持つ。
   */
  readonly nameConstraints: NameConstraints | undefined;
  /** 名前制約の照合対象となる SubjectAltName（上位 CA の nameConstraints と突き合わせる）。 */
  readonly altNames: AltNames;
  /**
   * 本 SDK が解釈しない critical 拡張を持つか（RFC 5280 §6.1.4 (f)。読み取りは
   * `trust/x509/critical.ts`）。`ca` と同じ理由でここに持つ — critical の検査は証明書を
   * 受け入れてよいかの前提条件であり、確かめ忘れても型で気付けるようにしておく。
   */
  readonly hasUnrecognizedCriticalExtension: boolean;
}

/** BIT STRING の先頭 1 バイト（未使用ビット数）を取り除く。 */
function stripBitStringPad(node: Asn1Node): Uint8Array {
  if (node.content.length === 0) {
    throw new Asn1Error('DER: empty BIT STRING');
  }
  return node.content.subarray(1);
}

/** ASN.1 UTCTime タグ。 */
const TAG_UTC_TIME = 0x17;
/** ASN.1 GeneralizedTime タグ。 */
const TAG_GENERALIZED_TIME = 0x18;

/** 数字のみの文字列を 10 進整数として厳格にパースする（前後の符号・非数字を拒否）。 */
function parseDigits(text: string): number {
  if (!/^\d+$/.test(text)) {
    throw new Asn1Error('DER: invalid time');
  }
  return Number.parseInt(text, 10);
}

/**
 * UTCTime / GeneralizedTime を Unix 秒へ変換する（RFC 5280 §4.1.2.5）。
 *
 * RFC 5280 は証明書の時刻を必ず UTC（末尾 `Z`）で表現するよう要求する。UTCTime は
 * `YYMMDDHHMMSSZ`、GeneralizedTime は `YYYYMMDDHHMMSS[.fff]Z`。ここでは:
 * - 末尾が `Z` であることを検証する（他のタイムゾーン指定・欠落は拒否）。
 * - GeneralizedTime の小数秒（`.fff`）は秒未満のため切り捨てる（Unix 秒精度）。ただし桁は検証する。
 * - UTCTime / GeneralizedTime はタグで判別し、長さ推測に依存しない。
 */
function parseTime(node: Asn1Node): number {
  const raw = new TextDecoder().decode(node.content);
  if (!raw.endsWith('Z')) {
    // RFC 5280 は UTC（末尾 Z）を必須とする。ローカル時刻・±hhmm オフセットは拒否する。
    throw new Asn1Error('DER: time must be UTC (trailing Z)');
  }
  const text = raw.slice(0, -1);

  let y: number;
  let off: number;
  if (node.tag === TAG_UTC_TIME) {
    // UTCTime: YYMMDDHHMMSS。2 桁年は RFC 5280 の 50 境界で世紀を補完する。
    const yy = parseDigits(text.slice(0, 2));
    y = yy < 50 ? 2000 + yy : 1900 + yy;
    off = 2;
  } else if (node.tag === TAG_GENERALIZED_TIME) {
    // GeneralizedTime: YYYYMMDDHHMMSS[.fff]。
    y = parseDigits(text.slice(0, 4));
    off = 4;
  } else {
    throw new Asn1Error('DER: unexpected time tag');
  }

  const seconds = text.slice(off, off + 10);
  const fraction = text.slice(off + 10);
  // 秒までの 10 桁は必須。小数部があれば `.` + 数字のみを許容し、秒未満なので切り捨てる。
  if (seconds.length !== 10) {
    throw new Asn1Error('DER: invalid time');
  }
  if (fraction.length > 0 && !/^\.\d+$/.test(fraction)) {
    throw new Asn1Error('DER: invalid fractional seconds');
  }

  const mo = parseDigits(seconds.slice(0, 2));
  const d = parseDigits(seconds.slice(2, 4));
  const h = parseDigits(seconds.slice(4, 6));
  const mi = parseDigits(seconds.slice(6, 8));
  const s = parseDigits(seconds.slice(8, 10));
  const ms = Date.UTC(y, mo - 1, d, h, mi, s);
  if (Number.isNaN(ms)) {
    throw new Asn1Error('DER: invalid time');
  }
  return Math.floor(ms / 1000);
}

/**
 * `parseTime` のテスト専用エクスポート（内部関数のユニット検証用）。
 *
 * 公開 API ではないため `exports/trust.ts` へは出さない。回帰テストから DER 時刻ノードを直接
 * 与えて Z 検証・GeneralizedTime 小数秒の扱いを確認するために用いる。
 */
export function parseTimeForTest(node: Asn1Node): number {
  return parseTime(node);
}

/** AlgorithmIdentifier SEQUENCE から先頭 OID を取り出す。 */
function readAlgOid(node: Asn1Node): string {
  const first = readChildren(node)[0];
  if (first === undefined || first.tag !== TAG_OID) {
    throw new Asn1Error('DER: missing algorithm OID');
  }
  return decodeOid(first.content);
}

/**
 * DER エンコードされた X.509 証明書をパースする。
 *
 * @param der 証明書の DER バイト列。
 * @returns 検証に必要なフィールドを抽出した構造体。
 * @throws 構造が不正 / 必須フィールド欠落の場合（Asn1Error）。
 */
export function parseCertificate(der: Uint8Array): ParsedCertificate {
  const cert = readNode(der);
  if (cert.tag !== TAG_SEQUENCE) {
    throw new Asn1Error('DER: certificate is not a SEQUENCE');
  }
  const [tbs, sigAlg, sigValue] = readChildren(cert);
  if (tbs === undefined || sigAlg === undefined || sigValue === undefined) {
    throw new Asn1Error('DER: certificate missing fields');
  }
  if (sigValue.tag !== TAG_BIT_STRING) {
    throw new Asn1Error('DER: signatureValue is not a BIT STRING');
  }
  const tbsChildren = readChildren(tbs);
  // version[0] は省略可能。省略時は先頭が serialNumber(INTEGER)。
  let idx = 0;
  if (tbsChildren[0]?.tag === TAG_CONTEXT_0) {
    idx = 1;
  }
  // serialNumber, signature(AlgId), issuer, validity, subject, spki ...
  const issuer = tbsChildren[idx + 2];
  const validity = tbsChildren[idx + 3];
  const subject = tbsChildren[idx + 4];
  const spki = tbsChildren[idx + 5];
  if (
    issuer === undefined ||
    validity === undefined ||
    subject === undefined ||
    spki === undefined
  ) {
    throw new Asn1Error('DER: TBSCertificate missing fields');
  }
  if (tbsChildren[idx]?.tag !== TAG_INTEGER) {
    throw new Asn1Error('DER: missing serialNumber');
  }
  const [notBeforeNode, notAfterNode] = readChildren(validity);
  if (notBeforeNode === undefined || notAfterNode === undefined) {
    throw new Asn1Error('DER: validity missing bounds');
  }
  // RFC 5280 §4.1.1.2: 外側の signatureAlgorithm は tbsCertificate.signature と同一でなければ
  // ならない。食い違う証明書は、署名対象に書かれたアルゴリズムと実際に検証するアルゴリズムが
  // 別物になり得る（署名の意味が確定しない）ので受け付けない。
  // 外側の AlgorithmIdentifier は 1 回だけ読む（子の確保が 2 回・3 回に増幅されない）。
  const sigAlgOid = readAlgOid(sigAlg);
  const tbsSigAlg = tbsChildren[idx + 1];
  if (tbsSigAlg === undefined || readAlgOid(tbsSigAlg) !== sigAlgOid) {
    throw new Asn1Error('DER: signatureAlgorithm mismatch');
  }
  // 拡張の走査は 1 通につき 1 回だけ行い、結果を各読み取りへ配る（4 回走らせると同じ DER を
  // 4 回パースすることになる）。読めなかった場合は `undefined` を配り、各読み取りが fail-closed
  // な既定値へ畳む。
  const extensions = tryCertificateExtensions(tbsChildren);
  return {
    tbsBytes: sliceNode(tbs),
    signatureAlg: SIG_ALG_BY_OID[sigAlgOid],
    signature: stripBitStringPad(sigValue),
    spki: sliceNode(spki),
    issuerDer: sliceNode(issuer),
    subjectDer: sliceNode(subject),
    notBefore: parseTime(notBeforeNode),
    notAfter: parseTime(notAfterNode),
    ca: caConstraintsOf(extensions),
    canSignData: allowsDataSignatureOf(extensions),
    nameConstraints: nameConstraintsOf(extensions),
    altNames: altNamesOf(extensions),
    hasUnrecognizedCriticalExtension: hasUnrecognizedCriticalExtension(extensions),
  };
}

/**
 * 親ノード内の子ノードに対応する DER バイト列全体（tag+length+content）を取り出す。
 *
 * `readNode`/`readChildren` が返す `content` は tag/length を含まないため、署名検証や DN 照合には
 * 元 DER 上の該当スライスが必要になる。`content` の backing buffer 上の位置から復元する。
 */
function sliceNode(node: Asn1Node): Uint8Array {
  // content は元 buffer の subarray なので byteOffset から header 分だけ手前を含めて切り出す。
  const buf = node.content;
  const headerLen = node.totalLength - node.content.length;
  const start = buf.byteOffset - headerLen;
  const source = new Uint8Array(buf.buffer);
  return source.subarray(start, start + node.totalLength);
}

/** issuer/subject DN の DER バイト列が一致するか（チェーン照合用）。 */
export function derEquals(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) {
    return false;
  }
  for (let i = 0; i < a.length; i++) {
    if (a[i] !== b[i]) {
      return false;
    }
  }
  return true;
}
