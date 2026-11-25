/**
 * X.509 証明書パース用の最小 DER（ASN.1）リーダ（trust/etsi-tsl）。
 *
 * ETSI Trusted List の Qualified Certificate チェーン検証に必要な範囲のみを扱う。汎用 ASN.1
 * ライブラリは導入せず（依存最小化・`sideEffects: false` の browser バンドル維持）、TLV
 * (Tag-Length-Value) の読み取りに限定した小さなパーサを提供する。`x509.ts` から利用する。
 *
 * セキュリティ上の注意:
 * - 例外メッセージや `context` に証明書本文・鍵素材を含めない。
 *   パース失敗はすべて呼び出し側で `QUALIFIED_CERT_INVALID` に正規化する前提で `Asn1Error`
 *   を投げる。
 */

/** DER パース失敗を表す内部エラー。呼び出し側で VericertsError に正規化する。 */
export class Asn1Error extends Error {}

/** DER の 1 要素（TLV）。`tag` はクラス/構造ビット込みの生タグ、`content` は値部のみ。 */
export interface Asn1Node {
  /** 生のタグバイト（例: SEQUENCE=0x30, INTEGER=0x02）。 */
  readonly tag: number;
  /** 値部のバイト列（length ヘッダを除く）。 */
  readonly content: Uint8Array;
  /** この要素全体（tag + length + content）のバイト長。 */
  readonly totalLength: number;
}

/** 1 バイト長で表現できる最大値（0x80 以上は long-form length）。 */
const SHORT_FORM_MAX = 0x7f;
/** long-form length の最初のバイトに立つビット。 */
const LONG_FORM_FLAG = 0x80;

/**
 * パースを受け付ける DER 全体の最大バイト長。実在の X.509 証明書は数 KB（SAN を数百件持つ
 * 証明書でも 32 KiB 未満）。TSL / LOTL の KeyInfo は XML 長（8 MiB）まで、`x5c` は JWT の 1 MiB まで
 * 攻撃者が長い DER を置けるため、アンカー検証より前のこの入口で縛る。
 * `readNode` に渡る `bytes` の長さに効くので、子ノードの `content` を渡す再帰的な読み取りも同じ検査を
 * 通る（トップレベルが通れば、より短い子は必ず通る）。ノード総数は `MAX_DER_BYTES / 2` 以下に収まる。
 */
export const MAX_DER_BYTES = 64 * 1024;

/**
 * 1 つの構造型ノードが持てる子要素の最大数。AlgorithmIdentifier は 2、TBSCertificate は約 10、
 * 拡張は数十、SAN の GeneralName は数百。上限一杯でも `Asn1Node` 配列は約 0.4 MB に収まる。
 */
export const MAX_ASN1_CHILDREN = 4096;

/**
 * `bytes` の `offset` 位置から 1 つの TLV をパースする。
 *
 * @param bytes DER バイト列。
 * @param offset 開始オフセット。
 * @returns パースした要素。`totalLength` は常に 2 以上、かつ `offset + totalLength` は `bytes.length` 以下。
 * @throws バッファ範囲外 / 未対応・非最短 length 形式の場合（Asn1Error）。
 */
export function readNode(bytes: Uint8Array, offset = 0): Asn1Node {
  if (bytes.length > MAX_DER_BYTES) {
    // パーサの入口で入力全体の大きさを縛る。ノード数は入力長 / 2 以下なので、子の個数上限
    // （`MAX_ASN1_CHILDREN`）と併せて、1 通のパースで確保するノード総数に決定的な上限が付く。
    throw new Asn1Error('DER: input too large');
  }
  if (offset + 2 > bytes.length) {
    throw new Asn1Error('DER: truncated header');
  }
  const tag = bytes[offset] as number;
  const firstLen = bytes[offset + 1] as number;
  let length: number;
  let headerLength: number;
  if (firstLen <= SHORT_FORM_MAX) {
    length = firstLen;
    headerLength = 2;
  } else {
    const numBytes = firstLen & ~LONG_FORM_FLAG;
    if (numBytes === 0 || numBytes > 4) {
      // 不定長（0x80）および 4 バイト超の length は証明書では扱わない。
      throw new Asn1Error('DER: unsupported length form');
    }
    if (offset + 2 + numBytes > bytes.length) {
      throw new Asn1Error('DER: truncated length');
    }
    // 符号なしで組み立てる。`<<` / `|` は 32bit 符号付きで、4 バイト length の最上位ビットが立つと
    // 負数になり、`totalLength` が 0 以下のノードで `readChildren` が前進せず無限ループした。
    length = 0;
    for (let i = 0; i < numBytes; i++) {
      length = length * 256 + (bytes[offset + 2 + i] as number);
    }
    if (bytes[offset + 2] === 0 || length <= SHORT_FORM_MAX) {
      // DER は最短の length 表現を要求する（先頭 0x00・short-form で足りる値の long-form は不正）。
      throw new Asn1Error('DER: non-minimal length');
    }
    headerLength = 2 + numBytes;
  }
  const contentStart = offset + headerLength;
  if (length > bytes.length - contentStart) {
    throw new Asn1Error('DER: content overruns buffer');
  }
  return {
    tag,
    content: bytes.subarray(contentStart, contentStart + length),
    totalLength: headerLength + length,
  };
}

/**
 * SEQUENCE / SET など構造型の子要素をすべて読み出す。
 *
 * 子要素数は `MAX_ASN1_CHILDREN` で縛る。`05 00`（NULL、2 バイト）のような最小の子を並べるだけで、
 * 1 バイトあたり約 100 バイトの `Asn1Node` を確保させられる（290 万個で RSS 約 840 MB）。
 * 上限を超えたら、それ以上の子を読み出す前に拒否する。
 *
 * @param node 構造型ノード（content が連続した TLV）。
 * @returns 子ノードの配列。
 * @throws 子要素のパースに失敗した場合・子要素数が上限を超えた場合（Asn1Error）。
 */
export function readChildren(node: Asn1Node): Asn1Node[] {
  const children: Asn1Node[] = [];
  let pos = 0;
  while (pos < node.content.length) {
    if (children.length >= MAX_ASN1_CHILDREN) {
      throw new Asn1Error('DER: too many child nodes');
    }
    const child = readNode(node.content, pos);
    if (child.totalLength < 2) {
      // 前進しないループの構造的な禁止（`readNode` は常に 2 以上を返すが、不変条件として保証する）。
      throw new Asn1Error('DER: non-advancing node');
    }
    children.push(child);
    pos += child.totalLength;
  }
  return children;
}

/** `value * 128 + 127` が安全整数に収まる `value` の上限。 */
const MAX_ARC_BEFORE_SHIFT = Math.floor((Number.MAX_SAFE_INTEGER - 0x7f) / 0x80);

/**
 * OBJECT IDENTIFIER の content を dotted-decimal 文字列に変換する。
 *
 * 各 arc は base-128（上位ビット = 継続）。符号付き 32bit の `<<` で上位ビットが落ちて長大 arc が
 * 小さな既知 OID に化けないよう、安全整数の乗算で組み立て、2^53 を超える arc・非最短（先頭 `0x80`）・
 * 未終端の OID は拒否する。第 1 subidentifier は 40*X+Y で、X=2 のとき Y は 40 以上を取れる。
 *
 * @param content OID の値部（tag/length を除く）。
 * @returns 例 `"1.2.840.113549.1.1.11"`（sha256WithRSAEncryption）。
 * @throws content が空 / 未終端 / 非最短 / arc が安全整数を超える場合（Asn1Error）。
 */
export function decodeOid(content: Uint8Array): string {
  if (content.length === 0) {
    throw new Asn1Error('DER: empty OID');
  }
  const arcs: number[] = [];
  let value = 0;
  let inArc = false;
  for (const byte of content) {
    if (!inArc && byte === 0x80) {
      throw new Asn1Error('DER: non-minimal OID arc');
    }
    if (value > MAX_ARC_BEFORE_SHIFT) {
      throw new Asn1Error('DER: OID arc too large');
    }
    value = value * 0x80 + (byte & 0x7f);
    inArc = true;
    if ((byte & 0x80) === 0) {
      arcs.push(value);
      value = 0;
      inArc = false;
    }
  }
  if (inArc) {
    throw new Asn1Error('DER: unterminated OID arc');
  }
  const [head, ...rest] = arcs as [number, ...number[]];
  const top = head < 40 ? 0 : head < 80 ? 1 : 2;
  return [top, head - top * 40, ...rest].join('.');
}
