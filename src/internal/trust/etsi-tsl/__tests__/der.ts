/**
 * テスト用の最小 DER エンコーダ（trust/etsi-tsl フィクスチャ共通部品）。
 *
 * 証明書ビルダ（`fixtures.ts`）と、拡張の中身だけを直接組み立てたいユニットテスト
 * （`trust/x509/__tests__`）の双方から使うため、TLV 組み立てと Name のエンコードをここに切り出す。
 * 本番コードに DER エンコーダを持ち込まない方針は `fixtures.ts` と同じで、置き場所を分けただけである
 * （1 ファイル 300 行の上限に収めるための分割）。
 */

/** DER length を short/long form でエンコードする。 */
export function encodeLength(len: number): number[] {
  if (len < 0x80) {
    return [len];
  }
  const bytes: number[] = [];
  let n = len;
  while (n > 0) {
    bytes.unshift(n & 0xff);
    n >>= 8;
  }
  return [0x80 | bytes.length, ...bytes];
}

/** TLV を組み立てる。 */
export function tlv(tag: number, content: number[]): number[] {
  return [tag, ...encodeLength(content.length), ...content];
}

/** INTEGER（正の値・先頭ビット対策の 0x00 付与）。 */
export function intBytes(value: number): number[] {
  const bytes: number[] = [];
  let n = value;
  do {
    bytes.unshift(n & 0xff);
    n >>= 8;
  } while (n > 0);
  if ((bytes[0] as number) & 0x80) {
    bytes.unshift(0x00);
  }
  return tlv(0x02, bytes);
}

/** OID を DER エンコードする（dotted → bytes）。 */
export function oid(dotted: string): number[] {
  const parts = dotted.split('.').map((p) => Number.parseInt(p, 10));
  const first = (parts[0] as number) * 40 + (parts[1] as number);
  const body: number[] = [first];
  for (let i = 2; i < parts.length; i++) {
    let v = parts[i] as number;
    const stack: number[] = [v & 0x7f];
    v >>= 7;
    while (v > 0) {
      stack.unshift((v & 0x7f) | 0x80);
      v >>= 7;
    }
    body.push(...stack);
  }
  return tlv(0x06, body);
}

/** OCTET STRING でラップする（Extension.extnValue）。 */
export function octetString(content: number[]): number[] {
  return tlv(0x04, content);
}

/**
 * basicConstraints 拡張（OID 2.5.29.19）。`ca` が true なら `cA:TRUE`。
 *
 * `BasicConstraints ::= SEQUENCE { cA BOOLEAN DEFAULT FALSE, pathLenConstraint INTEGER (0..MAX)
 * OPTIONAL }` なので、`pathLen` を渡すと `cA` の BOOLEAN の後ろに INTEGER を置く。`cA:FALSE` は
 * DEFAULT なので本来省略するが、「拡張はあるが CA ではない」証明書を作れるよう明示的に書く。
 *
 * `etsi-tsl` と `rp-access` の双方のフィクスチャが中間 CA 証明書を組むのに要るため、ここに 1 つだけ
 * 置く（両方に写すと、片方だけ pathLen に対応しているような食い違いが生まれる）。
 */
export function basicConstraintsExtension(ca: boolean, pathLen?: number): number[] {
  const inner = [
    ...tlv(0x01, [ca ? 0xff : 0x00]),
    ...(pathLen === undefined ? [] : intBytes(pathLen)),
  ];
  return tlv(0x30, [...oid('2.5.29.19'), ...octetString(tlv(0x30, inner))]);
}

/** commonName の属性型 OID。 */
const OID_COMMON_NAME = '2.5.4.3';

/** UTF8String の DER タグ（`name` の既定）。 */
const TAG_UTF8_STRING = 0x0c;
/** BMPString の DER タグ（UTF-16BE。名前正規化の未対応表現テスト用）。 */
const TAG_BMP_STRING = 0x1e;

/**
 * 属性値を指定タグでエンコードする。
 *
 * BMPString は UTF-16BE、それ以外（UTF8String / PrintableString / IA5String …）は UTF-8 として
 * 書く。PrintableString の文字集合検査はしない（テストで使う値は ASCII に限る）。
 */
function attributeValue(text: string, tag: number): number[] {
  if (tag !== TAG_BMP_STRING) {
    return tlv(tag, [...Buffer.from(text, 'utf8')]);
  }
  const bytes: number[] = [];
  for (let i = 0; i < text.length; i++) {
    const unit = text.charCodeAt(i);
    bytes.push(unit >> 8, unit & 0xff);
  }
  return tlv(tag, bytes);
}

/**
 * `CN=<cn>` 1 RDN の Name（RDNSequence）を、属性値の文字列型タグを指定して組み立てる。
 *
 * 名前制約の照合が「同じ名前を別の文字列型で書き直す」回避を許さないことを確かめるために、
 * PrintableString(0x13) / UTF8String(0x0c) / BMPString(0x1e) を作り分けられるようにしている。
 */
export function dnWithTag(cn: string, tag: number): number[] {
  const attr = tlv(0x30, [...oid(OID_COMMON_NAME), ...attributeValue(cn, tag)]);
  return tlv(0x30, tlv(0x31, attr));
}

/** 簡易 Name（1 RDN・CN=文字列・UTF8String）。 */
export function name(cn: string): number[] {
  return dnWithTag(cn, TAG_UTF8_STRING);
}
