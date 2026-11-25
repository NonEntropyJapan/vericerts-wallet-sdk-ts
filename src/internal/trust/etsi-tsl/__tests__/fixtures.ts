/**
 * trust/etsi-tsl テスト用フィクスチャ生成。
 *
 * 本番コードに DER 証明書エンコーダを持ち込まないため、テスト専用の最小 X.509 v3 証明書ビルダと
 * XMLDSig(enveloped) 署名 XML ビルダをここに置く。Node `crypto` で鍵生成・署名し、`parseCertificate`
 * / `verifyXmlDsig` が実際に検証できる本物の DER / 署名を作る。TLV 組み立てと Name のエンコードは
 * `der.ts` に切り出してある。
 */

import { createPublicKey, createSign, generateKeyPairSync, type KeyObject } from 'node:crypto';
import { basicConstraintsExtension, intBytes, name, octetString, oid, tlv } from './der.js';

/** AlgorithmIdentifier SEQUENCE（RSA は NULL params、EC 署名は params 省略）。 */
function algId(algOid: string, withNull: boolean): number[] {
  const content = withNull ? [...oid(algOid), ...tlv(0x05, [])] : oid(algOid);
  return tlv(0x30, content);
}

/** UTCTime（YYMMDDHHMMSSZ）。 */
function utcTime(date: Date): number[] {
  const p = (n: number): string => n.toString().padStart(2, '0');
  const s = `${p(date.getUTCFullYear() % 100)}${p(date.getUTCMonth() + 1)}${p(date.getUTCDate())}${p(date.getUTCHours())}${p(date.getUTCMinutes())}${p(date.getUTCSeconds())}Z`;
  return tlv(0x17, [...Buffer.from(s, 'ascii')]);
}

/** keyUsage に載せられるビット（RFC 5280 §4.2.1.3 のビット位置）。 */
const KEY_USAGE_BITS: Readonly<
  Record<
    'digitalSignature' | 'nonRepudiation' | 'keyEncipherment' | 'keyCertSign' | 'cRLSign',
    number
  >
> = {
  digitalSignature: 0,
  nonRepudiation: 1,
  keyEncipherment: 2,
  keyCertSign: 5,
  cRLSign: 6,
};

/** keyUsage 拡張（OID 2.5.29.15・BIT STRING）。 */
function keyUsageExtension(usages: readonly (keyof typeof KEY_USAGE_BITS)[]): number[] {
  const bits = usages.map((usage) => KEY_USAGE_BITS[usage]);
  const highest = Math.max(...bits, 0);
  const byteCount = Math.floor(highest / 8) + 1;
  const bytes = new Array<number>(byteCount).fill(0);
  for (const bit of bits) {
    const index = Math.floor(bit / 8);
    bytes[index] = (bytes[index] as number) | (0x80 >> (bit % 8));
  }
  const unusedBits = byteCount * 8 - (highest + 1);
  return tlv(0x30, [...oid('2.5.29.15'), ...octetString(tlv(0x03, [unusedBits, ...bytes]))]);
}

/** GeneralName の DER タグ（[2] dNSName / [4] directoryName / [6] URI）。 */
const TAG_GN_DNS = 0x82;
const TAG_GN_DIRECTORY = 0xa4;
const TAG_GN_URI = 0x86;

/** IMPLICIT IA5String な GeneralName（dNSName / URI）。 */
function implicitString(tag: number, text: string): number[] {
  return tlv(tag, [...Buffer.from(text, 'utf8')]);
}

/** subjectAltName 拡張（OID 2.5.29.17）。 */
function subjectAltNameExtension(uris: readonly string[], dnsNames: readonly string[]): number[] {
  const names = [
    ...uris.flatMap((uri) => implicitString(TAG_GN_URI, uri)),
    ...dnsNames.flatMap((dns) => implicitString(TAG_GN_DNS, dns)),
  ];
  return tlv(0x30, [...oid('2.5.29.17'), ...octetString(tlv(0x30, names))]);
}

/** nameConstraints に載せる GeneralSubtrees。 */
export interface NameConstraintsFixture {
  /** permittedSubtrees の URI [6] base。 */
  readonly permittedUris?: readonly string[];
  /** excludedSubtrees の URI [6] base。 */
  readonly excludedUris?: readonly string[];
  /** permittedSubtrees の directoryName [4] base（`CN=<値>` の 1 RDN）。 */
  readonly permittedCns?: readonly string[];
  /** excludedSubtrees の directoryName [4] base（`CN=<値>` の 1 RDN）。 */
  readonly excludedCns?: readonly string[];
  /** permittedSubtrees の dNSName [2] base（実装が評価できない種別のテスト用）。 */
  readonly permittedDnsNames?: readonly string[];
  /** 各 GeneralSubtree に `minimum` を書く（RFC 5280 がエラー扱いを求める形のテスト用）。 */
  readonly minimum?: number;
  /** permittedSubtrees を 0 要素で書く（`SIZE (1..MAX)` 違反のテスト用）。 */
  readonly emptyPermitted?: boolean;
}

/** `GeneralSubtree ::= SEQUENCE { base GeneralName, minimum [0] DEFAULT 0, maximum [1] OPTIONAL }`。 */
function generalSubtree(base: number[], minimum: number | undefined): number[] {
  return tlv(0x30, [...base, ...(minimum === undefined ? [] : tlv(0x80, [minimum]))]);
}

/**
 * GeneralSubtrees を [0] / [1] の IMPLICIT タグで書く。
 *
 * RFC 5280 の ASN.1 モジュールは IMPLICIT TAGS なので、`GeneralSubtrees ::= SEQUENCE OF
 * GeneralSubtree` の SEQUENCE タグが [0] / [1] に置き換わる。つまり 0xa0 / 0xa1 の content は
 * GeneralSubtree（0x30）の並びそのもので、**内側に 0x30 のラッパは入らない**。実装
 * （`trust/x509/name-constraints.ts`）も同じ読み方をする。
 */
function generalSubtrees(tag: number, subtrees: readonly number[][]): number[] {
  return tlv(tag, subtrees.flat());
}

/** nameConstraints 拡張（OID 2.5.29.30）。 */
function nameConstraintsExtension(nc: NameConstraintsFixture): number[] {
  const subtree = (base: number[]): number[] => generalSubtree(base, nc.minimum);
  const permitted = [
    ...(nc.permittedUris ?? []).map((uri) => subtree(implicitString(TAG_GN_URI, uri))),
    ...(nc.permittedCns ?? []).map((cn) => subtree(tlv(TAG_GN_DIRECTORY, name(cn)))),
    ...(nc.permittedDnsNames ?? []).map((dns) => subtree(implicitString(TAG_GN_DNS, dns))),
  ];
  const excluded = [
    ...(nc.excludedUris ?? []).map((uri) => subtree(implicitString(TAG_GN_URI, uri))),
    ...(nc.excludedCns ?? []).map((cn) => subtree(tlv(TAG_GN_DIRECTORY, name(cn)))),
  ];
  const value = [
    ...(permitted.length > 0 || nc.emptyPermitted === true ? generalSubtrees(0xa0, permitted) : []),
    ...(excluded.length > 0 ? generalSubtrees(0xa1, excluded) : []),
  ];
  return tlv(0x30, [...oid('2.5.29.30'), ...octetString(tlv(0x30, value))]);
}

/** 中身を持たない拡張を任意の OID・critical 指定で載せる（criticality 検査のテスト用）。 */
function opaqueExtension(extOid: string, critical: boolean): number[] {
  const criticalField = critical ? tlv(0x01, [0xff]) : [];
  return tlv(0x30, [...oid(extOid), ...criticalField, ...octetString(tlv(0x05, []))]);
}

/** extensions [3] EXPLICIT SEQUENCE OF Extension（1 件も無ければ空）。 */
function buildExtensions(opts: CertExtensionOptions): number[] {
  const exts: number[] = [];
  if (opts.ca !== undefined) {
    exts.push(...basicConstraintsExtension(opts.ca, opts.pathLen));
  }
  if (opts.duplicateBasicConstraints === true) {
    exts.push(...basicConstraintsExtension(opts.ca ?? true));
  }
  if (opts.keyUsage !== undefined) {
    exts.push(...keyUsageExtension(opts.keyUsage));
  }
  if (opts.sanUris !== undefined || opts.sanDnsNames !== undefined) {
    exts.push(...subjectAltNameExtension(opts.sanUris ?? [], opts.sanDnsNames ?? []));
  }
  if (opts.nameConstraints !== undefined) {
    exts.push(...nameConstraintsExtension(opts.nameConstraints));
  }
  if (opts.criticalExtensionOid !== undefined) {
    exts.push(...opaqueExtension(opts.criticalExtensionOid, true));
  }
  if (opts.nonCriticalExtensionOid !== undefined) {
    exts.push(...opaqueExtension(opts.nonCriticalExtensionOid, false));
  }
  return exts.length === 0 ? [] : tlv(0xa3, tlv(0x30, exts));
}

/**
 * CA 制約まわりの拡張を証明書に載せるオプション。
 *
 * どれも**省略すると拡張そのものを付けない**。RFC 5280 は CA 証明書に basicConstraints を
 * 要求するので、省略した証明書は「CA を名乗っていない」= 中間として使えない証明書になる。
 */
export interface CertExtensionOptions {
  /** basicConstraints を付ける（`true` なら `cA:TRUE`、`false` なら `cA:FALSE`）。 */
  readonly ca?: boolean;
  /** basicConstraints に pathLenConstraint を載せる（`ca` 未指定のときは無視される）。 */
  readonly pathLen?: number;
  /** keyUsage を付ける（挙げたビットだけを立てる）。 */
  readonly keyUsage?: readonly (keyof typeof KEY_USAGE_BITS)[];
  /** subjectAltName に uniformResourceIdentifier [6] を載せる。 */
  readonly sanUris?: readonly string[];
  /** subjectAltName に dNSName [2] を載せる（実装が評価できない種別のテスト用）。 */
  readonly sanDnsNames?: readonly string[];
  /** nameConstraints を載せる（配下へ課す名前空間の制限）。 */
  readonly nameConstraints?: NameConstraintsFixture;
  /** この OID の拡張を `critical:TRUE` で載せる（RFC 5280 §6.1.4 (f) のテスト用）。 */
  readonly criticalExtensionOid?: string;
  /** この OID の拡張を `critical` 無しで載せる（上と対にして criticality の効きを見る）。 */
  readonly nonCriticalExtensionOid?: string;
  /** basicConstraints を 2 度載せる（同一 OID の重複を fail-closed に倒すテスト用）。 */
  readonly duplicateBasicConstraints?: boolean;
}

/** テスト用に生成した証明書 + 鍵一式。 */
export interface CertFixture {
  /** 証明書 DER。 */
  readonly der: Uint8Array;
  /** 証明書に対応する秘密鍵（子証明書の署名に使える）。 */
  readonly privateKey: KeyObject;
  /** subject Name（DER・子証明書の issuer に使う）。 */
  readonly subjectName: number[];
}

/** RSA / EC の鍵ペアを生成する。 */
function genKeyPair(kind: 'rsa' | 'ec'): { privateKey: KeyObject; publicKey: KeyObject } {
  return kind === 'rsa'
    ? generateKeyPairSync('rsa', { modulusLength: 2048 })
    : generateKeyPairSync('ec', { namedCurve: 'P-256' });
}

/**
 * 最小 X.509 v3 証明書を生成する。issuer が未指定なら自己署名。
 *
 * @param opts CN・鍵種別・有効期間・発行者（未指定で自己署名）・subject 鍵の再利用。
 */
export function makeCertificate(
  opts: CertExtensionOptions & {
    cn: string;
    kind: 'rsa' | 'ec';
    notBefore?: Date;
    notAfter?: Date;
    issuer?: { name: number[]; privateKey: KeyObject; kind: 'rsa' | 'ec' };
    /**
     * subject 鍵として再利用する秘密鍵（公開鍵はここから導出する）。CA 証明書の更新
     * （鍵はそのままで有効期間だけ延ばした新証明書）を再現するためのオプション。
     */
    subjectKey?: KeyObject;
  },
): CertFixture {
  const { privateKey, publicKey } =
    opts.subjectKey === undefined
      ? genKeyPair(opts.kind)
      : { privateKey: opts.subjectKey, publicKey: createPublicKey(opts.subjectKey) };
  const subjectName = name(opts.cn);
  const issuerName = opts.issuer?.name ?? subjectName;
  const signerKey = opts.issuer?.privateKey ?? privateKey;
  const signerKind = opts.issuer?.kind ?? opts.kind;
  const sigAlgOid = signerKind === 'rsa' ? '1.2.840.113549.1.1.11' : '1.2.840.10045.4.3.2';
  const spki = [...publicKey.export({ type: 'spki', format: 'der' })];
  const nb = opts.notBefore ?? new Date(Date.now() - 86_400_000);
  const na = opts.notAfter ?? new Date(Date.now() + 86_400_000);

  const tbsContent = [
    ...tlv(0xa0, intBytes(2)), // version [0] EXPLICIT v3(=2)
    ...intBytes(1), // serialNumber
    ...algId(sigAlgOid, signerKind === 'rsa'), // signature
    ...issuerName,
    ...tlv(0x30, [...utcTime(nb), ...utcTime(na)]), // validity
    ...subjectName,
    ...spki, // subjectPublicKeyInfo
    ...buildExtensions(opts),
  ];
  const tbs = tlv(0x30, tbsContent);

  const signer = createSign('SHA256');
  signer.update(Buffer.from(tbs));
  signer.end();
  const signature = signer.sign(
    signerKind === 'rsa' ? signerKey : { key: signerKey, dsaEncoding: 'der' },
  );
  const sigBitString = tlv(0x03, [0x00, ...signature]);

  const cert = tlv(0x30, [...tbs, ...algId(sigAlgOid, signerKind === 'rsa'), ...sigBitString]);
  return { der: Uint8Array.from(cert), privateKey, subjectName };
}
