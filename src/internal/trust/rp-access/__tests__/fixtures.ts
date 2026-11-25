/**
 * trust/rp-access テスト用フィクスチャ生成。
 *
 * RP Access Certificate 検証を実データで確認するため、Subject DN 属性（organizationName /
 * organizationIdentifier / countryName）・SubjectAltName（URI）・SubjectDirectoryAttributes
 * 拡張（認可属性 / 目的 / カテゴリ）を含む本物の X.509 v3 DER を Node `crypto` で署名生成する。
 * 本番コードに DER エンコーダを持ち込まないためのテスト専用ビルダ。TLV 組み立て・OID・
 * basicConstraints といった汎用部品は `etsi-tsl/__tests__/der.ts` に 1 つだけ置いてあるので、
 * ここではそれを import して RP 固有の拡張（SubjectDirectoryAttributes 等）だけを組む。
 */

import { createSign, generateKeyPairSync, type KeyObject } from 'node:crypto';
import {
  basicConstraintsExtension,
  encodeLength,
  intBytes,
  octetString,
  oid,
  tlv,
} from '../../etsi-tsl/__tests__/der.js';
import { RP_ACCESS_ATTR_OIDS } from '../cert.js';

/** AlgorithmIdentifier。 */
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

/** UTF8String。 */
function utf8(value: string): number[] {
  return tlv(0x0c, [...Buffer.from(value, 'utf8')]);
}

/** AttributeTypeAndValue（type OID + UTF8 value）を単一 RDN(SET) にする。 */
function rdn(typeOid: string, value: string): number[] {
  const atv = tlv(0x30, [...oid(typeOid), ...utf8(value)]);
  return tlv(0x31, atv);
}

/** RP の識別属性を持つ Name を作る。 */
export interface RpNameParts {
  readonly organizationName?: string;
  readonly organizationIdentifier?: string;
  readonly country?: string;
  readonly commonName?: string;
}

/** Name（RDNSequence）を組み立てる。 */
function buildName(parts: RpNameParts): number[] {
  const rdns: number[] = [];
  if (parts.country !== undefined) {
    rdns.push(...rdn('2.5.4.6', parts.country));
  }
  if (parts.organizationName !== undefined) {
    rdns.push(...rdn('2.5.4.10', parts.organizationName));
  }
  if (parts.organizationIdentifier !== undefined) {
    rdns.push(...rdn('2.5.4.97', parts.organizationIdentifier));
  }
  if (parts.commonName !== undefined) {
    rdns.push(...rdn('2.5.4.3', parts.commonName));
  }
  return tlv(0x30, rdns);
}

/** SET OF UTF8String。 */
function utf8Set(values: readonly string[]): number[] {
  return tlv(
    0x31,
    values.flatMap((v) => utf8(v)),
  );
}

/** 1 件の SubjectDirectoryAttributes Attribute（type + values SET）。 */
function attribute(typeOid: string, values: readonly string[]): number[] {
  return tlv(0x30, [...oid(typeOid), ...utf8Set(values)]);
}

/** RP の認可スコープ。 */
export interface AuthorizedScopeParts {
  readonly attributes?: readonly string[];
  readonly purposes?: readonly string[];
  readonly categories?: readonly string[];
}

/** SubjectDirectoryAttributes 拡張（OID 2.5.29.9）を組み立てる。 */
function subjectDirAttrsExtension(scope: AuthorizedScopeParts): number[] {
  const attrs: number[] = [];
  if (scope.attributes !== undefined) {
    attrs.push(...attribute(RP_ACCESS_ATTR_OIDS.authorizedAttributes, scope.attributes));
  }
  if (scope.purposes !== undefined) {
    attrs.push(...attribute(RP_ACCESS_ATTR_OIDS.authorizedPurposes, scope.purposes));
  }
  if (scope.categories !== undefined) {
    attrs.push(...attribute(RP_ACCESS_ATTR_OIDS.authorizedCategories, scope.categories));
  }
  const seq = tlv(0x30, attrs);
  return tlv(0x30, [...oid('2.5.29.9'), ...octetString(seq)]);
}

/** SubjectAltName 拡張（OID 2.5.29.17・URI [6]）を組み立てる。 */
function subjectAltNameExtension(uri: string): number[] {
  const generalNames = tlv(0x30, [0x86, ...encodeLength(uri.length), ...Buffer.from(uri, 'ascii')]);
  return tlv(0x30, [...oid('2.5.29.17'), ...octetString(generalNames)]);
}

/**
 * SubjectDirectoryAttributes 拡張の `extnValue` を**そのまま**書く（構造不正の再現用）。
 *
 * SEQUENCE でない中身を渡せるようにするためのフックで、`extractScope` が
 * `readChildren` へ素通しすると任意形状のバイト列が認可スコープに化けることを固定する。
 */
function rawSubjectDirAttrsExtension(value: number[]): number[] {
  return tlv(0x30, [...oid('2.5.29.9'), ...octetString(value)]);
}

/** extensions [3] EXPLICIT SEQUENCE OF Extension。 */
function buildExtensions(
  scope: AuthorizedScopeParts,
  origin: string | undefined,
  ca: boolean | undefined,
  rawScopeExtnValue: number[] | undefined,
): number[] {
  const exts: number[] = [];
  if (ca !== undefined) {
    exts.push(...basicConstraintsExtension(ca));
  }
  if (origin !== undefined) {
    exts.push(...subjectAltNameExtension(origin));
  }
  if (rawScopeExtnValue !== undefined) {
    exts.push(...rawSubjectDirAttrsExtension(rawScopeExtnValue));
  } else if (
    scope.attributes !== undefined ||
    scope.purposes !== undefined ||
    scope.categories !== undefined
  ) {
    exts.push(...subjectDirAttrsExtension(scope));
  }
  if (exts.length === 0) {
    return [];
  }
  return tlv(0xa3, tlv(0x30, exts));
}

/** 鍵ペア生成。 */
function genKeyPair(kind: 'rsa' | 'ec'): { privateKey: KeyObject; publicKey: KeyObject } {
  return kind === 'rsa'
    ? generateKeyPairSync('rsa', { modulusLength: 2048 })
    : generateKeyPairSync('ec', { namedCurve: 'P-256' });
}

/** 生成した証明書 + 鍵。 */
export interface RpCertFixture {
  readonly der: Uint8Array;
  readonly privateKey: KeyObject;
  readonly subjectName: number[];
}

/** RP Access Certificate（もしくは CA）フィクスチャの生成オプション。 */
export interface MakeRpCertOptions {
  readonly subject: RpNameParts;
  readonly kind: 'rsa' | 'ec';
  readonly origin?: string;
  readonly scope?: AuthorizedScopeParts;
  readonly notBefore?: Date;
  readonly notAfter?: Date;
  readonly serial?: number;
  /** basicConstraints を付ける（`true` なら `cA:TRUE`）。中間 CA として使う証明書に指定する。 */
  readonly ca?: boolean;
  /**
   * SubjectDirectoryAttributes の `extnValue` を生バイト列で差し替える（`scope` より優先）。
   * SEQUENCE でない `extnValue` を持つ証明書を組むためのテスト専用フック。
   */
  readonly rawScopeExtnValue?: number[];
  readonly issuer?: { name: number[]; privateKey: KeyObject; kind: 'rsa' | 'ec' };
}

/**
 * RP Access Certificate（拡張・DN 属性付き X.509 v3）を生成する。issuer 未指定なら自己署名。
 */
export function makeRpCertificate(opts: MakeRpCertOptions): RpCertFixture {
  const { privateKey, publicKey } = genKeyPair(opts.kind);
  const subjectName = buildName(opts.subject);
  const issuerName = opts.issuer?.name ?? subjectName;
  const signerKey = opts.issuer?.privateKey ?? privateKey;
  const signerKind = opts.issuer?.kind ?? opts.kind;
  const sigAlgOid = signerKind === 'rsa' ? '1.2.840.113549.1.1.11' : '1.2.840.10045.4.3.2';
  const spki = [...publicKey.export({ type: 'spki', format: 'der' })];
  const nb = opts.notBefore ?? new Date(Date.now() - 86_400_000);
  const na = opts.notAfter ?? new Date(Date.now() + 86_400_000);

  const tbsContent = [
    ...tlv(0xa0, intBytes(2)), // version [0] v3
    ...intBytes(opts.serial ?? 1), // serialNumber
    ...algId(sigAlgOid, signerKind === 'rsa'),
    ...issuerName,
    ...tlv(0x30, [...utcTime(nb), ...utcTime(na)]),
    ...subjectName,
    ...spki,
    ...buildExtensions(opts.scope ?? {}, opts.origin, opts.ca, opts.rawScopeExtnValue),
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
