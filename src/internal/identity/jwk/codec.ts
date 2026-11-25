/**
 * did:jwk の JWK バリデーション・用途分類・DID/DID Document の符号化ヘルパ。
 *
 * メソッドプラグイン（`method-jwk.ts`）から共有される純粋関数群
 * （1 ファイル 300 行以下のため分割）。
 *
 * base64url のエンコード/デコードは `@scure/base` の `base64urlnopad`（パディングなし）に委ねる。
 * did:jwk の識別子はパディングなし base64url で構成する（W3C did:jwk Method Specification）。
 *
 * セキュリティ上の注意:
 * - 例外メッセージや `context` に DID 文字列・JWK・鍵バイトなどの入力データを含めない。
 *   秘密鍵パラメータ（`d`）は公開 JWK に含めない前提とする。
 */

import { base64urlnopad } from '@scure/base';
import { ErrorCodes, VericertsError } from '../../errors.js';
import { ownProperty } from '../../prototype-safety/own-property.js';
import { parseJsonWithoutPrototype } from '../../prototype-safety/parse-json.js';
import type { DIDDocument, PublicKeyJwk, VerificationMethod } from '../did.js';

/** `did:jwk:` メソッドプレフィックス。 */
export const DID_JWK_PREFIX = 'did:jwk:';

/** did:jwk の VerificationMethod type（全鍵タイプ共通）。 */
const VERIFICATION_METHOD_TYPE = 'JsonWebKey2020';

/** did:jwk DID Document の JSON-LD コンテキスト。 */
const DID_JWK_CONTEXT: readonly string[] = [
  'https://www.w3.org/ns/did/v1',
  'https://w3id.org/security/suites/jws-2020/v1',
];

/** 対応する EC 曲線（kty=EC）。 */
const EC_CURVES = new Set(['P-256', 'P-384']);
/** 対応する OKP 曲線（kty=OKP）。 */
const OKP_CURVES = new Set(['Ed25519', 'X25519']);

/**
 * JWK の用途分類。verification relationship の付与を決めるために使う。
 *
 * - `signing`: 署名向き（authentication / assertionMethod / capability*）。
 * - `keyAgreement`: 鍵交換向き（keyAgreement）。
 */
export interface KeyUsage {
  /** 署名向き relationship を付与するか。 */
  readonly signing: boolean;
  /** keyAgreement を付与するか。 */
  readonly keyAgreement: boolean;
}

/**
 * 公開鍵 JWK を最小限バリデーションし、kty/crv と `use` から用途を判定する。
 *
 * - kty=EC は crv ∈ {P-256, P-384}、x/y を要求。
 * - kty=OKP は crv ∈ {Ed25519, X25519}、x を要求。
 * - 秘密鍵パラメータ `d` を含む JWK は公開鍵として不正（DID 形式不正）。
 * - `use`（`sig` / `enc`）が指定されていれば用途を限定する。X25519 は鍵交換専用、
 *   Ed25519 は署名専用のため、`use` と矛盾する場合は不正とする。
 *
 * JWK メンバ（`d` / `kty` / `crv` / `use` / `x` / `y`）は**自身のプロパティ**としてのみ読み、
 * 継承したメンバは「存在しない」として扱う。`resolveDidJwk` 経由の JWK は
 * `decodeDidJwk`（`parseJsonWithoutPrototype`）由来で `null` プロトタイプだが、公開 API の
 * `createDidJwk` は呼び出し側が組んだ plain object をそのまま受け取るため `Object.prototype` を
 * 継承する。鎖読みだと、汚染下で `kty` / `crv` / `x` / `y` を**欠く JWK が継承値で補われて受理**され、
 * `use` 未指定の鍵の用途が**継承値で書き換え**られ、逆に `d` の不在チェックは
 * `Object.prototype.d` を拾って**正当な公開鍵 JWK を誤って拒否**する（DoS）。
 *
 * @param jwk 公開鍵 JWK。
 * @returns 用途分類。
 * @throws kty/crv 未対応・必須メンバ欠落・秘密鍵混入・use 矛盾の場合（VericertsError、code `2001`）。
 */
export function classifyKeyUsage(jwk: PublicKeyJwk): KeyUsage {
  // 秘密鍵パラメータは公開鍵表現に含めない（自身のプロパティとして含まれていれば不正）。
  if (Object.hasOwn(jwk, 'd')) {
    throw new VericertsError(ErrorCodes.INVALID_DID);
  }
  const kty = ownProperty<unknown>(jwk, 'kty');
  const crv = ownProperty<unknown>(jwk, 'crv');
  const use = ownProperty<unknown>(jwk, 'use');
  const x = ownProperty<unknown>(jwk, 'x');
  const y = ownProperty<unknown>(jwk, 'y');
  if (use !== undefined && use !== 'sig' && use !== 'enc') {
    throw new VericertsError(ErrorCodes.INVALID_DID);
  }

  if (kty === 'EC') {
    if (typeof crv !== 'string' || !EC_CURVES.has(crv)) {
      throw new VericertsError(ErrorCodes.INVALID_DID);
    }
    if (typeof x !== 'string' || typeof y !== 'string') {
      throw new VericertsError(ErrorCodes.INVALID_DID);
    }
    // EC は署名・鍵交換の両方が可能。use があれば一方に限定する。
    return {
      signing: use !== 'enc',
      keyAgreement: use !== 'sig',
    };
  }

  if (kty === 'OKP') {
    if (typeof crv !== 'string' || !OKP_CURVES.has(crv)) {
      throw new VericertsError(ErrorCodes.INVALID_DID);
    }
    if (typeof x !== 'string') {
      throw new VericertsError(ErrorCodes.INVALID_DID);
    }
    if (crv === 'Ed25519') {
      // Ed25519 は署名専用。use=enc は矛盾。
      if (use === 'enc') {
        throw new VericertsError(ErrorCodes.INVALID_DID);
      }
      return { signing: true, keyAgreement: false };
    }
    // X25519 は鍵交換専用。use=sig は矛盾。
    if (use === 'sig') {
      throw new VericertsError(ErrorCodes.INVALID_DID);
    }
    return { signing: false, keyAgreement: true };
  }

  throw new VericertsError(ErrorCodes.INVALID_DID);
}

/**
 * 公開鍵 JWK から did:jwk の DID 文字列を構築する。
 *
 * JWK を JSON 文字列化し、UTF-8 バイト列を base64url（パディングなし）でエンコードする。
 *
 * @param jwk 公開鍵 JWK。
 * @returns did:jwk DID 文字列。
 */
export function encodeDidJwk(jwk: PublicKeyJwk): string {
  const json = JSON.stringify(jwk);
  const encoded = base64urlnopad.encode(new TextEncoder().encode(json));
  return `${DID_JWK_PREFIX}${encoded}`;
}

/**
 * 用途分類と DID から DID Document を組み立てる。
 *
 * VerificationMethod は常に 1 件（`#0`）。relationship は用途に応じて付与する。
 *
 * @param did DID 文字列（`did:jwk:<encoded>`）。
 * @param jwk publicKeyJwk に格納する公開鍵 JWK。
 * @param usage 用途分類。
 * @returns DID Document。
 */
export function buildDidDocument(did: string, jwk: PublicKeyJwk, usage: KeyUsage): DIDDocument {
  const methodId = `${did}#0`;
  const verificationMethod: VerificationMethod = {
    id: methodId,
    type: VERIFICATION_METHOD_TYPE,
    controller: did,
    publicKeyJwk: jwk,
  };
  const doc: {
    '@context': readonly string[];
    id: string;
    verificationMethod: readonly VerificationMethod[];
    authentication: readonly string[];
    assertionMethod: readonly string[];
    capabilityInvocation?: readonly string[];
    capabilityDelegation?: readonly string[];
    keyAgreement?: readonly string[];
  } = {
    '@context': DID_JWK_CONTEXT,
    id: did,
    verificationMethod: [verificationMethod],
    // authentication / assertionMethod は DIDDocument 型で必須のため常に定義する。
    // 署名向きでない鍵（X25519）の場合は空配列にする。
    authentication: usage.signing ? [methodId] : [],
    assertionMethod: usage.signing ? [methodId] : [],
  };
  if (usage.signing) {
    doc.capabilityInvocation = [methodId];
    doc.capabilityDelegation = [methodId];
  }
  if (usage.keyAgreement) {
    doc.keyAgreement = [methodId];
  }
  return doc;
}

/**
 * did:jwk 文字列を base64url デコードして公開鍵 JWK を取り出す。
 *
 * `did:jwk:` プレフィックス除去 → base64url（パディングなし）デコード → UTF-8 →
 * JSON.parse。JWK は plain object であることを要求する。
 *
 * @param did did:jwk 文字列。
 * @returns 公開鍵 JWK。
 * @throws プレフィックス不正・空 identifier・base64url 不正・JSON 不正・非オブジェクトの場合
 *         （VericertsError、code `2001`）。
 */
export function decodeDidJwk(did: string): PublicKeyJwk {
  if (!did.startsWith(DID_JWK_PREFIX)) {
    throw new VericertsError(ErrorCodes.INVALID_DID);
  }
  const encoded = did.slice(DID_JWK_PREFIX.length);
  if (encoded.length === 0) {
    throw new VericertsError(ErrorCodes.INVALID_DID);
  }
  let json: string;
  try {
    json = new TextDecoder('utf-8', { fatal: true }).decode(base64urlnopad.decode(encoded));
  } catch {
    // @scure/base / TextDecoder 由来の例外は入力を含み得るため cause を渡さず正規化する。
    throw new VericertsError(ErrorCodes.INVALID_DID);
  }
  let parsed: unknown;
  try {
    parsed = parseJsonWithoutPrototype(json);
  } catch {
    throw new VericertsError(ErrorCodes.INVALID_DID);
  }
  if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) {
    throw new VericertsError(ErrorCodes.INVALID_DID);
  }
  return parsed as PublicKeyJwk;
}
