/**
 * DID Document から DIDComm v2 送信に必要な要素（keyAgreement 鍵 / serviceEndpoint）を抽出する。
 *
 * セキュリティ上の注意:
 * - 例外メッセージ・`context` に DID 文字列・鍵バイトを含めない。
 */

import { verificationMethodToJwk } from '../credential/vc/verifier-key-jwk.js';
import { ErrorCodes, VericertsError } from '../errors.js';
import type { DIDDocument, PublicKeyJwk, VerificationMethod } from '../identity/did.js';
import {
  relationshipEntriesOf,
  servicesOf,
  verificationMethodsOf,
} from '../identity/did-document-read.js';
import { ownProperty } from '../prototype-safety/own-property.js';

/** 解決済み keyAgreement 鍵（`id` は JWE header の `kid` に載せる VerificationMethod id）。 */
export interface ResolvedKeyAgreement {
  readonly id: string;
  readonly publicKeyJwk: PublicKeyJwk;
}

function resolveVerificationMethodRef(
  doc: DIDDocument,
  ref: string | VerificationMethod,
): VerificationMethod | undefined {
  if (typeof ref !== 'string') {
    return ref;
  }
  return verificationMethodsOf(doc).find((vm) => ownProperty<string>(vm, 'id') === ref);
}

/**
 * DID Document の `keyAgreement[0]` を解決し、P-256 公開鍵 JWK として返す。
 *
 * @param doc 解決済み DID Document。
 * @returns keyAgreement の VerificationMethod id と公開鍵 JWK。
 * @throws `keyAgreement` が空 / 参照解決失敗 / 対応外の鍵表現・曲線の場合（`DIDCOMM_PACKING_FAILED`）。
 */
export function resolveKeyAgreement(doc: DIDDocument): ResolvedKeyAgreement {
  const entry = (relationshipEntriesOf(doc, 'keyAgreement') ?? [])[0];
  if (entry === undefined) {
    throw new VericertsError(ErrorCodes.DIDCOMM_PACKING_FAILED);
  }
  const vm = resolveVerificationMethodRef(doc, entry);
  if (vm === undefined) {
    throw new VericertsError(ErrorCodes.DIDCOMM_PACKING_FAILED);
  }
  let publicKeyJwk: PublicKeyJwk;
  try {
    publicKeyJwk = verificationMethodToJwk(vm);
  } catch (error) {
    if (error instanceof VericertsError) {
      throw new VericertsError(ErrorCodes.DIDCOMM_PACKING_FAILED, { cause: error });
    }
    throw new VericertsError(ErrorCodes.DIDCOMM_PACKING_FAILED);
  }
  if (ownProperty<unknown>(publicKeyJwk, 'crv') !== 'P-256') {
    // DIDComm の JWE 鍵合意は P-256 のみ対応（`didcomm/jwe.ts` 冒頭コメント参照）。
    throw new VericertsError(ErrorCodes.DIDCOMM_PACKING_FAILED);
  }
  // JWE header の `kid` になる id も own 限定。欠いた VerificationMethod が汚染 id を拾って鍵合意先を偽らない。
  const id = ownProperty<string>(vm, 'id');
  if (id === undefined) {
    throw new VericertsError(ErrorCodes.DIDCOMM_PACKING_FAILED);
  }
  return { id, publicKeyJwk };
}

function endpointUriFromValue(value: unknown): string | undefined {
  if (typeof value === 'string') {
    return value;
  }
  if (Array.isArray(value)) {
    return value.length > 0 ? endpointUriFromValue(value[0]) : undefined;
  }
  if (typeof value === 'object' && value !== null) {
    // `uri` は own 限定で読む（`'uri' in value` / `.uri` は `Object.prototype.uri` の汚染値を拾い、送信先が攻撃者 URL になる）。
    const uri = ownProperty<unknown>(value, 'uri');
    return typeof uri === 'string' ? uri : undefined;
  }
  return undefined;
}

/** `service` から `type: DIDCommMessaging` の serviceEndpoint URI を抽出する（無ければ `undefined`）。 */
export function resolveServiceEndpoint(doc: DIDDocument): string | undefined {
  // 要素が null / 非オブジェクトの `service` は素の `.find` が生 TypeError を漏らすため、共有リーダで
  // 2010 に正規化する。`type` / `serviceEndpoint` は要素の必須メンバだが実体はネットワーク由来で、
  // 省略した文書が `Object.prototype` の汚染値を拾うと送信先が攻撃者 URL になるため own 限定で読む。
  const service = servicesOf(doc).find(
    (entry) => ownProperty<unknown>(entry, 'type') === 'DIDCommMessaging',
  );
  return service === undefined
    ? undefined
    : endpointUriFromValue(ownProperty<unknown>(service, 'serviceEndpoint'));
}
