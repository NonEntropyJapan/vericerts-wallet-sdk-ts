/**
 * did:jwk メソッド実装（JWK ベース軽量 DID）。
 *
 * did:jwk はネットワーク通信不要で、公開鍵 JWK から DID と DID Document をローカル生成する:
 *   `did:jwk:<base64url(JWK JSON)>`
 *
 * 対応鍵タイプ:
 *
 * | kty | crv     | 用途                                |
 * | --- | ------- | ----------------------------------- |
 * | EC  | P-256   | Data Integrity (ecdsa)、COSE        |
 * | EC  | P-384   | Data Integrity (ecdsa)              |
 * | OKP | Ed25519 | Data Integrity (eddsa)、署名        |
 * | OKP | X25519  | DIDComm v2 鍵交換                   |
 *
 * VerificationMethod type は `JsonWebKey2020`。verification relationship は鍵の用途で分岐する:
 * - 署名向き鍵（Ed25519 / EC で `use !== 'enc'`）: authentication / assertionMethod /
 *   capabilityInvocation / capabilityDelegation に `#0` を入れる。
 * - 鍵交換向き鍵（X25519 / EC で `use !== 'sig'`）: keyAgreement に `#0` を入れる。
 *
 * did:jwk は不変のため `update` / `deactivate` は非対応（code `2002`）。
 *
 * JWK バリデーション・用途分類・DID/DID Document の符号化は `codec.ts` に分割している
 * （1 ファイル 300 行以下のため）。
 *
 * セキュリティ上の注意:
 * - 例外メッセージや `context` に DID 文字列・JWK・鍵バイトなどの入力データを含めない。
 *   秘密鍵パラメータ（`d`）は公開 JWK に含めない前提とする。
 */

import { ErrorCodes, VericertsError } from '../../errors.js';
import { ownProperty } from '../../prototype-safety/own-property.js';
import type { CreateOptions, DIDDocument, DIDMethod, PublicKeyJwk, UpdateOptions } from '../did.js';
import { buildDidDocument, classifyKeyUsage, decodeDidJwk, encodeDidJwk } from './codec.js';

/**
 * 公開鍵 JWK から did:jwk の DID Document を生成する。
 *
 * @param jwk 公開鍵 JWK（kty=EC crv∈{P-256,P-384} / kty=OKP crv∈{Ed25519,X25519}）。
 * @returns DID Document。
 * @throws JWK が未対応・必須メンバ欠落・秘密鍵混入の場合（VericertsError、code `2001`）。
 */
export function createDidJwk(jwk: PublicKeyJwk): DIDDocument {
  const usage = classifyKeyUsage(jwk);
  const did = encodeDidJwk(jwk);
  return buildDidDocument(did, jwk, usage);
}

/**
 * did:jwk 文字列を DID Document に解決する。
 *
 * 手順:
 * 1. `did:jwk:` プレフィックスを除去。
 * 2. base64url デコード → JWK JSON。
 * 3. kty/crv から用途を判定（VerificationMethod type は JsonWebKey2020）。
 * 4. DID Document を構築。
 *
 * @param did did:jwk 文字列（`did:jwk:<base64url(JWK)>`）。
 * @returns DID Document。
 * @throws プレフィックス不正・base64url 不正・JSON 不正・JWK 未対応の場合
 *         （VericertsError、code `2001`）。
 */
export function resolveDidJwk(did: string): DIDDocument {
  const jwk = decodeDidJwk(did);
  const usage = classifyKeyUsage(jwk);
  return buildDidDocument(did, jwk, usage);
}

/**
 * did:jwk メソッドプラグイン。
 *
 * `create` / `resolve` を提供する。did:jwk は不変のため `update` / `deactivate` は
 * 非対応で、`METHOD_NOT_SUPPORTED`（code `2002`）を投げる。
 *
 * `create` は `CreateOptions.jwk`（公開鍵 JWK）から DID Document を生成する。raw 公開鍵
 * （`CreateOptions.publicKey`）からの JWK 構築は鍵タイプごとの座標エンコードが必要で
 * keymanager の責務のため、本メソッドは JWK を直接受け取る。
 */
export class MethodJwk implements DIDMethod {
  /** メソッド名（`'jwk'`）。 */
  method(): string {
    return 'jwk';
  }

  /**
   * 公開鍵 JWK から DID Document を生成する。
   *
   * @param opts `jwk` に公開鍵 JWK を指定する。
   * @throws `jwk` 未指定・JWK 未対応の場合（VericertsError、code `2001`）。
   */
  async create(opts: CreateOptions): Promise<DIDDocument> {
    const jwk = ownProperty<PublicKeyJwk>(opts, 'jwk');
    if (jwk === undefined) {
      throw new VericertsError(ErrorCodes.INVALID_DID);
    }
    return createDidJwk(jwk);
  }

  /** did:jwk 文字列を DID Document に解決する。 */
  async resolve(did: string): Promise<DIDDocument> {
    return resolveDidJwk(did);
  }

  /** did:jwk は不変のため更新非対応（code `2002`）。 */
  async update(_did: string, _opts: UpdateOptions): Promise<DIDDocument> {
    throw new VericertsError(ErrorCodes.METHOD_NOT_SUPPORTED);
  }

  /** did:jwk は不変のため無効化非対応（code `2002`）。 */
  async deactivate(_did: string): Promise<void> {
    throw new VericertsError(ErrorCodes.METHOD_NOT_SUPPORTED);
  }
}
