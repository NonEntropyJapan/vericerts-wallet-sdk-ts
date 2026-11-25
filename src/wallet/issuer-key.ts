/**
 * 受領・検証経路が共有する Issuer 検証鍵の解決（DID Resolver → 検証鍵）。
 *
 * `did-resolver.ts`（`buildDidResolver` が ethers を引く did:ethr / did:ipid 等の全 DID メソッドを import する）
 * から切り出した。`issuer-trust/`（受領 VC の署名検証）がここだけに依存することで、全 DID メソッドの登録を
 * 引かずに SDK の受領検証規則をそのまま再利用できる。DID Resolver 自体は呼び出し側が注入する
 * （拡張機能は公開 API の `createDidResolver` で組み立てる）。
 */

import { inlineExternalMethods } from '../internal/credential/did-signing/external-methods.js';
import {
  type CredentialVerifierKey,
  didDocumentToVerifierKey,
  parseSdJwt,
  type VerifierKeyOptions,
} from '../internal/credential/index.js';
import { decodeCompactJws } from '../internal/credential/vc/jws.js';
import { ErrorCodes, VericertsError } from '../internal/errors.js';
import type { DidResolverLike } from '../internal/identity/bounded-resolver.js';
import type { PublicKeyJwk } from '../internal/identity/did.js';
import { ownProperty } from '../internal/prototype-safety/own-property.js';

/** JWS ヘッダ `kid`（文字列のとき）があれば、その VerificationMethod を指定 relationship 内から選ばせる。 */
function kidSelection(
  header: Readonly<Record<string, unknown>>,
  relationship: VerifierKeyRelationship,
): VerifierKeyOptions {
  const kid = header.kid;
  return typeof kid === 'string' ? { relationship, verificationMethodId: kid } : { relationship };
}

/**
 * JWS 署名鍵を選ぶ DID Document の検証関係。
 * VC / SD-JWT の発行者署名は `assertionMethod`、VP の holder 署名（本人認証）は `authentication`。
 */
export type VerifierKeyRelationship = 'assertionMethod' | 'authentication';

/**
 * JWT-VC の `iss`（発行者 DID）を解決し、検証鍵（`CredentialVerifierKey`）を組み立てる。
 *
 * JWT を分解して payload の `iss` を取り出し、`resolver.resolve` で DID Document を解決した上で
 * `didDocumentToVerifierKey` で検証鍵へ変換する。Wallet の検証系メソッド（credential 等）共通の前段処理。
 *
 * @param resolver DID 解決委譲先（`Resolver` のほか、上限付きラッパーなど構造互換の実装を受け取る）。
 * @param jwt 検証対象のコンパクト JWT-VC 文字列（VP の holder 署名鍵解決では JWT-VP）。
 * @param relationship 署名鍵を選ぶ検証関係。既定 `assertionMethod`（VC の発行者鍵）。JWT-VP の holder
 *        署名は W3C VC / DID Core に従い `authentication` を指定する。検証関係が他 DID の検証メソッドを
 *        DID URL で参照しているときは、その DID を解決して辿る（`kid` の指す 1 件、`kid` が無ければ先頭の要素）。
 * @returns `verifyCredential` 系に渡せる検証鍵。
 * @throws JWT 形式不正の場合（VericertsError、code `2001`）、`iss` が欠落・非文字列の場合（code `3002`）、
 *         未対応メソッドの場合（code `2002`）、DID Document が不正な場合・参照先の検証メソッドを辿れない場合（code `2010`）。
 */
export async function resolveIssuerVerifierKey(
  resolver: DidResolverLike,
  jwt: string,
  relationship: VerifierKeyRelationship = 'assertionMethod',
): Promise<CredentialVerifierKey> {
  const { payload, header } = decodeCompactJws(jwt);
  const iss = payload.iss;
  if (typeof iss !== 'string') {
    // 発行者 DID（iss）を欠く JWT-VC は検証鍵を組み立てられないため構造不正として拒否する。
    throw new VericertsError(ErrorCodes.VC_SCHEMA_INVALID);
  }
  const selection = kidSelection(header, relationship);
  // 検証関係が他 DID の検証メソッドを DID URL 参照で載せているとき（委任 DID が委任先ペルソナの鍵を参照する。DID Core §5.3）
  // は、その DID を解決して実体を引く。他 DID への参照が無い文書では何もしない（解決を増やさない）。
  const kid = ownProperty<string>(selection, 'verificationMethodId');
  const document = await inlineExternalMethods(
    resolver,
    await resolver.resolve(iss),
    relationship,
    kid === undefined ? {} : { kid },
  );
  return didDocumentToVerifierKey(document, selection);
}

/**
 * SD-JWT の Issuer-signed JWT から `iss`（発行者 DID）を解決し、検証用の公開鍵 JWK を取り出す。
 *
 * SD-JWT を分解して Issuer-signed JWT の payload `iss` を読み、DID Document を解決して
 * `didDocumentToVerifierKey` で検証鍵へ変換する。`verifySdJwt` は JWK 形式の Issuer 鍵を要求するため、
 * 検証関数のみで JWK を持たない鍵タイプ（did:pkh の blockchainAccountId 等）は SD-JWT 検証に使えず拒否する。
 *
 * @param resolver DID 解決委譲先（`Resolver` のほか、上限付きラッパーなど構造互換の実装を受け取る）。
 * @param sdJwt 検証対象の SD-JWT 文字列。
 * @returns Issuer の EC 公開鍵 JWK。
 * @throws SD-JWT / JWT 形式不正の場合（code `2001`）、`iss` 欠落・非文字列の場合（code `3002`）、
 *         Issuer 鍵が JWK でない場合（code `3010`）。
 */
export async function resolveSdJwtIssuerKey(
  resolver: DidResolverLike,
  sdJwt: string,
): Promise<PublicKeyJwk> {
  const { issuerJwt } = parseSdJwt(sdJwt);
  const { payload, header } = decodeCompactJws(issuerJwt);
  const iss = payload.iss;
  if (typeof iss !== 'string') {
    throw new VericertsError(ErrorCodes.VC_SCHEMA_INVALID);
  }
  const key = didDocumentToVerifierKey(
    await resolver.resolve(iss),
    kidSelection(header, 'assertionMethod'),
  );
  const publicKeyJwk = ownProperty<PublicKeyJwk>(key, 'publicKeyJwk');
  if (publicKeyJwk === undefined) {
    throw new VericertsError(ErrorCodes.SIG_INVALID);
  }
  return publicKeyJwk;
}
