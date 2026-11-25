/**
 * did:jwt メソッド実装（JWT 軽量 DID）。
 *
 * did:jwt はネットワーク通信不要・完全ローカルで解決する。DID 文字列に JWT を
 * 完全内包する:
 *   `did:jwt:<base64url(JWT)>`
 *
 * JWT は `header.payload.signature` の 3 セグメント（各 base64url）で構成され、
 * payload に DID Document 相当の `verificationMethod` / `authentication` /
 * `assertionMethod` を埋め込む。解決手順:
 * 1. JWT を header / payload / signature にデコード。
 * 2. `id` / `iss` / `sub` が指定されていれば、それぞれが `did:jwt:` で始まる文字列であることを確認。
 * 3. `payload.verificationMethod` を DID Document として扱う。
 * 4. 署名を `payload.verificationMethod[0].publicKeyJwk` で検証。
 *    検証入力は signing-input（`header.payload` の ASCII）。SHA-256 の事前ハッシュが要るかは
 *    alg（`ALG_SPECS`）側の責務。
 * 5. `exp` / `nbf` を評価。
 *
 * 対応署名アルゴリズム（header.alg）は `ES256`（P-256）/ `ES256K`（secp256k1）/
 * `EdDSA`（Ed25519）。`jwkToVerificationKey` が alg と鍵の `kty` / `crv` の組み合わせを検査する。
 * 対応表にない alg は DID 形式不正（code `2001`）として拒否する。
 *
 * did:jwt は不変のため `update` / `deactivate` は非対応（code `2002`）。生成は
 * 秘密鍵での JWT 署名が必要だが `DIDMethod.create` は `{ keyType, publicKey }` のみで
 * 秘密鍵を受け取れないため本メソッドの `create` も非対応（code `2002`）とし、生成は
 * `generate.ts` の `createDidJwt`（公開 API）を使う。JWT デコード・JWK 変換・クレーム検証は
 * `jwt-codec.ts`、生成は `generate.ts` に分割している（1 ファイル 300 行以下のため）。
 *
 * セキュリティ上の注意:
 * - 例外メッセージや `context` に DID 文字列・JWT・公開鍵などの入力データを
 *   含めない。
 */

import { ErrorCodes, VericertsError } from '../../errors.js';
import type { CreateOptions, DIDDocument, DIDMethod, UpdateOptions } from '../did.js';
import { ALG_SPECS, jwkToVerificationKey } from './jwk-key.js';
import {
  assertJwtDidClaim,
  assertNoCriticalHeaders,
  base64urlDecode,
  DID_JWT_PREFIX,
  evaluateTimeClaims,
  extractFirstVerificationMethod,
  type JwtPayload,
  parseJson,
  toRelationshipRefs,
} from './jwt-codec.js';

/**
 * did:jwt 文字列を DID Document に解決する。
 *
 * @param did did:jwt 文字列（`did:jwt:<base64url(JWT)>`）。
 * @param nowSeconds 時刻クレーム評価に使う現在時刻（エポック秒）。
 *        既定は `Date.now()` 由来。テスト用に注入できる。
 * @returns 検証済み DID Document。
 * @throws プレフィックス不正・JWT 構造不正・id 不一致・未対応 alg・署名検証失敗・
 *         期限切れ等の場合（VericertsError、code `2001`）。
 */
export function resolveDidJwt(
  did: string,
  nowSeconds: number = Math.floor(Date.now() / 1000),
): DIDDocument {
  if (!did.startsWith(DID_JWT_PREFIX)) {
    throw new VericertsError(ErrorCodes.INVALID_DID);
  }
  const encodedJwt = did.slice(DID_JWT_PREFIX.length);
  if (encodedJwt.length === 0) {
    throw new VericertsError(ErrorCodes.INVALID_DID);
  }

  // DID 識別子は base64url(JWT) のため、まず JWT 文字列へデコードする。
  // 不正 UTF-8 は TextDecoder の TypeError ではなく 2001 へ正規化する。
  let jwt: string;
  try {
    jwt = new TextDecoder('utf-8', { fatal: true }).decode(base64urlDecode(encodedJwt));
  } catch {
    throw new VericertsError(ErrorCodes.INVALID_DID);
  }
  const segments = jwt.split('.');
  if (segments.length !== 3) {
    throw new VericertsError(ErrorCodes.INVALID_DID);
  }
  const [headerSeg, payloadSeg, signatureSeg] = segments as [string, string, string];
  if (headerSeg.length === 0 || payloadSeg.length === 0 || signatureSeg.length === 0) {
    throw new VericertsError(ErrorCodes.INVALID_DID);
  }

  const header = parseJson(base64urlDecode(headerSeg));
  assertNoCriticalHeaders(header);
  const payload = parseJson(base64urlDecode(payloadSeg)) as JwtPayload;
  const signature = base64urlDecode(signatureSeg);

  // 1. 指定された DID claim のメソッドを確認する。
  //
  // did:jwt は `did:jwt:<base64url(JWT)>` で DID 自身が JWT を内包する。一方
  // payload.id は JWT 内にあるため、id を「最終 DID 文字列そのもの」に厳密一致
  // させる JWT は自己参照（id → JWT → DID → id）で構築不能になる。そのため
  // 本実装は次のメソッド束縛を検査する:
  // - `id` が存在する場合、`did:jwt:` メソッドの DID であること（メソッド束縛）。
  // - `iss` / `sub` が存在する場合も同様に `did:jwt:` メソッドであること。
  // 暗号的な所有者束縛は署名検証（verificationMethod の公開鍵で
  // header.payload を検証）で担保する。
  assertJwtDidClaim(payload.id);
  assertJwtDidClaim(payload.iss);
  assertJwtDidClaim(payload.sub);

  // 2. alg を判定する。対応表（ALG_SPECS）にない alg は DID 形式不正へ正規化する。
  const alg = header.alg;
  if (typeof alg !== 'string') {
    throw new VericertsError(ErrorCodes.INVALID_DID);
  }
  const algSpec = ALG_SPECS[alg];
  if (algSpec === undefined) {
    throw new VericertsError(ErrorCodes.INVALID_DID);
  }

  // 3. verificationMethod[0].publicKeyJwk で署名を検証。
  //    検証入力は signing input（header.payload の ASCII）そのもので、ECDSA の SHA-256 事前
  //    ハッシュを行うかは algSpec.verify の責務。公開鍵は alg が要求する kty / crv
  //    （EC / OKP）に厳密に束縛して取り出す。
  const vm = extractFirstVerificationMethod(payload);
  const publicKey = jwkToVerificationKey(vm.publicKeyJwk, algSpec);
  const signingInput = new TextEncoder().encode(`${headerSeg}.${payloadSeg}`);
  // did:jwt は署名を含む JWT 自体が DID 文字列（識別子）なので、`s` と `n - s` が別 DID を成立させる。
  // ES256 の high-S を既定で受理する共通 JWS 検証（`verifyWithJwk`）とは違い、`allowHighS: false` を明示して
  // low-S を強制する。
  if (!algSpec.verify(signingInput, signature, publicKey, false)) {
    throw new VericertsError(ErrorCodes.INVALID_DID);
  }

  // 4. exp / nbf を評価。
  evaluateTimeClaims(payload, nowSeconds);

  // 5. payload の verificationMethod を DID Document として組み立てる。
  return {
    '@context': ['https://www.w3.org/ns/did/v1'],
    id: did,
    verificationMethod: [
      {
        id: vm.id,
        type: vm.type,
        controller: did,
        publicKeyJwk: vm.publicKeyJwk,
      },
    ],
    authentication: toRelationshipRefs(payload.authentication, vm.id),
    assertionMethod: toRelationshipRefs(payload.assertionMethod, vm.id),
  };
}

/**
 * did:jwt メソッドプラグイン。
 *
 * `resolve` のみを提供する（ネットワーク不要・完全ローカル）。生成は秘密鍵での JWT
 * 署名が必要で `DIDMethod.create`（`{ keyType, publicKey }`）では秘密鍵を受け取れないため
 * `create` は非対応とし、生成は `createDidJwt`（`generate.ts`）を使う。did:jwt は不変のため
 * `update` / `deactivate` も非対応で、いずれも `METHOD_NOT_SUPPORTED`（code `2002`）を投げる。
 */
export class MethodJwt implements DIDMethod {
  /** メソッド名（`'jwt'`）。 */
  method(): string {
    return 'jwt';
  }

  /**
   * did:jwt の生成は秘密鍵での JWT 署名が必要で `CreateOptions`（`{ keyType, publicKey }`）
   * では秘密鍵を受け取れないため本メソッドでは非対応（code `2002`）。生成は `createDidJwt` を使う。
   */
  async create(_opts: CreateOptions): Promise<DIDDocument> {
    throw new VericertsError(ErrorCodes.METHOD_NOT_SUPPORTED);
  }

  /** did:jwt 文字列を DID Document に解決する。 */
  async resolve(did: string): Promise<DIDDocument> {
    return resolveDidJwt(did);
  }

  /** did:jwt は不変のため更新非対応（code `2002`）。 */
  async update(_did: string, _opts: UpdateOptions): Promise<DIDDocument> {
    throw new VericertsError(ErrorCodes.METHOD_NOT_SUPPORTED);
  }

  /** did:jwt は不変のため無効化非対応（code `2002`）。 */
  async deactivate(_did: string): Promise<void> {
    throw new VericertsError(ErrorCodes.METHOD_NOT_SUPPORTED);
  }
}
