/**
 * JWT-VP（JWS）の署名検証（`presentation.ts` の下位ロジック）。
 *
 * `verifyPresentationClaims` の前半（署名検証コールバックの解決）をここに切り出し、
 * `alg` 検証（`assertAlg`）は `vc/jws.ts` に集約されている。
 * `presentation.ts` は `verifyPresentationClaims` / `verifyPresentation` のオーケストレーションに
 * 専念する（`presentation.ts` から分離しているのはファイル行数上限（300 行）のため）。
 *
 * セキュリティ上の注意:
 * - 例外メッセージや `context` に privateKey・VC 本文・開示値・JWT を含めない。
 */

import { ErrorCodes, VericertsError } from '../../errors.js';
import type { PublicKeyJwk } from '../../identity/did.js';
import type { CredentialSignerAlg, DecodedJws } from '../vc/jws.js';
import { verifyWithKey } from '../vc/jws.js';

/** `verifyPresentation` の検証鍵注入方法（`verify.ts` の `CredentialVerifierKey` と同形）。 */
export type PresentationVerifierKey =
  | { readonly publicKeyJwk: PublicKeyJwk; readonly verify?: undefined }
  | {
      /**
       * 署名検証コールバック（`CredentialVerifierKey.verify` と同一契約）。ECDSA（`ES256` /
       * `ES256K`）は `digest`（signing-input の SHA-256）を、`EdDSA` は事前ハッシュしないため
       * 必ず第 3 引数 `signingInput` を使う。第 3 引数は任意パラメータ扱いのため従来の 2 引数
       * コールバックもそのまま渡せ、ECDSA 専用コールバックが EdDSA を渡された場合は `false` を
       * 返して `SIG_INVALID` に正規化される（フェイルクローズ）。
       */
      readonly verify: (
        digest: Uint8Array,
        signature: Uint8Array,
        signingInput: Uint8Array,
      ) => boolean;
      readonly publicKeyJwk?: undefined;
    }
  | {
      /** `alg: "ES256K-R"`（IANA 登録外の標準外の例外）専用のアドレス鍵。`CredentialVerifierKey` と同一契約。 */
      readonly ethereumAddress: string;
      readonly publicKeyJwk?: undefined;
      readonly verify?: undefined;
    };

/**
 * デコード済み JWS の署名を、DI された検証鍵で検証する。
 *
 * @throws 署名不一致の場合（code `3010`）。alg と JWK の kty / crv の不一致も同じ `3010` に正規化する。
 */
export function assertSignature(
  alg: CredentialSignerAlg,
  decoded: DecodedJws,
  key: PresentationVerifierKey,
): void {
  // 検証は `verifyWithKey` に集約している（`vc/verify.ts` と共通）。`key` は KMS / HSM を
  // `class KmsVerifierKey { verify(...) {} get publicKeyJwk() {} }` でラップしたクラスインスタンスも
  // 取り得るため own 限定にはできず、`Object.prototype` 自身に生えた値だけを採用しない
  // （`nonObjectPrototypeProperty`）。`verify` は厳密に `true` を返したときのみ成功とする。
  if (!verifyWithKey(alg, decoded, key)) {
    throw new VericertsError(ErrorCodes.SIG_INVALID);
  }
}
