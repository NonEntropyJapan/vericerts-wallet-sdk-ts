/**
 * HAIP SD-JWT VC 相互運用テストで各ペアが使う共通のテストベクター。
 *
 * 実鍵・実署名で完結する決定的フィクスチャ（モック・ネット非依存）。固定秘密鍵から Issuer /
 * Holder の `CredentialSigner` と公開鍵 JWK を導出し、HAIP プロファイル準拠の SD-JWT VC を発行する
 * ための入力（vct / cnf / 開示クレーム / 固定 salt）を提供する。各ペアはこの同一ベクターを起点に
 * 独立して 1 サイクル（Offer → Receive → Present）を実行する。
 *
 * HAIP（High Assurance Interoperability Profile, OpenID4VC HAIP）の SD-JWT VC 要件のうち本ベクターが
 * 満たす要素:
 * - Issuer-signed JWT の `alg` は ES256（P-256）。HAIP は SD-JWT VC に ES256 を必須とする。
 * - `vct` を必須で付与する。
 * - Holder Binding（`cnf.jwk`）を必須で付与し、KB-JWT の鍵源とする。
 * - 選択的開示クレーム（`_sd`）を含む。
 */

import type { ConfirmationClaim, CreateSdJwtOptions } from '../credential/sdjwt/sdjwt.js';
import type { CredentialAlg } from '../credential/vc/jws.js';
import type { CredentialSigner } from '../credential/vc/signer.js';
import { createPrivateKeySigner } from '../credential/vc/signer.js';
import type { PublicKeyJwk } from '../identity/did.js';

/** HAIP は SD-JWT VC の署名に ES256（P-256）を必須とする。 */
export const HAIP_ALG: CredentialAlg = 'ES256';

/** テストベクターの固定秘密鍵（決定性のため。実運用の鍵ではない）。 */
export const ISSUER_PRIVATE_KEY = new Uint8Array(32).fill(3);
export const HOLDER_PRIVATE_KEY = new Uint8Array(32).fill(5);
/** cnf に紐付かない別 Holder 鍵（Holder Binding 不一致の否定系検証に用いる）。 */
export const FOREIGN_HOLDER_PRIVATE_KEY = new Uint8Array(32).fill(9);

/** HAIP SD-JWT VC の Verifiable Credential Type（テストベクター）。 */
export const VCT = 'https://credentials.example/haip/identity';

/** Issuer の ES256 公開鍵 JWK（検証鍵）。 */
export const ISSUER_JWK: PublicKeyJwk = issuerSigner().publicKeyJwk;
/** Holder の ES256 公開鍵 JWK（cnf / KB-JWT 検証鍵）。 */
export const HOLDER_JWK: PublicKeyJwk = holderSigner().publicKeyJwk;

/** Holder Binding（cnf）。HAIP では必須。 */
export const HOLDER_CNF: ConfirmationClaim = { jwk: HOLDER_JWK };

/** Issuer の署名器（ES256）。 */
export function issuerSigner(): CredentialSigner {
  return createPrivateKeySigner(ISSUER_PRIVATE_KEY, HAIP_ALG);
}

/** Holder の署名器（ES256、cnf に対応）。 */
export function holderSigner(): CredentialSigner {
  return createPrivateKeySigner(HOLDER_PRIVATE_KEY, HAIP_ALG);
}

/** cnf に紐付かない別 Holder の署名器（否定系）。 */
export function foreignHolderSigner(): CredentialSigner {
  return createPrivateKeySigner(FOREIGN_HOLDER_PRIVATE_KEY, HAIP_ALG);
}

/**
 * HAIP SD-JWT VC の共通発行入力（fixtures）を構築する。
 *
 * 決定的なテストベクターにする。
 *
 * 発行時の属性検査に合わせ、生の氏名や生年月日を発行入力に含めない。
 * `nickname` にはテスト用のハンドル名、`age_over_18` には年齢条件の成否を使う。
 */
export function credentialInput(): CreateSdJwtOptions {
  return {
    vct: VCT,
    issuer: 'did:example:haip-issuer',
    cnf: HOLDER_CNF,
    disclosureClaims: ['nickname', 'age_over_18', 'resident_address', 'resident_country'],
    claims: {
      sub: 'did:example:haip-holder',
      nickname: 'ali',
      age_over_18: true,
      resident_address: 'Rue de la Loi 200, 1049 Brussels',
      resident_country: 'BE',
    },
    salts: {
      nickname: 'salt-nickname',
      age_over_18: 'salt-age',
      resident_address: 'salt-addr',
      resident_country: 'salt-country',
    },
  };
}
