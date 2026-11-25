/**
 * EUDI Wallet Unit Attestation (WUA) の型定義。
 *
 * ARF Annex 2 と draft-ietf-oauth-attestation-based-client-auth に基づく WUA および WUA-PoP を扱う。
 *
 * WUA は Wallet Provider Backend が発行する SD-JWT VC（`vct=urn:eudi:wallet-attestation:1`）で、
 * Wallet Unit が WSCA/WSCD 上で正当に動作していることを証明する。OID4VCI / OID4VP の
 * Token Request に OAuth2 Attestation-Based Client Authentication として添付する。
 *
 * WUA 発行エンドポイント（Wallet Provider Backend）は本 SDK の責務外。本モジュールは
 * WUA JWT の構造解析・検証（Wallet Provider 署名 / 期限 / WSCD バインド）と WUA-PoP 生成、
 * OAuth2 client_assertion 組み立てを担う。
 */

import type { PublicKeyJwk } from '../../identity/did.js';

/**
 * WUA の VC Type URI（ARF Annex 2、`urn:eudi:wallet-attestation:1`）。
 *
 * @experimental 挙動・シグネチャが変わり得る（v1.0 で `@stable` 昇格予定）。
 */
export const WUA_VCT = 'urn:eudi:wallet-attestation:1' as const;

/**
 * OAuth2 Attestation-Based Client Authentication の `client_assertion_type`
 * （draft-ietf-oauth-attestation-based-client-auth）。
 *
 * @experimental 挙動・シグネチャが変わり得る（v1.0 で `@stable` 昇格予定）。
 */
export const WUA_CLIENT_ASSERTION_TYPE =
  'urn:ietf:params:oauth:client-assertion-type:jwt-client-attestation' as const;

/**
 * 確認鍵（`cnf`）バインド。WUA `cnf.jwk` に対応する WSCD（Passkey 由来）鍵で、
 * WUA-PoP の署名鍵はこの鍵でなければならない。
 *
 * @experimental 挙動・シグネチャが変わり得る（v1.0 で `@stable` 昇格予定）。
 */
export interface WuaConfirmation {
  /** 確認鍵の EC 公開鍵 JWK（P-256）。WUA-PoP 署名鍵の公開鍵に一致する。 */
  readonly jwk: PublicKeyJwk;
}

/**
 * WUA JWT の payload クレーム。
 *
 * ユーザー PII は含まない（Wallet Unit のメタ情報のみ）。値の検査は `wua.ts` が行う。
 *
 * @experimental 挙動・シグネチャが変わり得る（v1.0 で `@stable` 昇格予定）。
 */
export interface WuaClaims {
  /** Wallet Provider の識別子（発行者、`iss`）。 */
  readonly iss: string;
  /** Wallet Instance の識別子（`sub`）。 */
  readonly sub: string;
  /** VC Type URI。常に `urn:eudi:wallet-attestation:1`。 */
  readonly vct: typeof WUA_VCT;
  /** 発行時刻（NumericDate、秒）。 */
  readonly iat: number;
  /** 有効期限（NumericDate、秒）。 */
  readonly exp: number;
  /** 確認鍵バインド（WSCD 由来鍵）。 */
  readonly cnf: WuaConfirmation;
  /** Wallet の表示名（任意）。 */
  readonly wallet_name?: string;
  /** Wallet 情報 URL（任意）。 */
  readonly wallet_link?: string;
}

/**
 * 受領済み Wallet Unit Attestation（`WalletUnitAttestation`）。
 *
 * `jwt` は WUA JWT のコンパクト表現、`claims` は解析済み payload、`cnf` は確認鍵。
 *
 * `walletProviderDID` は WUA の `iss` に由来する。
 * `issuedAt` と `expiresAt` は `iat` と `exp` を ISO 8601 に変換した値。PoP の Wallet Instance ID は JWT の `sub` から読む。
 *
 * `cnf` は公開鍵 JWK を保持する。WSCD バインドの検証では、両方の鍵の `kty` / `crv` / `x` を照合する。EC 鍵では `y` も照合し、それ以外では両方に `y` がないことを確認する。
 *
 * `nonce` は WUA-PoP のクレームで
 * AS が発行する `c_nonce` であり、WUA JWT 自体のクレームではない。1 本の WUA は複数の AS への
 * 複数回の Token Request で使い回されるため、リクエストごとに変わる値を長寿命の本型へ持たせる
 * 設計は成立せず、保存値を `buildWuaProofOfPossession` へ流用するとリプレイ防止が壊れる。
 *
 * @experimental 挙動・シグネチャが変わり得る（v1.0 で `@stable` 昇格予定）。
 */
export interface WalletUnitAttestation {
  /** WUA JWT 本体（コンパクト JWS）。 */
  readonly jwt: string;
  /** VC Type URI。常に `urn:eudi:wallet-attestation:1`。 */
  readonly vct: typeof WUA_VCT;
  /** Wallet Provider の識別子（`claims.iss`）。 */
  readonly walletProviderDID: string;
  /** 確認鍵バインド（`claims.cnf`）。 */
  readonly cnf: WuaConfirmation;
  /** 発行時刻（ISO 8601）。 */
  readonly issuedAt: string;
  /** 有効期限（ISO 8601）。 */
  readonly expiresAt: string;
}

/**
 * `buildWuaProofOfPossession` の入力オプション。
 *
 * @experimental 挙動・シグネチャが変わり得る（v1.0 で `@stable` 昇格予定）。
 */
export interface WuaPopOptions {
  /** 対象 Authorization Server（`aud`）。 */
  readonly aud: string;
  /** AS が発行した `c_nonce`（`nonce`）。リプレイ防止に必須。 */
  readonly nonce: string;
  /** WUA-PoP の有効期間（秒）。既定 300 秒。 */
  readonly lifetimeSeconds?: number;
  /**
   * WUA-PoP `jti`（一意 ID）。UUIDv4（ハイフンなし 32 文字 / 正準形 36 文字）でなければ `4013` で
   * 拒否する。省略時は `crypto.randomUUID()` で生成する。
   */
  readonly jti?: string;
}

/**
 * WUA-PoP JWT の payload クレーム。
 *
 * 署名鍵は WUA `cnf.jwk` に対応する WSCD（Passkey）由来鍵。
 *
 * @experimental 挙動・シグネチャが変わり得る（v1.0 で `@stable` 昇格予定）。
 */
export interface WuaPopClaims {
  /** Wallet Instance の識別子（WUA `sub`）。 */
  readonly iss: string;
  /** 対象 Authorization Server。 */
  readonly aud: string;
  /** 発行時刻（NumericDate、秒）。 */
  readonly iat: number;
  /** 有効期限（NumericDate、秒）。 */
  readonly exp: number;
  /** 一意 ID（リプレイ防止）。 */
  readonly jti: string;
  /** AS が発行した `c_nonce`。 */
  readonly nonce: string;
}

/**
 * OAuth2 Attestation-Based Client Authentication の client_assertion。
 *
 * `clientAssertion` は `<WUA>~<WUA-PoP>`、
 * `clientAssertionType` は `WUA_CLIENT_ASSERTION_TYPE`。Token Request / PAR に添付する。
 *
 * @experimental 挙動・シグネチャが変わり得る（v1.0 で `@stable` 昇格予定）。
 */
export interface ClientAttestation {
  /** `client_assertion`（`<WUA>~<WUA-PoP>`）。 */
  readonly clientAssertion: string;
  /** `client_assertion_type`。 */
  readonly clientAssertionType: typeof WUA_CLIENT_ASSERTION_TYPE;
}
