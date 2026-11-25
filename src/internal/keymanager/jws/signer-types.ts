/**
 * JWT-VC / SD-JWT の JWS 署名鍵の契約（`alg` / `publicKeyJwk` / `sign`）とアルゴリズム集合。
 *
 * **配置**: Foundation（`internal/keymanager/jws/`）。署名鍵の契約は Foundation の
 * `keymanager/kms/provider.ts`（KMS / HSM アダプタ）と `keymanager/jws/remote-signer.ts` が
 * 参照するため、鍵関連のモジュールが `credential/vc/` に依存せずに済むよう、ここに型を置く。
 * 依存する型は `identity/did.ts` の `PublicKeyJwk` のみ。
 *
 * `credential/vc/jws.ts` と `credential/vc/signer.ts` は互換のため本モジュールを再エクスポートする
 * ので、Domain 側の import パスと公開 API の識別子は変わらない。
 */

import type { PublicKeyJwk } from '../../identity/did.js';

/** JWT-VC が対応する IANA 登録済みの JWS 署名アルゴリズム（`ES256` / `ES256K` / `EdDSA`。RFC 7518 / 8812 / 8037）。 */
export type CredentialAlg = 'ES256' | 'ES256K' | 'EdDSA';

/**
 * 署名鍵・自分の DID の署名検証が扱う JWS `alg`。{@link CredentialAlg} に、IANA 登録外の `ES256K-R` を加えたもの。
 *
 * `ES256K-R` は EIP-191 の署名から公開鍵を復元する secp256k1（65 バイト署名）。did:pkh / did:ethr の controller 鍵
 * （検証メソッドが公開鍵を持たず `blockchainAccountId` だけを持つ）に限った標準外の例外。
 */
export type CredentialSignerAlg = CredentialAlg | 'ES256K-R';

/**
 * JWT-VC 署名鍵の抽象。
 *
 * `sign` は signing-input（`base64url(header).base64url(payload)`）のバイト列を受け取り、その
 * SHA-256 を取って 64 バイト raw 署名（`r || s`）を返す責務を実装側に持たせる。digest ではなく
 * signing-input を渡す点に注意（ハッシュ化と raw 化は実装の責務）。
 */
export interface CredentialSigner<A extends CredentialSignerAlg = CredentialAlg> {
  /** JWS 署名アルゴリズム（`ES256` = P-256 / `ES256K` = secp256k1 / `EdDSA` = Ed25519）。 */
  readonly alg: A;
  /** 発行者の EC または OKP 公開鍵 JWK（検証側へ受け渡すため公開）。 */
  readonly publicKeyJwk: PublicKeyJwk;
  /** JWS ヘッダへ載せる鍵 ID（`kid`）。未指定なら header に `kid` を出力しない。 */
  readonly kid?: string;
  /**
   * signing-input のバイト列に署名し、raw 署名を返す。
   *
   * `ES256` / `ES256K` は signing-input の SHA-256 digest に対する ECDSA 署名（`r || s`、64 バイト）、
   * `EdDSA` は事前ハッシュせず signing-input そのものに対する Ed25519 署名（`R || S`、64 バイト）、
   * `ES256K-R` は signing-input を EIP-191 メッセージとした recoverable 署名（`r || s || recovery`、65 バイト）。
   * ハッシュ化と raw 化はすべて実装側の責務。
   *
   * @param signingInput `base64url(header).base64url(payload)` の UTF-8 バイト列。
   * @returns raw 署名（`ES256K-R` のみ 65 バイト、ほかは 64 バイト）。
   */
  sign(signingInput: Uint8Array): Uint8Array;
}

/**
 * 非同期署名版の JWT-VC 署名鍵の抽象。
 *
 * KMS / HSM / 外部署名サービスのように署名がネットワーク越しになる実装のための seam。
 * `sign` が `Promise<Uint8Array>` を返す点だけが `CredentialSigner` と異なり、責務
 * （signing-input を受け取り、alg ごとの前処理を経て 64 バイト raw 署名を返す）は同一である。
 * 発行側は `issueCredentialAsync` / `createSdJwtAsync` が本インターフェースを受け付ける。
 */
export interface AsyncCredentialSigner<A extends CredentialSignerAlg = CredentialAlg> {
  /** JWS 署名アルゴリズム（`ES256` = P-256 / `ES256K` = secp256k1 / `EdDSA` = Ed25519）。 */
  readonly alg: A;
  /** 発行者の EC または OKP 公開鍵 JWK（検証側へ受け渡すため公開）。 */
  readonly publicKeyJwk: PublicKeyJwk;
  /** JWS ヘッダへ載せる鍵 ID（`kid`）。未指定なら header に `kid` を出力しない。 */
  readonly kid?: string;
  /**
   * signing-input のバイト列に署名し、64 バイトの raw 署名を返す。
   *
   * `ES256` / `ES256K` は signing-input の SHA-256 digest に対する ECDSA 署名（`r || s`）、
   * `EdDSA` は事前ハッシュせず signing-input そのものに対する Ed25519 署名（`R || S`）で、
   * いずれも 64 バイト。ハッシュ化と raw 化はすべて実装の責務。
   *
   * @param signingInput `base64url(header).base64url(payload)` の UTF-8 バイト列。
   * @returns 64 バイトの raw 署名の Promise。
   */
  sign(signingInput: Uint8Array): Promise<Uint8Array>;
}

/**
 * 同期 / 非同期いずれの JWT-VC 署名鍵も受け付ける union。
 *
 * `await signer.sign(...)` すれば両者を同一コードで扱えるため、非同期発行 API
 * （`issueCredentialAsync` / `createSdJwtAsync`）の引数型として用いる。
 */
export type AnyCredentialSigner<A extends CredentialSignerAlg = CredentialAlg> =
  | CredentialSigner<A>
  | AsyncCredentialSigner<A>;
