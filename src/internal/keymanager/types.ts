/**
 * `KeyManager` が公開する型（`KeyPair` / `Signer`）。
 *
 * `keymanager.ts` から切り出し（Linterly の行数上限対応）、`keymanager.ts` が re-export する。
 */

/**
 * KeyManager が管理する完全な鍵ペア。
 *
 * HD 層の `DerivedKey` に対し、上位概念である `id` / `algorithm` / `address` を付与した型。
 */
export interface KeyPair {
  /** 公開鍵の SHA-256 ハッシュ（hex）に基づく安定 ID。 */
  readonly id: string;
  /** 署名アルゴリズム。BIP-32 導出の鍵ペアは secp256k1 固定（P-256 は {@link P256KeyPair}）。 */
  readonly algorithm: 'secp256k1';
  /**
   * 秘密鍵（32 バイト）。
   *
   * `KeyManager` が返す鍵ペアでは列挙不可・書き換え不可の own プロパティ。`JSON.stringify` / `Object.keys` / スプレッド /
   * `structuredClone` / Node・Bun の `util.inspect` には出ない。ブラウザの DevTools（`console.log`）は非列挙の own
   * プロパティも展開しうるので、鍵ペアをそのままログへ渡さないこと。必要なら `.privateKey` を明示的に読む（消去するならコピーを）。
   */
  readonly privateKey: Uint8Array;
  /** 公開鍵（圧縮形式・33 バイト）。 */
  readonly publicKey: Uint8Array;
  /** EIP-55 チェックサム付き Ethereum アドレス（`0x` + 40 hex）。 */
  readonly address: string;
  /** この鍵を導出した BIP-32 パス。 */
  readonly derivationPath: string;
}

/**
 * 特定鍵に紐づく署名インターフェース。
 *
 * 秘密鍵を外部へ露出せず、署名・公開鍵・アドレス取得のみを提供する。
 */
export interface Signer {
  /** keccak256(data) を secp256k1 で recoverable 署名し、65 バイト署名を返す。 */
  sign(data: Uint8Array): Promise<Uint8Array>;
  /** 圧縮公開鍵（33 バイト）を返す。 */
  publicKey(): Uint8Array;
  /** EIP-55 チェックサム付き Ethereum アドレスを返す。 */
  address(): string;
}

/**
 * SLIP-0010（Nist256p1）で導出した P-256（ES256）鍵ペア。
 *
 * secp256k1 の {@link KeyPair} と異なり Ethereum アドレスを持たない（EOA としては使えない）。
 * 新規作成する DID（did:key / did:jwk / did:peer）の鍵で、`KeyManager.deriveP256Key` が返す。
 */
export interface P256KeyPair {
  /** 公開鍵の SHA-256 ハッシュ（hex）に基づく安定 ID。 */
  readonly id: string;
  /** 署名アルゴリズム。 */
  readonly algorithm: 'P-256';
  /**
   * 秘密鍵（32 バイト）。
   *
   * `KeyManager` が返す鍵ペアでは列挙不可・書き換え不可の own プロパティ。`JSON.stringify` / `Object.keys` / スプレッド /
   * `structuredClone` / Node・Bun の `util.inspect` には出ない。ブラウザの DevTools（`console.log`）は非列挙の own
   * プロパティも展開しうるので、鍵ペアをそのままログへ渡さないこと。必要なら `.privateKey` を明示的に読む（消去するならコピーを）。
   */
  readonly privateKey: Uint8Array;
  /** 公開鍵（圧縮形式・33 バイト）。 */
  readonly publicKey: Uint8Array;
  /** この鍵を導出した SLIP-0010 パス（例: `m/9256'/0'/0'/0'`）。 */
  readonly derivationPath: string;
}

/** `KeyManager` の鍵レジストリが保持する鍵ペア（secp256k1 / P-256）。 */
export type RegisteredKeyPair = KeyPair | P256KeyPair;
