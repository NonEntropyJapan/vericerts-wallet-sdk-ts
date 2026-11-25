/**
 * trust/arf の型定義。
 *
 * ARF（Architecture and Reference Framework）Trust Model のうち、EU Commission が管理する
 * Wallet Provider / Attestation Provider Registry（ARF Trust Anchor Catalogue）と、ETSI Trusted
 * List（trust/etsi-tsl）との対応付けに必要な型を定義する。
 *
 * 3 層統合信頼判定における Layer 3（最終フォールバック）の入力となる、署名検証済み
 * の Trust Anchor 集合を表現する。ネットワーク I/O・署名検証・突き合わせロジックは実装モジュール
 * （catalogue.ts / mapping.ts）が担い、本モジュールは構造の宣言に専念する。
 */

/**
 * ARF Catalogue の 1 エントリ（Wallet Provider / Issuer / Attestation Provider / Relying Party）。
 *
 * Layer 3 で `issuer_id` を突き合わせる単位。公開鍵は SPKI（DER）で保持し、ETSI TSL
 * の QTSP サービス証明書（`QtspServiceCertificate`）との対応付け（mapping.ts）に用いる。
 */
export interface ArfCatalogueEntry {
  /** レジストリ上の識別子（例 `did:web:issuer.example.eu` / `https://issuer.example.eu`）。 */
  readonly id: string;
  /** エントリ種別（Wallet Provider / Issuer / Attestation Provider / Relying Party）。 */
  readonly role: ArfEntryRole;
  /** 登録主体の所在国（ISO 3166-1 alpha-2、例 `DE`）。不明なら undefined。 */
  readonly country?: string;
  /**
   * Trust Anchor 公開鍵の SPKI（subjectPublicKeyInfo・DER）。
   *
   * ETSI TSL の granted QTSP サービス証明書の SPKI と照合して ARF ⇔ TSL の対応を判定する。
   * レジストリが公開鍵を掲載しないエントリでは undefined。
   */
  readonly spki?: Uint8Array;
}

/**
 * ARF Catalogue エントリの役割。
 *
 * `relying-party`は JAR 署名者（Verifier）の Trust Anchor 起点として ARF 層
 * （`jar-trust-arf.ts` の `arfLayerStatus`）を使う場合に用いる。当該判定は role がこの値の
 * エントリのみを対象にする（一時的に許容していた `wallet-provider` /
 * `issuer` / `attestation-provider` での代用は採用しない）。
 */
export type ArfEntryRole = 'wallet-provider' | 'issuer' | 'attestation-provider' | 'relying-party';

/**
 * 署名検証済みの ARF Trust Anchor 集合（`loadArfTrustAnchor` の結果）。
 *
 * Catalogue JSON は ARF Trust Anchor の固定 Ed25519 鍵で署名される。本型は
 * 署名検証に成功したエントリ群のみを保持する。
 */
export interface ArfTrustAnchorSet {
  /** Ed25519 署名検証に成功したか（成功時のみ本オブジェクトが返る）。 */
  readonly signatureValid: true;
  /** レジストリのバージョン識別子（Catalogue が提供する場合）。 */
  readonly version?: string;
  /**
   * 世代番号（署名済み payload の `sequence`。非負の安全整数、単調増加）。Catalogue が提供する場合のみ。
   * `LoadArfTrustAnchorOptions.previous` との比較で旧世代の再生を拒否するのに使う。
   */
  readonly sequence?: number;
  /** 発行日時（署名済み payload の `issuedAt`。ISO 8601・オフセット必須）。提供される場合のみ。 */
  readonly issuedAt?: string;
  /** 次回更新期限（署名済み payload の `nextUpdate`。ISO 8601・オフセット必須）。提供される場合のみ。 */
  readonly nextUpdate?: string;
  /** 登録エントリ一覧。 */
  readonly entries: readonly ArfCatalogueEntry[];
}

/** 直前に受理した Catalogue の世代情報（`ArfTrustAnchorSet` の部分集合）。 */
export type ArfCatalogueGeneration = Pick<ArfTrustAnchorSet, 'sequence' | 'issuedAt'>;

/** ARF Catalogue（Wallet Provider Registry JSON）を URL から取得する DI seam。 */
export type ArfTrustAnchorFetcher = (url: string) => Promise<string>;

/** `loadArfTrustAnchor` のオプション。 */
export interface LoadArfTrustAnchorOptions {
  /** Catalogue 取得関数（DI）。ネットワーク I/O を呼び出し側へ委譲する。 */
  readonly fetcher: ArfTrustAnchorFetcher;
  /**
   * Catalogue 署名検証に用いる ARF Trust Anchor の固定 Ed25519 公開鍵（raw 32 バイト）。
   *
   * アプリにピン留めして配布する ARF Trust Anchor の鍵。取得した Catalogue の
   * すり替えを防ぐ。
   */
  readonly trustAnchorPublicKey: Uint8Array;
  /**
   * 基準時刻（エポック秒）。省略時は実時計。Catalogue の `nextUpdate` の期限切れ判定に使う。
   */
  readonly nowSeconds?: number;
  /**
   * 直前に受理した世代。署名は固定鍵で永続的に有効なため、登録解除前の旧 Catalogue を
   * 再生されても署名検証は通る。ここに直前の `sequence` / `issuedAt` を渡すと、取得した世代が
   * それより後退していれば 10305 で拒否する（TSL の世代ロールバック拒否）。
   * 守れるのは呼び出し側が受理した世代を覚えている間だけ（省略時・初回取得は守れない）。
   */
  readonly previous?: ArfCatalogueGeneration;
}
