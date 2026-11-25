/**
 * OpenID Federation 1.0 の Entity Statement / Trust Chain 型定義。
 *
 * OpenID Federation では各エンティティが署名済みの JWT（Entity Statement）を公開する:
 *
 * - **Entity Configuration**: エンティティ自身が自己の JWKS で自己署名した Statement。
 *   `<entity_id>/.well-known/openid-federation` で公開される（`iss == sub`）。
 * - **Subordinate Statement**: 上位（Intermediate / Trust Anchor）が下位について発行する
 *   Statement（`iss != sub`）。上位の `federation_fetch_endpoint` から取得する。
 *
 * Trust Chain は Leaf（Entity Configuration）→ 上位の Subordinate Statement 連鎖 →
 * Trust Anchor（自己署名 Entity Configuration）の順に構成する。
 *
 * 本モジュールは JWT の署名検証に既存の `credential/vc/jws.ts` のプリミティブ
 * （`decodeCompactJws` / `verifyWithJwk`）を再利用し、`jose` 等は導入しない。
 */

import type { FailSafeWarning } from '../../failsafe-policy/index.js';
import type { PublicKeyJwk } from '../../identity/did.js';
import type { StatementConstraints } from './constraints/parse.js';

/**
 * JWK Set（`keys` 配列を持つ）。Entity Statement の `jwks` クレームに対応する。
 */
export interface JsonWebKeySet {
  /** 公開鍵 JWK の配列。各鍵は `kid` を持ち得る。 */
  readonly keys: readonly PublicKeyJwk[];
}

/**
 * Entity Statement（Entity Configuration / Subordinate Statement 共通）のクレーム。
 *
 * OpenID Federation 1.0 §3.1 に準拠した最小サブセット。`metadata_policy` /
 * `constraints` 等の任意クレームは検証で参照する範囲のみ型付けする。
 */
export interface EntityStatement {
  /** 発行者の Entity Identifier（HTTPS URL）。 */
  readonly iss: string;
  /** 主体の Entity Identifier（Entity Configuration では `iss` と一致）。 */
  readonly sub: string;
  /** 発行日時（NumericDate、エポック秒）。 */
  readonly iat: number;
  /** 有効期限（NumericDate、エポック秒）。 */
  readonly exp: number;
  /** 主体の署名鍵集合（この Statement 内の主体を検証する鍵）。 */
  readonly jwks: JsonWebKeySet;
  /** 上位エンティティ（Trust Anchor 方向）の Entity Identifier 群。Leaf / Intermediate が持つ。 */
  readonly authority_hints?: readonly string[];
  /** メタデータ（`federation_entity` 等）。`federation_fetch_endpoint` の解決に使う。 */
  readonly metadata?: EntityMetadata;
  /** 下位に適用する metadata policy（Subordinate Statement が持つ）。 */
  readonly metadata_policy?: MetadataPolicy;
  /**
   * 下位に課す制約（Subordinate Statement が持つ。OpenID Federation 1.0 §6.2）。
   *
   * `max_path_length` / `naming_constraints` / `allowed_entity_types` を `buildTrustChain` が強制する
   * （`constraints/enforce.ts`）。Entity Configuration の `constraints` は自己申告で権威を持たないため強制しない。
   */
  readonly constraints?: StatementConstraints;
  /**
   * 主体の鍵に対する無効化宣言（Subordinate Statement が持つ任意クレーム）。
   *
   * Entity Configuration は自己署名のため権威を持たない（`collectRevokedKeys` は無視する）。
   */
  readonly revoked_keys?: readonly RevokedKeyDeclaration[];
}

/**
 * Subordinate Statement の鍵無効化宣言。
 *
 * 上位が「主体の鍵 `kid` を `revoked_at` 以降は信頼しない」と宣言する override。Issuer の KMS 鍵が
 * 漏洩した後に残る唯一の実効的な防御線であるため、任意クレームであっても検証は必須とする。
 */
export interface RevokedKeyDeclaration {
  /** 無効化する鍵の `kid`。 */
  readonly kid: string;
  /** この時刻（エポック秒）以降に発行された署名を拒否する。 */
  readonly revoked_at: number;
  /** 任意の理由（`key_compromise` 等）。判定には使わない。 */
  readonly reason?: string;
}

/**
 * 宣言対象の subject を紐付けた鍵無効化宣言（Trust Chain 集約後の形）。
 *
 * `kid` は **1 つの JWKS の中でしか一意でない**。Subordinate Statement の `revoked_keys` は
 * その Statement の `sub`（= 宣言対象のエンティティ）の JWKS 内の鍵を指すため、チェーン全体の
 * 宣言を平坦化する際に `sub` を捨てると別エンティティの同名 `kid` と衝突する。
 *
 * 衝突は両方向に壊れる。Trust Anchor が intermediate の `kid: "1"` について出した宣言が、
 * たまたま同じ `kid` を使う leaf の署名まで巻き込んで拒否する（誤検知）。「最も早い `revoked_at`
 * が勝つ」規則はこの巻き添えを増幅する。したがって `sub` の紐付けは突合の必須条件である
 */
export interface ScopedRevokedKeyDeclaration extends RevokedKeyDeclaration {
  /** 宣言対象のエンティティ（宣言を含む Subordinate Statement の `sub`）。 */
  readonly sub: string;
}

/** Entity Statement の `metadata` クレーム（参照する範囲のみ型付け）。 */
export interface EntityMetadata {
  /** federation_entity メタデータ（fetch endpoint 等）。 */
  readonly federation_entity?: FederationEntityMetadata;
  /** その他のメタデータ種別（openid_provider / openid_relying_party 等）。 */
  readonly [key: string]: unknown;
}

/** `federation_entity` メタデータ（OpenID Federation 1.0 §5.1.1）。 */
export interface FederationEntityMetadata {
  /** Subordinate Statement を取得する fetch endpoint（HTTPS URL）。 */
  readonly federation_fetch_endpoint?: string;
  /** その他のフィールド。 */
  readonly [key: string]: unknown;
}

/**
 * metadata policy（OpenID Federation 1.0 §6.1）。
 *
 * メタデータ種別 → クレーム名 → policy 演算子（`subset_of` / `value` 等）の入れ子構造。
 * 本実装では下位メタデータへの適用可否（policy 違反検知）を判定する範囲で保持する。
 */
export type MetadataPolicy = Readonly<Record<string, Record<string, MetadataPolicyOperators>>>;

/** 単一クレームに対する policy 演算子群（OpenID Federation 1.0 §6.1.1）。 */
export interface MetadataPolicyOperators {
  /** 値をこの内容で上書き / 既定値化する。 */
  readonly value?: unknown;
  /** この集合の部分集合であることを要求する。 */
  readonly subset_of?: readonly unknown[];
  /** この集合の上位集合であることを要求する。 */
  readonly superset_of?: readonly unknown[];
  /** この集合のいずれかを含むことを要求する。 */
  readonly one_of?: readonly unknown[];
  /** 必須クレームであることを要求する。 */
  readonly essential?: boolean;
  /** 存在しない場合に補う既定値。 */
  readonly default?: unknown;
  /** その他の演算子。 */
  readonly [operator: string]: unknown;
}

/**
 * 取得・検証済みの Entity Configuration。
 *
 * `resolveEntityConfiguration` の戻り値。生の compact JWT と、デコード・自己署名検証済みの
 * クレームを保持する。
 */
export interface EntityConfiguration {
  /** 主体の Entity Identifier（`iss == sub`）。 */
  readonly entityId: string;
  /** 検証済みの Entity Statement クレーム。 */
  readonly statement: EntityStatement;
  /** 取得した生の compact JWS（`header.payload.signature`）。 */
  readonly jwt: string;
  /** FO-6 で通過した場合の警告（TTL 切れのキャッシュを使った旨）。 */
  readonly warnings?: readonly FailSafeWarning[];
}

/** Trust Chain の 1 ノード（1 つの Entity Statement に対応）。 */
export interface TrustChainNode {
  /** Statement の発行者。 */
  readonly iss: string;
  /** Statement の主体。 */
  readonly sub: string;
  /** この Statement が Entity Configuration（自己署名）か Subordinate Statement か。 */
  readonly kind: 'entity-configuration' | 'subordinate-statement';
  /** 検証済みの Entity Statement クレーム。 */
  readonly statement: EntityStatement;
  /**
   * この Statement の署名を実際に検証した鍵の `kid`（鍵が `kid` を持たなければ `undefined`）。
   *
   * 「失効させられた鍵が署名した Statement」をチェーン内で検出するために保持する
   * （`trust-chain.ts` の `assertChainSignaturesNotRevoked`）。
   */
  readonly signingKid?: string;
  /**
   * このノードの生 compact JWT。
   *
   * Leaf / Trust Anchor は `EntityConfiguration.jwt`、Subordinate は検証済み
   * `VerifiedStatement.jwt` に由来する。`FederationEntityCache.trustChain`を
   * 組み立てるために保持する。
   */
  readonly jwt?: string;
}

/**
 * 構築・検証済みの Trust Chain（`buildTrustChain` の戻り値）。
 *
 * `nodes` は Leaf（index 0）→ Trust Anchor（末尾）の順。仕様の
 * 「chain.length === 3 (Entity → Intermediate → Anchor)」に一致する。
 */
export interface TrustChain {
  /** Trust Anchor から到達可能で全ての署名 / policy 検証を通過したか。 */
  readonly valid: boolean;
  /** Leaf の Entity Identifier。 */
  readonly leaf: string;
  /** Trust Anchor の Entity Identifier。 */
  readonly trustAnchor: string;
  /** Leaf → Trust Anchor 順のノード列。 */
  readonly nodes: readonly TrustChainNode[];
  /** チェーン長（`nodes.length`）。 */
  readonly length: number;
  /**
   * チェーン内の全 Subordinate Statement から集約した鍵無効化宣言（宣言が無ければ空配列）。
   *
   * 各宣言は宣言対象の `sub` を伴う（`ScopedRevokedKeyDeclaration`）。`kid` は JWKS 内でしか
   * 一意でないため、`sub` を伴わない突合は別エンティティの同名 `kid` と衝突する。
   *
   * **VC への適用は VC 検証経路に配線されている**。`buildTrustChain` は VC を受け取らないため
   * chain 構築時には突合できないが、この chain を `verifyCredential` / `verifySdJwt` の
   * `issuerTrust` に渡せば署名検証の直後に自動的に適用される（opt-in）。
   */
  readonly revokedKeys: readonly ScopedRevokedKeyDeclaration[];
  /**
   * Trust Anchor の鍵が out-of-band 設定の鍵（`buildTrustChain` の `options.trustAnchorJwks`）に
   * ピン留めされて検証されたか（`buildTrustChain` は常に設定する）。`false` は Anchor の Entity Configuration を自己署名と
   * TLS だけで信頼したこと（鍵のローテーションと乗っ取りを区別できない）を表す。
   */
  readonly anchorPinned?: boolean;
  /**
   * チェーン構築中に成立した FO-6 警告の集約（1 件も無ければ未設定）。Leaf / 中間ノード /
   * Trust Anchor の Entity Configuration 解決で独立に起こり得るため配列で持つ。Subordinate
   * Statement の取得は FO-6 の対象外なのでここには現れない。
   */
  readonly warnings?: readonly FailSafeWarning[];
}
