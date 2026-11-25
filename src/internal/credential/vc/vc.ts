/**
 * W3C Verifiable Credential（VC）データモデルの最小型定義。
 *
 * spec: W3C Verifiable Credentials Data Model v2.0。本 SDK は VC を JWT-VC（JWS）として
 * 発行・検証する（`issue.ts` / `verify.ts`）。本モジュールは型のみを提供し、実装は持たない。
 *
 * 検証は最小スコープとし、`credentialStatus`（失効）等は型に含めるが実評価は将来の責務とする。
 */

import type { EvidenceEntry, TermsOfUseEntry } from '../evidence-tou/types.js';
import type { StatusReference } from '../sdjwt/sdjwt.js';

/**
 * W3C VC の `credentialStatus`（失効・一時停止の参照）。
 *
 * Bitstring Status List / Token Status List 等の参照を保持する。最小スコープでは型のみ
 * 提供し、実際の失効評価（`VC_REVOKED` 3020）は行わない。
 */
export interface CredentialStatus {
  /** Status List エントリの ID。 */
  readonly id?: string;
  /** Status の type（例: `BitstringStatusListEntry`）。 */
  readonly type: string;
  /** 追加のメソッド固有プロパティ（statusListIndex 等）。 */
  readonly [key: string]: unknown;
}

/**
 * W3C VC の `credentialSchema` エントリ（VC JSON Schema）。
 *
 * spec: [W3C Verifiable Credentials JSON Schema](https://www.w3.org/TR/vc-json-schema/)。
 * `id` はスキーマ文書の URL（本 SDK は HTTPS のみ取得する）、`type` はスキーマの種別で、
 * JSON Schema 系は `JsonSchema` / `JsonSchemaCredential`。W3C VC Data Model の
 * `credentialSchema` は単一 object と object 配列の双方を許容する。
 *
 * 検証は `validateCredentialSchema` が行う。
 */
export interface CredentialSchemaReference {
  /** スキーマ文書の URL。 */
  readonly id: string;
  /** スキーマ種別（例: `JsonSchema`）。 */
  readonly type: string;
  /**
   * スキーマ文書のハッシュ固定（W3C VC JSON Schema の `digestSRI`）。SDK は照合できないため、宣言があれば
   * `3061`（`integrity_unverifiable`）で拒否する。`digestMultibase` も同じ扱い。
   */
  readonly digestSRI?: string;
  /** スキーマ文書のハッシュ固定（VCDM 2.0 の `digestMultibase`）。{@link CredentialSchemaReference.digestSRI} と同じ扱い。 */
  readonly digestMultibase?: string;
}

/**
 * W3C VC の `refreshService`（期限前リフレッシュのエンドポイント参照）。
 *
 * Issuer が VC に埋め込み、Holder は `refreshCredential` で参照する。
 */
export interface RefreshServiceConfig {
  /** Refresh Service エントリの ID。 */
  readonly id: string;
  /**
   * Refresh Service の type。`OID4VCIRefreshService2025`（OID4VCI 経由）/
   * `ManualRefreshService2018`（手動）等。未知の type は拡張として許容する。
   */
  readonly type: 'ManualRefreshService2018' | 'OID4VCIRefreshService2025' | (string & {});
  /** リフレッシュ要求を送る HTTPS エンドポイント。 */
  readonly url: string;
  /** リフレッシュ契機（期限前 / 失効時 / スキーマ変更時 / オンデマンド）。 */
  readonly triggers?: ReadonlyArray<
    'pre-expiry' | 'on-revocation' | 'on-schema-change' | 'on-demand'
  >;
  /** リフレッシュ実行に Holder 同意を必須とするか。 */
  readonly requireHolderConsent?: boolean;
}

/**
 * W3C Verifiable Credential のデータモデル（最小）。
 *
 * `credentialSubject` は任意の object（クレーム本体）。`issuer` は発行者 DID 文字列。
 * `issuanceDate` / `expirationDate` は ISO 8601 文字列（W3C VC v1.1 命名）とする。
 */
export interface VerifiableCredential {
  /** JSON-LD コンテキスト（先頭は W3C VC v1 / v2 の base context）。 */
  readonly '@context': readonly string[];
  /** VC の type（先頭は `VerifiableCredential`）。 */
  readonly type: readonly string[];
  /** 発行者 DID 文字列。 */
  readonly issuer: string;
  /** クレーム本体（任意の object）。 */
  readonly credentialSubject: Readonly<Record<string, unknown>>;
  /** 発行日時（ISO 8601）。JWT-VC の `nbf` に対応する。 */
  readonly issuanceDate: string;
  /** 有効期限（ISO 8601）。JWT-VC の `exp` に対応する。 */
  readonly expirationDate?: string;
  /** VC の ID（URI）。JWT-VC の `jti` に対応する。 */
  readonly id?: string;
  /** 失効・一時停止の参照（最小スコープでは型のみ）。 */
  readonly credentialStatus?: CredentialStatus;
  /**
   * IETF Token Status List の `status` 参照。
   *
   * JWT VC / SD-JWT VC の失効管理に用いる（`credentialStatus` は W3C Bitstring Status List /
   * StatusList2021 側の参照で、両者は別物）。`IssuerModule.issueVC` が
   * `statusListType === 'token-status-list'` のとき自動付与する。
   */
  readonly status?: StatusReference;
  /**
   * クレーム構造を定義する JSON Schema の参照。
   * 単一エントリまたは配列を許容する（W3C VC Data Model の `credentialSchema` は object | object[]）。
   * `validateCredentialSchema` がここから URL を解決し `credentialSubject` を検証する。
   */
  readonly credentialSchema?: CredentialSchemaReference | readonly CredentialSchemaReference[];
  /**
   * 期限前リフレッシュのエンドポイント参照（Issuer が発行時に埋め込む）。
   * Holder は `refreshCredential`（refresh.ts）でこれを参照して VC を更新する。
   */
  readonly refreshService?: RefreshServiceConfig;
  /**
   * VC チェーンの親 VC の ID（`derivedFrom`）。リフレッシュで入れ替わった新 VC は旧 VC を
   * `derivedFrom` に持ち、監査用のチェーンエッジを形成する。
   * Credential Chain 検証（`verifyCredentialChain`）でも辿る親エッジ。
   */
  readonly derivedFrom?: string;
  /**
   * VC チェーンの根拠 VC の ID（`basedOn`）。`derivedFrom`（派生元）とは別に、根拠として参照する
   * 親エッジを表す。
   *
   * 複数の入力 VC から 1 つの VC を導出する N:1 の来歴（Provenance）を表現できるよう、単数と配列の
   * 両方を許容する。チェーン検証では他の親エッジと併せてすべて辿る。
   */
  readonly basedOn?: string | readonly string[];
  /**
   * この VC が置換した親 VC の ID（`supersedes`）。親は論理的に廃止されたものとして扱う。
   * チェーン検証では親エッジとして辿るが、親の失効は子へ伝搬しない（親は既に廃止済みのため）。
   */
  readonly supersedes?: string;
  /**
   * この VC が部分訂正した親 VC の ID（`amends`）。親は有効なまま一部が訂正される。
   * チェーン検証では親エッジとして辿り、親の失効は `derivedFrom` と同様に子へ伝搬する。
   */
  readonly amends?: string;
  /**
   * 親 VC 失効時の子 VC への失効伝搬ポリシー（Issuer が派生発行時に埋め込む）。
   * `strict`: 親失効で子も無効。`permissive`: 親失効を警告に留め子は有効。`custom`: 呼び出し側ハンドラで判定。
   */
  readonly revocationPropagation?: 'strict' | 'permissive' | 'custom';
  /**
   * 発行根拠（W3C VC `evidence`）。KYC / 書類確認等の確認プロセスを記述する。
   * 単一エントリまたは配列を許容する（W3C VC Data Model の `evidence` は object | object[]）。
   */
  readonly evidence?: EvidenceEntry | readonly EvidenceEntry[];
  /**
   * 利用条件（W3C VC `termsOfUse`）。ODRL 風の permission / prohibition / obligation を記述する
   * 単一エントリまたは配列を許容する。
   */
  readonly termsOfUse?: TermsOfUseEntry | readonly TermsOfUseEntry[];
}
