/**
 * Holder が DIF Credential Manifest の取得・申請に使うデータモデルと定数。
 * 提示要件は DIF Presentation Exchange v2.0 で表す。
 *
 * 型定義のみを持つ。取得・パース・申請・レスポンス処理のロジックは兄弟モジュール
 * （`parse.ts` / `application.ts`）に分離する。
 */

import type { FetchLike } from '../../fetch-di.js';
import type { LoA } from '../evidence-tou/evidence.js';
import type { VerifiableCredential } from '../vc/vc.js';

/** Manifest 取得・申請の HTTP タイムアウト（ミリ秒）。発行者通信と揃えて 10 秒。 */
export const MANIFEST_REQUEST_TIMEOUT_MS = 10_000;

/**
 * 本 SDK が対応する DIF Credential Manifest の `spec_version` プレフィックス。
 *
 * DIF は spec_version を仕様書 URL（例:
 * `https://identity.foundation/credential-manifest/spec/v1.0.0/`）で表現する。
 * URL のバージョン部分が `v1.` または `v0.3` で始まるものをサポートする。
 */
export const SUPPORTED_SPEC_VERSION_PREFIXES = [
  'https://identity.foundation/credential-manifest/spec/v1.',
  'https://identity.foundation/credential-manifest/spec/v0.3',
] as const;

/** DIF Credential Application オブジェクトの `spec_version`。Manifest と同系を使う。 */
export const APPLICATION_SPEC_VERSION =
  'https://identity.foundation/credential-manifest/spec/v1.0.0/';

/** Manifest / Output Descriptor の表示スタイル（DIF Credential Manifest `styles`）。任意 JSON。 */
export type ManifestStyle = Readonly<Record<string, unknown>>;

/** Output Descriptor の表示マッピング（DIF `display`）。任意 JSON。 */
export type DisplayMapping = Readonly<Record<string, unknown>>;

/**
 * PEx v2 Presentation Definition の生 JSON。
 *
 * 本 SDK は auth 層（request.ts）と同様に PEx を深くパースせず不透明な構造として扱う。
 * `id` のみ submission 構築のため参照する。
 */
export interface PresentationDefinition {
  /** Presentation Definition の ID（`presentation_submission.definition_id` に対応）。 */
  readonly id: string;
  /** input_descriptors など残りのフィールド（本 SDK では不透明）。 */
  readonly [key: string]: unknown;
}

/** Manifest が要求する VC フォーマット（DIF `format` / PEx Format）。任意 JSON。 */
export type FormatRequirement = Readonly<Record<string, unknown>>;

/** Manifest の発行者情報。 */
export interface ManifestIssuer {
  /** Issuer DID または URL。 */
  readonly id: string;
  /** 表示名。 */
  readonly name?: string;
  /** 表示スタイル。 */
  readonly styles?: ManifestStyle;
}

/** 発行される VC の記述子。 */
export interface OutputDescriptor {
  /** Output Descriptor の ID。 */
  readonly id: string;
  /** VC スキーマ URI（DIF は必須）。 */
  readonly schema: string;
  /** 表示名。 */
  readonly name?: string;
  /** 説明。 */
  readonly description?: string;
  /** 表示スタイル。 */
  readonly styles?: ManifestStyle;
  /** 表示マッピング。 */
  readonly display?: DisplayMapping;
}

/** DIF Credential Manifest。 */
export interface CredentialManifest {
  /** Manifest の ID。 */
  readonly id: string;
  /** 仕様バージョン（DIF spec URL）。 */
  readonly spec_version: string;
  /** 発行者情報。 */
  readonly issuer: ManifestIssuer;
  /** 発行される VC の記述子（1 件以上）。 */
  readonly output_descriptors: readonly OutputDescriptor[];
  /** 要求フォーマット。 */
  readonly format?: FormatRequirement;
  /** 申請時に満たすべき PEx v2 Presentation Definition。 */
  readonly presentation_definition?: PresentationDefinition;
  /**
   * 発行される VC に要求する最低 LoA（Level of Assurance）。DIF Credential Manifest v1.0 の
   * 標準プロパティではない Vericerts 拡張。他フィールド（`spec_version` /
   * `output_descriptors` 等）と同じくワイヤ形状（snake_case）に合わせた命名にする（Issuer が
   * Manifest JSON に実際に載せる際の表記と一致させるため）。`parseCredentialManifest`
   * （`parse.ts`）が own 読み + `isLoA` 検証で配線する。`fetchCredentialManifest` /
   * `submitCredentialApplication` の申請ロジック自体はこの値をまだ参照しない
   * （`createPresentation` の LoA 判定は `auth/request.ts` の `PresentationRequest.requiredLoA`
   * 側で別途配線する）。将来、発行申請フローでの LoA 要求記述に使う型の土台として先行導入する。
   */
  readonly required_loa?: LoA;
}

/**
 * 申請時に Holder が埋める入力回答。
 *
 * `presentation_definition` の各 input_descriptor.id をキーに回答値を渡す。
 */
export interface ManifestAnswers {
  readonly [inputId: string]: string | number | boolean | object;
}

/**
 * PEx v2 Presentation Submission の descriptor_map 1 エントリ。
 *
 * `id` は対応する input_descriptor.id、`format` は提示する VC フォーマット、`path` は
 * Application 内での提示位置を指す JSONPath。
 */
export interface PresentationSubmissionDescriptor {
  readonly id: string;
  readonly format: string;
  readonly path: string;
}

/** PEx v2 Presentation Submission（DIF Credential Application に埋め込む）。 */
export interface PresentationSubmission {
  /** Submission 自体の ID。 */
  readonly id: string;
  /** 対応する Presentation Definition の ID。 */
  readonly definition_id: string;
  /** input_descriptor と提示 VC の対応表。 */
  readonly descriptor_map: readonly PresentationSubmissionDescriptor[];
}

/** DIF Credential Application オブジェクト（Issuer へ送る申請本体）。 */
export interface CredentialApplication {
  /** Application の ID。 */
  readonly id: string;
  /** 仕様バージョン（Manifest と同系）。 */
  readonly spec_version: string;
  /** 対象 Manifest の ID。 */
  readonly manifest_id: string;
  /** 要求フォーマット（Manifest の format をエコーバック）。 */
  readonly format?: FormatRequirement;
  /** presentation_definition を満たす submission（Manifest が要求する場合のみ）。 */
  readonly presentation_submission?: PresentationSubmission;
}

/** 申請結果。 */
export interface ApplicationResult {
  /** 申請が受理されたか。 */
  readonly accepted: boolean;
  /** 遅延発行時の追跡 ID。 */
  readonly transactionId?: string;
  /** 発行された VC（受理かつ即時発行時）。 */
  readonly credential?: VerifiableCredential;
  /** 却下理由（却下時）。 */
  readonly rejectionReason?: string;
}

/** `buildCredentialApplication` のオプション（ID 生成の注入を含む）。 */
export interface BuildApplicationOptions {
  /**
   * 提示する VC のフォーマット識別子（PEx `format`）。既定 `jwt_vc_json`。
   * Manifest の presentation_definition がある場合の submission に反映する。
   */
  readonly presentationFormat?: string;
  /** Application ID の生成関数（テスト注入用）。省略時は `crypto.randomUUID()`。 */
  readonly generateId?: () => string;
}

/** `fetchCredentialManifest` / `submitCredentialApplication` の依存注入。 */
export interface ManifestDependencies {
  /** HTTP リクエストに使う `fetch` 実装（テスト注入用）。省略時はグローバル `fetch`。 */
  readonly fetchImpl?: FetchLike;
}

/** `submitCredentialApplication` の依存注入。 */
export interface SubmitApplicationDependencies extends ManifestDependencies {
  /**
   * 受領した生 VC 文字列を検証しパース済み VC を返す。署名 / スキーマ / 失効検証失敗時は throw する
   * （呼び出し側で `verifyCredential` 等を配線）。
   */
  readonly verifyReceived: (rawCredential: string) => Promise<VerifiableCredential>;
}
