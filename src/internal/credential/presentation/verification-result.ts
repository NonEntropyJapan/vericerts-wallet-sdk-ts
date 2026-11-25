/**
 * 高レベル Verifier API `verifyPresentation` と、envelope 専用 primitive の戻り値型。
 *
 * 2 層構成:
 *
 * - **低レベル primitive**: `verifyPresentationEnvelopeStrict` は VP envelope（署名・時刻・
 *   aud/nonce バインド）だけを fail-closed で検証し、成功時に {@link VerifiedPresentationEnvelope}
 *   を返す。**内包 VC の検証結果は返さない**（1 回の呼び出しで暗号的に保証できた範囲だけを返す）。
 * - **高レベル Verifier API**: `verifyPresentation` は {@link PresentationVerificationResult} を返す。
 *   内包 VC の失敗は例外にならないため、`valid` で判別して使う。
 *
 * **`valid` と `presentationValid` の違い**: `presentationValid` は VP envelope
 * だけの成否、`valid` は「`presentationValid` **かつ** 全内包 VC が有効」である。部分成功
 * （envelope は正当だが内包 VC の一部が invalid）は診断情報として `credentialResults` に残しつつ、
 * 最終的な認可判定である top-level `valid` は `false` に倒す（deny）。
 *
 * セキュリティ上の注意:
 * - `errors` / `warnings` にはエラーコードと静的な文言だけを入れ、VP / VC 本文・開示値・JWT を
 *   含めない。
 */

import type { VCFormat } from '../format-negotiation/types.js';
import type { VerificationIssue } from '../verification-issue.js';
import type { VerifiablePresentation } from './vp.js';

/**
 * `verifyPresentationEnvelopeStrict`（低レベル primitive）の戻り値。
 *
 * 内包 VC については**何も検証していない**。`presentation.verifiableCredential` を読むだけでは
 * 未検証の VC を受理することになるため、内包 VC も要るなら高レベル `verifyPresentation` を使う。
 */
export interface VerifiedPresentationEnvelope {
  /** デコード済み JWS ヘッダ。 */
  readonly header: Record<string, unknown>;
  /** デコード済み JWS ペイロード（`iss` / `aud` / `nonce` / `vp` 等）。 */
  readonly payload: Record<string, unknown>;
  /** 構造検証済みの VP（`payload.vp`）。内包 VC は未検証。 */
  readonly presentation: VerifiablePresentation;
  /** 提示者 DID（`vp.holder` = JWT の `iss`）。 */
  readonly holderDID: string;
}

/**
 * 内包 VC 1 件の検証結果のうち、成否によらず必ず埋まるフィールド
 * （低レベルの `VerificationResult` と同じ内容）。
 */
export interface EmbeddedCredentialVerificationFields {
  /** 発行者 DID（`iss`）。取り出せなかった場合は空文字列。 */
  readonly issuerDID: string;
  /** `exp` が現在時刻より過去か（`exp` を持たない VC は `false`）。 */
  readonly isExpired: boolean;
  /** 失効確認の結果。本経路は実行しないため常に `null`（未実行）。 */
  readonly isRevoked: boolean | null;
  /** 一時停止確認の結果。本経路は実行しないため常に `null`（未実行）。 */
  readonly isSuspended: boolean | null;
  /**
   * Trusted Issuer List 突合の結果。
   *
   * `verifyPresentation` に `trustedIssuerList` が DI されていない場合は従来どおり `null`（未実行）。
   * DI された場合は、内包 VC の `issuerDID` を当該リストと照合した結果。
   */
  readonly isTrustedIssuer: boolean | null;
  /** スキーマ検証の結果。本経路は実行しないため常に `null`（未実行）。 */
  readonly schemaValid: boolean | null;
  /** 判別したフォーマット。 */
  readonly format: VCFormat;
}

/** 内包 VC 1 件の検証結果（高レベル。`valid` で判別する）。 */
export type EmbeddedCredentialVerificationResult =
  | (EmbeddedCredentialVerificationFields & {
      readonly valid: true;
      /** 拒否には至らなかった注意事項。現時点では常に空配列。 */
      readonly warnings: readonly VerificationIssue[];
    })
  | (EmbeddedCredentialVerificationFields & {
      readonly valid: false;
      /** 失敗理由（最低 1 件）。 */
      readonly errors: readonly VerificationIssue[];
    });

/** 有効だった内包 VC の結果だけを指す型（`valid: true` の枝）。 */
export type ValidEmbeddedCredentialVerificationResult = Extract<
  EmbeddedCredentialVerificationResult,
  { valid: true }
>;

/**
 * `verifyPresentation`（高レベル）の結果。`valid` で判別する判別共用体。
 *
 * `valid: true` は「VP envelope が正当」**かつ**「内包 VC が 1 件以上あり全件が有効」を意味する。
 * envelope だけが正当で内包 VC に不正があるケース、および**内包 VC を 1 件も含まないケース**
 *は `valid: false` / `presentationValid: true` として返り、診断は
 * `credentialResults` / `errors` を読む。
 */
export type PresentationVerificationResult =
  | {
      /** envelope が正当で、内包 VC が 1 件以上あり全件有効。認可してよい唯一の状態。 */
      readonly valid: true;
      /** envelope の検証結果（`presentation` は構造検証済みの VP）。 */
      readonly data: VerifiedPresentationEnvelope;
      /** 提示者 DID（`vp.holder` = JWT の `iss`）。 */
      readonly holderDID: string;
      /** 各内包 VC の検証結果（`vp.verifiableCredential` と同じ順序・同じ長さ。全件 `valid: true`）。 */
      readonly credentialResults: readonly ValidEmbeddedCredentialVerificationResult[];
      /** 拒否には至らなかった注意事項。現時点では常に空配列。 */
      readonly warnings: readonly VerificationIssue[];
    }
  | {
      /** envelope か内包 VC のいずれかが不成立。認可は deny に倒すこと。 */
      readonly valid: false;
      /** 提示者 DID。envelope の検証自体に失敗した場合は持たない。 */
      readonly holderDID?: string;
      /** VP envelope（署名・時刻・aud/nonce バインド）だけの成否。 */
      readonly presentationValid: boolean;
      /** 各内包 VC の検証結果。envelope が不成立なら空配列（内包 VC は評価していない）。 */
      readonly credentialResults: readonly EmbeddedCredentialVerificationResult[];
      /** 失敗理由（最低 1 件）。 */
      readonly errors: readonly VerificationIssue[];
    };
